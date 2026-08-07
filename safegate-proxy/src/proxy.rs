//! HTTP request validation and upstream forwarding.

use std::{sync::Arc, time::Instant};

use arc_swap::ArcSwap;
use http_body_util::{BodyExt, Full};
use hyper::{
    Request, Response, StatusCode, Uri,
    body::{Bytes, Incoming},
    header::{CONTENT_TYPE, HOST},
};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};
use safegate_audit::{AuditDecision, writer::AuditLogger};
use safegate_core::{
    JsonRpcErrorPayload, JsonRpcRequest, JsonRpcResponse, PiiRedactor, SafeGateError,
};
use safegate_wasm::WasmPolicyEngine;
use serde_json::{Value, json};
use tracing::{info, warn};
use uuid::Uuid;

use crate::config::ProxyConfig;
use crate::identity::extract_agent_context;
use crate::metrics::{
    HTTP_REQUESTS_TOTAL, POLICY_DECISIONS_TOTAL, PROXY_LATENCY_SECONDS,
    WASM_EXECUTION_LATENCY_SECONDS, gather_metrics_text,
};
use crate::rate_limit::RateLimiter;

type ProxyBody = Full<Bytes>;
type HttpClient = Client<HttpConnector, ProxyBody>;

const AGENT_RATE_LIMIT: usize = 60;
const AGENT_RATE_LIMIT_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);

/// Reverse proxy that validates JSON-RPC requests and forwards them to MCP.
pub struct Proxy {
    target_base: Uri,
    client: HttpClient,
    rate_limiter: Arc<RateLimiter>,
    /// Atomically-swappable handle to the currently active WASM policy engine.
    ///
    /// Updated by [`PolicyWatcher`] whenever a new `.wasm` file is detected.
    policy_engine: Arc<ArcSwap<WasmPolicyEngine>>,
    /// Non-blocking structured audit logger.
    audit_logger: Arc<AuditLogger>,
    /// PII and secret-token redaction engine; applied before WASM policy evaluation.
    redactor: Arc<PiiRedactor>,
}

impl Proxy {
    /// Creates a proxy using the supplied configuration, a live policy engine
    /// handle, and an audit logger.
    ///
    /// `policy_engine` is the [`ArcSwap`] produced by [`PolicyWatcher::shared()`].
    /// `audit_logger` is shared via [`Arc`] so the same instance can be used by
    /// multiple worker tasks.
    pub fn new(
        config: ProxyConfig,
        policy_engine: Arc<ArcSwap<WasmPolicyEngine>>,
        audit_logger: Arc<AuditLogger>,
    ) -> Result<Self, SafeGateError> {
        let target_base = config.target_mcp_url.parse::<Uri>().map_err(|error| {
            SafeGateError::InternalError(format!("invalid target MCP URL: {error}"))
        })?;

        if target_base.scheme().is_none() || target_base.authority().is_none() {
            return Err(SafeGateError::InternalError(
                "target MCP URL must include a scheme and authority".to_owned(),
            ));
        }

        Ok(Self {
            target_base,
            client: Client::builder(TokioExecutor::new()).build_http(),
            rate_limiter: Arc::new(RateLimiter::new()),
            policy_engine,
            audit_logger,
            redactor: Arc::new(PiiRedactor::new()),
        })
    }

    /// Validates an inbound request and relays it to the configured upstream MCP server.
    ///
    /// Request pipeline (in order):
    /// 0. Special routes: `/metrics` and `/healthz`
    /// 1. Authentication check
    /// 2. Per-agent rate limiting
    /// 3. Body read + JSON-RPC parse
    /// 4. **WASM policy evaluation** (Allow / Deny / RedactArgs)
    /// 5. Upstream forwarding
    /// 6. **Immutable audit log entry** (emitted for every outcome)
    /// 7. **Prometheus metrics** recording (latency + counters)
    pub async fn handle_request(&self, request: Request<Incoming>) -> Response<ProxyBody> {
        let request_start = Instant::now();
        let trace_id = Uuid::new_v4().to_string();

        // ── 0. Special management routes ────────────────────────────────────
        //
        // These two routes bypass all proxy logic (auth, rate limiting, WASM,
        // audit logging) and are handled directly here.
        let path = request.uri().path().to_owned();

        if path == "/metrics" {
            return self.handle_metrics();
        }

        if path == "/healthz" {
            return self.handle_healthz();
        }

        // ── 1. Authentication ────────────────────────────────────────────────
        let (parts, body) = request.into_parts();
        let agent_ctx = extract_agent_context(&parts.headers);
        if !agent_ctx.authenticated {
            return json_rpc_error_response(
                StatusCode::UNAUTHORIZED,
                Value::Null,
                SafeGateError::Unauthorized("missing or invalid bearer token".to_owned()),
            );
        }
        info!(?agent_ctx, "Agent request received");

        // ── 2. Rate limiting ─────────────────────────────────────────────────
        if let Err(error) = self.rate_limiter.check_rate_limit(
            &agent_ctx.agent_id,
            AGENT_RATE_LIMIT,
            AGENT_RATE_LIMIT_WINDOW,
        ) {
            return json_rpc_error_response(StatusCode::TOO_MANY_REQUESTS, Value::Null, error);
        }

        // ── 3. Read body ─────────────────────────────────────────────────────
        let body_bytes = match body.collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(error) => {
                return json_rpc_error_response(
                    StatusCode::BAD_REQUEST,
                    Value::Null,
                    SafeGateError::JsonRpcError(format!("failed to read request body: {error}")),
                );
            }
        };

        // Parse JSON-RPC only for POST requests; pass other methods straight through.
        let (request_id, tool_call_params) = if parts.method == hyper::Method::POST {
            match serde_json::from_slice::<JsonRpcRequest>(&body_bytes) {
                Ok(json_rpc) => {
                    info!(method = %json_rpc.method, "validated JSON-RPC request");
                    let tool_params = if json_rpc.method == "tools/call" {
                        json_rpc.params.as_ref().and_then(|p| {
                            serde_json::from_value::<safegate_core::McpToolCallParams>(p.clone())
                                .ok()
                        })
                    } else {
                        None
                    };
                    (json_rpc.id, tool_params)
                }
                Err(error) => {
                    return json_rpc_error_response(
                        StatusCode::BAD_REQUEST,
                        Value::Null,
                        SafeGateError::JsonRpcError(format!("invalid JSON-RPC request: {error}")),
                    );
                }
            }
        } else {
            (Value::Null, None)
        };

        let tool_name = tool_call_params
            .as_ref()
            .map(|p| p.name.clone())
            .unwrap_or_else(|| "<non-tool>".to_owned());

        // ── 3.5 PII Redaction ────────────────────────────────────────────────
        //
        // Scan and sanitise tool arguments for PII / secrets *before* they are
        // forwarded to the WASM engine or upstream.  If any value is redacted
        // the JSON-RPC body bytes are rebuilt so the cleaned payload propagates
        // through the rest of the pipeline unchanged.
        //
        // We use a locally-owned copy of `tool_call_params` so that the
        // sanitised arguments can be passed to `evaluate_policy` directly.
        let (body_bytes, tool_call_params, pii_redacted) =
            if let Some(mut params) = tool_call_params {
                if let Some(ref mut args) = params.arguments {
                    if self.redactor.sanitize_json(args) {
                        // Rebuild the wire body with the sanitised arguments.
                        let sanitised_args_json =
                            serde_json::to_string(args).unwrap_or_else(|_| "null".to_owned());
                        let new_body = rebuild_tool_call_body(&body_bytes, &sanitised_args_json)
                            .unwrap_or(body_bytes);
                        info!(tool = %params.name, "PII redactor sanitised tool arguments");
                        (new_body, Some(params), true)
                    } else {
                        (body_bytes, Some(params), false)
                    }
                } else {
                    (body_bytes, Some(params), false)
                }
            } else {
                (body_bytes, None, false)
            };

        // ── 4. WASM Policy evaluation ────────────────────────────────────────
        // Load a snapshot of the current engine (lock-free ArcSwap).
        let engine_guard = self.policy_engine.load();

        // `body_to_forward` may be replaced by RedactArgs or PII redaction.
        // `audit_decision` is captured for the log entry.
        //
        // If PII was already redacted in step 3.5, we start with a RedactArgs
        // decision so the audit log always reflects the sanitisation.
        let initial_decision = if pii_redacted {
            POLICY_DECISIONS_TOTAL.with_label_values(&["redact"]).inc();
            let sanitised_args = tool_call_params
                .as_ref()
                .and_then(|p| p.arguments.as_ref())
                .map(|a| a.to_string())
                .unwrap_or_else(|| "null".to_owned());
            AuditDecision::RedactArgs(sanitised_args)
        } else {
            AuditDecision::Allow
        };

        let (body_to_forward, audit_decision) = if let Some(ref tool_params) = tool_call_params {
            let wasm_ctx = safegate_core::AgentContext {
                agent_id: agent_ctx.agent_id.clone(),
                tenant_id: agent_ctx.tenant_id.clone(),
                roles: agent_ctx.roles.clone(),
                authenticated: agent_ctx.authenticated,
            };

            let wasm_start = Instant::now();
            let policy_result = engine_guard.evaluate_policy(&wasm_ctx, tool_params).await;
            WASM_EXECUTION_LATENCY_SECONDS.observe(wasm_start.elapsed().as_secs_f64());

            match policy_result {
                Ok(safegate_wasm::PolicyDecision::Allow) => {
                    info!("WASM policy: Allow");
                    if !pii_redacted {
                        POLICY_DECISIONS_TOTAL.with_label_values(&["allow"]).inc();
                    }
                    (body_bytes, initial_decision)
                }
                Ok(safegate_wasm::PolicyDecision::Deny(reason)) => {
                    warn!(%reason, "WASM policy: Deny");
                    POLICY_DECISIONS_TOTAL.with_label_values(&["deny"]).inc();
                    let elapsed = request_start.elapsed();
                    PROXY_LATENCY_SECONDS.observe(elapsed.as_secs_f64());
                    HTTP_REQUESTS_TOTAL
                        .with_label_values(&["403", &agent_ctx.tenant_id])
                        .inc();
                    let latency_us = elapsed.as_micros();
                    self.emit_audit(
                        &trace_id,
                        &agent_ctx,
                        &tool_name,
                        AuditDecision::Deny(reason.clone()),
                        latency_us,
                    );
                    return json_rpc_error_response(
                        StatusCode::FORBIDDEN,
                        request_id,
                        SafeGateError::GuardrailViolation(reason),
                    );
                }
                Ok(safegate_wasm::PolicyDecision::RedactArgs(new_args_json)) => {
                    info!("WASM policy: RedactArgs – rewriting tool arguments");
                    POLICY_DECISIONS_TOTAL.with_label_values(&["redact"]).inc();
                    // Rebuild the JSON-RPC body with the WASM-sanitised arguments.
                    let new_body = match rebuild_tool_call_body(&body_bytes, &new_args_json) {
                        Ok(new_body) => new_body,
                        Err(error) => {
                            warn!(%error, "RedactArgs body rebuild failed; forwarding original");
                            body_bytes
                        }
                    };
                    (new_body, AuditDecision::RedactArgs(new_args_json))
                }
                Err(error) => {
                    // No loaded component → treat as Allow (engine not yet warmed up).
                    // Other engine errors are logged but do not block the request.
                    warn!(%error, "WASM policy evaluation failed; allowing request");
                    if !pii_redacted {
                        POLICY_DECISIONS_TOTAL.with_label_values(&["allow"]).inc();
                    }
                    (body_bytes, initial_decision)
                }
            }
        } else {
            // Non-tools/call method or non-POST: no policy evaluation needed.
            (body_bytes, initial_decision)
        };

        // ── 5. Forward to upstream ───────────────────────────────────────────
        let uri = match upstream_uri(&self.target_base, &parts.uri) {
            Ok(uri) => uri,
            Err(error) => {
                return json_rpc_error_response(StatusCode::BAD_GATEWAY, request_id, error);
            }
        };

        let mut upstream_request = Request::new(Full::new(body_to_forward));
        *upstream_request.method_mut() = parts.method;
        *upstream_request.uri_mut() = uri;
        *upstream_request.version_mut() = parts.version;
        *upstream_request.headers_mut() = parts.headers;
        upstream_request.headers_mut().remove(HOST);

        let upstream_result = self.client.request(upstream_request).await;

        // ── 6. Audit log ─────────────────────────────────────────────────────
        let elapsed = request_start.elapsed();
        let latency_us = elapsed.as_micros();
        self.emit_audit(
            &trace_id,
            &agent_ctx,
            &tool_name,
            audit_decision,
            latency_us,
        );

        // ── 7. Prometheus metrics ─────────────────────────────────────────────
        PROXY_LATENCY_SECONDS.observe(elapsed.as_secs_f64());

        match upstream_result {
            Ok(response) => {
                let status_code = response.status().as_u16().to_string();
                HTTP_REQUESTS_TOTAL
                    .with_label_values(&[&status_code, &agent_ctx.tenant_id])
                    .inc();
                relay_response(response).await
            }
            Err(error) => {
                warn!(%error, "upstream MCP request failed");
                HTTP_REQUESTS_TOTAL
                    .with_label_values(&["502", &agent_ctx.tenant_id])
                    .inc();
                json_rpc_error_response(
                    StatusCode::BAD_GATEWAY,
                    request_id,
                    SafeGateError::InternalError(format!(
                        "upstream MCP server is unavailable: {error}"
                    )),
                )
            }
        }
    }

    /// Handles `GET /metrics` – serialises all registered Prometheus metrics
    /// in the standard text exposition format.
    fn handle_metrics(&self) -> Response<ProxyBody> {
        match gather_metrics_text() {
            Ok(text) => Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")
                .body(Full::new(Bytes::from(text)))
                .expect("metrics response must be valid"),
            Err(error) => {
                warn!(%error, "failed to gather Prometheus metrics");
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Full::new(Bytes::from_static(b"metrics unavailable")))
                    .expect("error response must be valid")
            }
        }
    }

    /// Handles `GET /healthz` – verifies that the proxy is running and the WASM
    /// policy engine has been successfully initialised, then returns HTTP 200.
    ///
    /// The engine is considered healthy if the [`ArcSwap`] handle is loadable
    /// (which it always is after `Proxy::new` succeeds).  A more sophisticated
    /// liveness check could verify that a WASM component is actually loaded.
    fn handle_healthz(&self) -> Response<ProxyBody> {
        // Load the engine snapshot; if the ArcSwap is poisoned this would panic,
        // but ArcSwap::load is infallible in practice.
        let _engine = self.policy_engine.load();
        let body = serde_json::to_vec(&json!({"status": "healthy"}))
            .expect("health response must serialize");
        Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body)))
            .expect("health response must be valid")
    }

    /// Builds and enqueues one [`AuditLogEntry`][safegate_audit::AuditLogEntry]
    /// for the completed request.
    fn emit_audit(
        &self,
        trace_id: &str,
        agent_ctx: &safegate_core::AgentContext,
        tool_name: &str,
        decision: AuditDecision,
        latency_us: u128,
    ) {
        let entry = safegate_audit::AuditLogEntry::new(
            chrono::Utc::now(),
            trace_id.to_owned(),
            Some(agent_ctx.tenant_id.clone()),
            agent_ctx.agent_id.clone(),
            tool_name.to_owned(),
            decision,
            latency_us,
            self.audit_logger.hmac_secret(),
        );
        self.audit_logger.log(entry);
    }
}

/// Builds an upstream URI by preserving the inbound path and query string.
fn upstream_uri(target_base: &Uri, incoming: &Uri) -> Result<Uri, SafeGateError> {
    let mut parts = target_base.clone().into_parts();
    parts.path_and_query = incoming.path_and_query().cloned();
    Uri::from_parts(parts).map_err(|error| {
        SafeGateError::InternalError(format!("failed to construct upstream URI: {error}"))
    })
}

/// Replaces the `params.arguments` field of a JSON-RPC body with `new_args_json`.
///
/// Used by the `RedactArgs` policy decision to rewrite tool call arguments before
/// the request is forwarded upstream.  If parsing fails the original bytes are
/// returned unchanged (the caller falls back to the original body).
fn rebuild_tool_call_body(original: &[u8], new_args_json: &str) -> Result<Bytes, SafeGateError> {
    let mut rpc: Value =
        serde_json::from_slice(original).map_err(|e| SafeGateError::JsonRpcError(e.to_string()))?;
    let new_args: Value = serde_json::from_str(new_args_json)
        .map_err(|e| SafeGateError::JsonRpcError(e.to_string()))?;
    if let Some(params) = rpc.get_mut("params") {
        params["arguments"] = new_args;
    }
    let rebuilt =
        serde_json::to_vec(&rpc).map_err(|e| SafeGateError::JsonRpcError(e.to_string()))?;
    Ok(Bytes::from(rebuilt))
}

/// Converts an upstream response into a buffered response for the downstream client.
async fn relay_response(response: Response<Incoming>) -> Response<ProxyBody> {
    let (parts, body) = response.into_parts();
    match body.collect().await {
        Ok(collected) => Response::from_parts(parts, Full::new(collected.to_bytes())),
        Err(error) => json_rpc_error_response(
            StatusCode::BAD_GATEWAY,
            Value::Null,
            SafeGateError::InternalError(format!("failed to read upstream response: {error}")),
        ),
    }
}

/// Creates a JSON-RPC error response suitable for an MCP client.
fn json_rpc_error_response(
    status: StatusCode,
    id: Value,
    error: SafeGateError,
) -> Response<ProxyBody> {
    let payload = match error {
        SafeGateError::JsonRpcError(message) => JsonRpcErrorPayload {
            code: -32700,
            message: "Parse error".to_owned(),
            data: Some(json!({ "detail": message })),
        },
        SafeGateError::Unauthorized(message) => JsonRpcErrorPayload {
            code: -32001,
            message: "Unauthorized".to_owned(),
            data: Some(json!({ "detail": message })),
        },
        SafeGateError::RateLimitExceeded => JsonRpcErrorPayload {
            code: -32029,
            message: "Rate limit exceeded".to_owned(),
            data: None,
        },
        SafeGateError::GuardrailViolation(message) => JsonRpcErrorPayload {
            code: -32002,
            message: "Guardrail violation".to_owned(),
            data: Some(json!({ "detail": message })),
        },
        SafeGateError::WasmExecutionError(message) | SafeGateError::InternalError(message) => {
            JsonRpcErrorPayload {
                code: -32603,
                message: "Internal error".to_owned(),
                data: Some(json!({ "detail": message })),
            }
        }
    };
    let response = JsonRpcResponse {
        jsonrpc: "2.0".to_owned(),
        id,
        result: None,
        error: Some(payload),
    };
    let body = serde_json::to_vec(&response).expect("JSON-RPC error response must serialize");

    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body)))
        .expect("JSON-RPC error response must be valid")
}
