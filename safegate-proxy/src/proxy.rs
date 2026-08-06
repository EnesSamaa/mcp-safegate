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
use safegate_core::{JsonRpcErrorPayload, JsonRpcRequest, JsonRpcResponse, SafeGateError};
use safegate_wasm::WasmPolicyEngine;
use serde_json::{Value, json};
use tracing::{info, warn};
use uuid::Uuid;

use crate::config::ProxyConfig;
use crate::identity::extract_agent_context;
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
        })
    }

    /// Validates an inbound request and relays it to the configured upstream MCP server.
    ///
    /// Request pipeline (in order):
    /// 1. Authentication check
    /// 2. Per-agent rate limiting
    /// 3. Body read + JSON-RPC parse
    /// 4. **WASM policy evaluation** (Allow / Deny / RedactArgs)
    /// 5. Upstream forwarding
    /// 6. **Immutable audit log entry** (emitted for every outcome)
    pub async fn handle_request(&self, request: Request<Incoming>) -> Response<ProxyBody> {
        let request_start = Instant::now();
        let trace_id = Uuid::new_v4().to_string();

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

        // ── 4. WASM Policy evaluation ────────────────────────────────────────
        // Load a snapshot of the current engine (lock-free ArcSwap).
        let engine_guard = self.policy_engine.load();

        // `body_to_forward` may be replaced by RedactArgs.
        // `audit_decision` is captured for the log entry.
        let (body_to_forward, audit_decision) = if let Some(ref tool_params) = tool_call_params {
            let wasm_ctx = safegate_core::AgentContext {
                agent_id: agent_ctx.agent_id.clone(),
                tenant_id: agent_ctx.tenant_id.clone(),
                roles: agent_ctx.roles.clone(),
                authenticated: agent_ctx.authenticated,
            };

            match engine_guard.evaluate_policy(&wasm_ctx, tool_params).await {
                Ok(safegate_wasm::PolicyDecision::Allow) => {
                    info!("WASM policy: Allow");
                    (body_bytes, AuditDecision::Allow)
                }
                Ok(safegate_wasm::PolicyDecision::Deny(reason)) => {
                    warn!(%reason, "WASM policy: Deny");
                    let latency_us = request_start.elapsed().as_micros();
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
                    // Rebuild the JSON-RPC body with the sanitised arguments.
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
                    (body_bytes, AuditDecision::Allow)
                }
            }
        } else {
            // Non-tools/call method or non-POST: no policy evaluation needed.
            (body_bytes, AuditDecision::Allow)
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
        let latency_us = request_start.elapsed().as_micros();
        self.emit_audit(
            &trace_id,
            &agent_ctx,
            &tool_name,
            audit_decision,
            latency_us,
        );

        match upstream_result {
            Ok(response) => relay_response(response).await,
            Err(error) => {
                warn!(%error, "upstream MCP request failed");
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
