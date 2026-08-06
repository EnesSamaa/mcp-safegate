//! HTTP request validation and upstream forwarding.

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
use safegate_core::{JsonRpcErrorPayload, JsonRpcRequest, JsonRpcResponse, SafeGateError};
use serde_json::{Value, json};
use tracing::{info, warn};

use crate::config::ProxyConfig;

type ProxyBody = Full<Bytes>;
type HttpClient = Client<HttpConnector, ProxyBody>;

/// Reverse proxy that validates JSON-RPC requests and forwards them to MCP.
pub struct Proxy {
    target_base: Uri,
    client: HttpClient,
}

impl Proxy {
    /// Creates a proxy using the supplied configuration.
    pub fn new(config: ProxyConfig) -> Result<Self, SafeGateError> {
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
        })
    }

    /// Validates an inbound request and relays it to the configured upstream MCP server.
    pub async fn handle_request(&self, request: Request<Incoming>) -> Response<ProxyBody> {
        let (parts, body) = request.into_parts();
        let body = match body.collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(error) => {
                return json_rpc_error_response(
                    StatusCode::BAD_REQUEST,
                    Value::Null,
                    SafeGateError::JsonRpcError(format!("failed to read request body: {error}")),
                );
            }
        };

        let request_id = if parts.method == hyper::Method::POST {
            match serde_json::from_slice::<JsonRpcRequest>(&body) {
                Ok(json_rpc) => {
                    info!(method = %json_rpc.method, "validated JSON-RPC request");
                    json_rpc.id
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
            Value::Null
        };

        let uri = match upstream_uri(&self.target_base, &parts.uri) {
            Ok(uri) => uri,
            Err(error) => {
                return json_rpc_error_response(StatusCode::BAD_GATEWAY, request_id, error);
            }
        };

        let mut upstream_request = Request::new(Full::new(body));
        *upstream_request.method_mut() = parts.method;
        *upstream_request.uri_mut() = uri;
        *upstream_request.version_mut() = parts.version;
        *upstream_request.headers_mut() = parts.headers;
        upstream_request.headers_mut().remove(HOST);

        match self.client.request(upstream_request).await {
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
}

/// Builds an upstream URI by preserving the inbound path and query string.
fn upstream_uri(target_base: &Uri, incoming: &Uri) -> Result<Uri, SafeGateError> {
    let mut parts = target_base.clone().into_parts();
    parts.path_and_query = incoming.path_and_query().cloned();
    Uri::from_parts(parts).map_err(|error| {
        SafeGateError::InternalError(format!("failed to construct upstream URI: {error}"))
    })
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
