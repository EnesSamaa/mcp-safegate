//! JSON-RPC 2.0 and MCP payload models.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Returns the JSON-RPC protocol version used by SafeGate messages.
fn jsonrpc_version() -> String {
    "2.0".to_owned()
}

/// A JSON-RPC 2.0 request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    /// JSON-RPC protocol version. Defaults to `"2.0"` when absent during deserialization.
    #[serde(default = "jsonrpc_version")]
    pub jsonrpc: String,
    /// Client-selected request identifier.
    pub id: Value,
    /// Method to invoke.
    pub method: String,
    /// Optional method arguments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

/// A JSON-RPC 2.0 response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    /// JSON-RPC protocol version. Defaults to `"2.0"` when absent during deserialization.
    #[serde(default = "jsonrpc_version")]
    pub jsonrpc: String,
    /// Identifier copied from the corresponding request.
    pub id: Value,
    /// Successful method result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Failure payload when the request could not be completed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcErrorPayload>,
}

/// A JSON-RPC 2.0 error object.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcErrorPayload {
    /// JSON-RPC error code.
    pub code: i32,
    /// Human-readable error description.
    pub message: String,
    /// Optional implementation-specific error data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// Parameters supplied when an MCP client invokes a tool.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpToolCallParams {
    /// Name of the tool to execute.
    pub name: String,
    /// Optional tool-specific input arguments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Value>,
}

/// Parameters supplied by an MCP client during initialization.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpInitializeParams {
    /// MCP protocol version requested by the client.
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
    /// Client capabilities advertised for the session.
    pub capabilities: Value,
    /// Metadata describing the client implementation.
    #[serde(rename = "clientInfo")]
    pub client_info: Value,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn request_round_trips_through_json() {
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_owned(),
            id: json!("request-42"),
            method: "tools/call".to_owned(),
            params: Some(json!({"name": "lookup", "arguments": {"query": "SafeGate"}})),
        };

        let encoded = serde_json::to_string(&request).expect("request should serialize");
        let decoded: JsonRpcRequest =
            serde_json::from_str(&encoded).expect("request should deserialize");

        assert_eq!(decoded, request);
    }

    #[test]
    fn response_round_trips_through_json() {
        let response = JsonRpcResponse {
            jsonrpc: "2.0".to_owned(),
            id: json!(42),
            result: None,
            error: Some(JsonRpcErrorPayload {
                code: -32600,
                message: "Invalid Request".to_owned(),
                data: Some(json!({"reason": "missing method"})),
            }),
        };

        let encoded = serde_json::to_string(&response).expect("response should serialize");
        let decoded: JsonRpcResponse =
            serde_json::from_str(&encoded).expect("response should deserialize");

        assert_eq!(decoded, response);
    }
}
