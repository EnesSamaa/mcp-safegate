//! Core protocol models, errors, and shared abstractions for MCP-WASM SafeGate.

/// Error types emitted by SafeGate components.
pub mod error;
/// Agent identity and authorization context types.
pub mod identity;
/// MCP and JSON-RPC 2.0 wire protocol types.
pub mod protocol;
/// PII and secret-token redaction engine.
pub mod redactor;

pub use error::SafeGateError;
pub use identity::AgentContext;
pub use protocol::{
    JsonRpcErrorPayload, JsonRpcRequest, JsonRpcResponse, McpInitializeParams, McpToolCallParams,
};
pub use redactor::PiiRedactor;
