//! Core protocol models, errors, and shared abstractions for MCP-WASM SafeGate.

/// Error types emitted by SafeGate components.
pub mod error;
/// MCP and JSON-RPC 2.0 wire protocol types.
pub mod protocol;

pub use error::SafeGateError;
pub use protocol::{
    JsonRpcErrorPayload, JsonRpcRequest, JsonRpcResponse, McpInitializeParams, McpToolCallParams,
};
