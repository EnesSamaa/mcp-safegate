//! Error definitions shared by SafeGate components.

use thiserror::Error;

/// Errors that can occur while processing traffic through SafeGate.
#[derive(Debug, Error)]
pub enum SafeGateError {
    /// The JSON-RPC message was invalid or could not be processed.
    #[error("JSON-RPC error: {0}")]
    JsonRpcError(String),
    /// The caller is not authorized to perform the requested operation.
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    /// The caller exceeded its permitted request rate.
    #[error("rate limit exceeded")]
    RateLimitExceeded,
    /// The circuit breaker is open due to repeated policy violations.
    #[error("circuit breaker open: {0}")]
    CircuitOpen(String),
    /// A configured security guardrail rejected the operation.
    #[error("guardrail violation: {0}")]
    GuardrailViolation(String),
    /// WebAssembly policy execution failed.
    #[error("WASM execution error: {0}")]
    WasmExecutionError(String),
    /// An unexpected internal error occurred.
    #[error("internal error: {0}")]
    InternalError(String),
}
