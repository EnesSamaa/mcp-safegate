//! Reusable SafeGate reverse proxy components.

/// Reverse proxy configuration.
pub mod config;
/// Agent identity extraction from HTTP headers.
pub mod identity;
/// HTTP request validation and upstream forwarding.
pub mod proxy;
/// Concurrent per-agent request limiting.
pub mod rate_limit;

pub use config::ProxyConfig;
pub use proxy::Proxy;
