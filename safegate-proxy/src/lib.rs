//! Reusable SafeGate reverse proxy components.

/// Circuit breaker and outlier interceptor per agent.
pub mod circuit_breaker;
/// Reverse proxy configuration.
pub mod config;
/// Agent identity extraction from HTTP headers.
pub mod identity;
/// Prometheus metrics: counters, histograms, and text serialisation.
pub mod metrics;
/// HTTP request validation and upstream forwarding.
pub mod proxy;
/// Concurrent per-agent request limiting.
pub mod rate_limit;

pub use config::ProxyConfig;
pub use proxy::Proxy;
