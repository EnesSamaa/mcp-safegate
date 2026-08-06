//! Reverse proxy configuration.

use std::net::SocketAddr;

/// Runtime configuration for the SafeGate reverse proxy.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Address on which the proxy accepts HTTP connections.
    pub listen_addr: SocketAddr,
    /// Base URL of the upstream MCP server.
    pub target_mcp_url: String,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 8080)),
            target_mcp_url: "http://127.0.0.1:3000".to_owned(),
        }
    }
}
