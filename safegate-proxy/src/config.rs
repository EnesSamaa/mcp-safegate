//! Reverse proxy configuration.

use std::{net::SocketAddr, path::PathBuf};

/// Runtime configuration for the SafeGate reverse proxy.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Address on which the proxy accepts HTTP connections.
    pub listen_addr: SocketAddr,
    /// Base URL of the upstream MCP server.
    pub target_mcp_url: String,
    /// Directory that is watched for `.wasm` policy file changes.
    ///
    /// Defaults to `./policies` relative to the working directory.
    pub policy_dir: PathBuf,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 8080)),
            target_mcp_url: "http://127.0.0.1:3000".to_owned(),
            policy_dir: PathBuf::from("./policies"),
        }
    }
}
