//! Reverse proxy configuration.

use std::{net::SocketAddr, path::PathBuf};

/// Runtime configuration for the SafeGate reverse proxy.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Address on which the proxy accepts HTTP connections.
    pub listen_addr: SocketAddr,
    /// Base URL of the upstream MCP server.
    pub target_mcp_url: String,
    /// Directory that is watched for the **default** `.wasm` policy file.
    ///
    /// Defaults to `./policies` relative to the working directory.
    pub policy_dir: PathBuf,
    /// Directory that is watched for **per-tenant** `.wasm` policy files.
    ///
    /// Each file must be named `<tenant_id>.wasm`.
    /// Defaults to `./policies/tenants` relative to the working directory.
    pub tenant_policy_dir: PathBuf,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from(([0, 0, 0, 0], 8080)),
            target_mcp_url: "http://127.0.0.1:3000".to_owned(),
            policy_dir: PathBuf::from("./policies"),
            tenant_policy_dir: PathBuf::from("./policies/tenants"),
        }
    }
}

impl ProxyConfig {
    /// Loads configuration from environment variables, falling back to defaults
    /// for any variable that is unset or unparseable.
    ///
    /// Supported environment variables:
    /// - `SAFEGATE_LISTEN_ADDR` (e.g. `0.0.0.0:8080`)
    /// - `SAFEGATE_TARGET_MCP_URL` or `SAFEGATE_UPSTREAM_URI` (e.g. `http://mcp-upstream:3000`)
    /// - `SAFEGATE_POLICY_DIR` (e.g. `/app/policies`)
    /// - `SAFEGATE_TENANT_POLICY_DIR` (e.g. `/app/policies/tenants`)
    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Ok(val) = std::env::var("SAFEGATE_LISTEN_ADDR")
            && let Ok(addr) = val.parse::<SocketAddr>()
        {
            config.listen_addr = addr;
        }

        if let Ok(val) = std::env::var("SAFEGATE_TARGET_MCP_URL")
            .or_else(|_| std::env::var("SAFEGATE_UPSTREAM_URI"))
            && !val.trim().is_empty()
        {
            config.target_mcp_url = val;
        }

        if let Ok(val) = std::env::var("SAFEGATE_POLICY_DIR")
            && !val.trim().is_empty()
        {
            config.policy_dir = PathBuf::from(val);
        }

        if let Ok(val) = std::env::var("SAFEGATE_TENANT_POLICY_DIR")
            && !val.trim().is_empty()
        {
            config.tenant_policy_dir = PathBuf::from(val);
        }

        config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_expected_values() {
        let config = ProxyConfig::default();
        assert_eq!(config.listen_addr, SocketAddr::from(([0, 0, 0, 0], 8080)));
        assert_eq!(config.target_mcp_url, "http://127.0.0.1:3000");
    }

    #[test]
    fn loads_override_values_from_env() {
        unsafe {
            std::env::set_var("SAFEGATE_LISTEN_ADDR", "127.0.0.1:9090");
            std::env::set_var("SAFEGATE_TARGET_MCP_URL", "http://mcp-server:5000");
            std::env::set_var("SAFEGATE_POLICY_DIR", "/custom/policies");
        }

        let config = ProxyConfig::from_env();
        assert_eq!(config.listen_addr, SocketAddr::from(([127, 0, 0, 1], 9090)));
        assert_eq!(config.target_mcp_url, "http://mcp-server:5000");
        assert_eq!(config.policy_dir, PathBuf::from("/custom/policies"));

        unsafe {
            std::env::remove_var("SAFEGATE_LISTEN_ADDR");
            std::env::remove_var("SAFEGATE_TARGET_MCP_URL");
            std::env::remove_var("SAFEGATE_POLICY_DIR");
        }
    }
}
