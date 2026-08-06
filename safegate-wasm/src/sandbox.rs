//! Resource limits and execution deadlines for policy components.

use tokio::time::Duration;

/// Resource limits applied to each isolated policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmSandboxConfig {
    /// Maximum size of each policy linear memory in bytes.
    pub max_memory_bytes: usize,
    /// Number of engine epoch ticks allowed before the store traps execution.
    pub epoch_deadlines: u64,
}

impl WasmSandboxConfig {
    /// Maximum wall-clock duration allowed for one policy evaluation.
    pub const EXECUTION_TIMEOUT: Duration = Duration::from_millis(5);
}

impl Default for WasmSandboxConfig {
    fn default() -> Self {
        Self {
            max_memory_bytes: 16 * 1024 * 1024,
            epoch_deadlines: 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::time::Duration;

    use super::WasmSandboxConfig;

    #[test]
    fn defaults_enforce_the_expected_memory_boundary() {
        assert_eq!(
            WasmSandboxConfig::default().max_memory_bytes,
            16 * 1024 * 1024
        );
    }

    #[test]
    fn defaults_configure_a_short_epoch_based_timeout() {
        let config = WasmSandboxConfig::default();

        assert_eq!(config.epoch_deadlines, 1);
        assert_eq!(
            WasmSandboxConfig::EXECUTION_TIMEOUT,
            Duration::from_millis(5)
        );
    }
}
