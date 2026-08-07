//! Circuit breaker and outlier interceptor for isolating offending agents.
//!
//! [`CircuitBreaker`] tracks policy violations (Deny decisions) per `agent_id`.
//! If an agent triggers 5 or more violations within a rolling 10-second window,
//! the breaker trips to **Open** state for that agent. While Open, all requests
//! from that agent are immediately rejected at the proxy layer with an HTTP 429
//! response for a 30-second cooldown period, bypassing WASM policy evaluation.

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use safegate_core::SafeGateError;

/// Number of violations in `FAILURE_WINDOW` that trips the breaker.
const FAILURE_THRESHOLD: usize = 5;

/// Rolling window during which violations are counted (10 seconds).
const FAILURE_WINDOW: Duration = Duration::from_secs(10);

/// Cooldown duration during which an agent is blocked when circuit is Open (30 seconds).
const COOLDOWN_PERIOD: Duration = Duration::from_secs(30);

#[derive(Debug)]
struct AgentCircuitState {
    /// Timestamps of recent policy violations (Denies).
    failures: Vec<Instant>,
    /// Instant when the circuit was opened (if currently open).
    opened_at: Option<Instant>,
}

impl AgentCircuitState {
    fn new() -> Self {
        Self {
            failures: Vec::new(),
            opened_at: None,
        }
    }
}

/// Thread-safe circuit breaker tracking policy violations per agent.
pub struct CircuitBreaker {
    states: Mutex<HashMap<String, AgentCircuitState>>,
    threshold: usize,
    window: Duration,
    cooldown: Duration,
}

impl CircuitBreaker {
    /// Creates a new `CircuitBreaker` with standard production parameters:
    /// 5 failures in 10 seconds → 30 seconds cooldown.
    pub fn new() -> Self {
        Self::with_params(FAILURE_THRESHOLD, FAILURE_WINDOW, COOLDOWN_PERIOD)
    }

    /// Creates a `CircuitBreaker` with custom parameters (useful for testing).
    pub fn with_params(threshold: usize, window: Duration, cooldown: Duration) -> Self {
        Self {
            states: Mutex::new(HashMap::new()),
            threshold,
            window,
            cooldown,
        }
    }

    /// Checks if requests from `agent_id` are permitted.
    ///
    /// Returns `Ok(())` if the circuit is Closed.
    /// Returns `Err(SafeGateError::CircuitOpen)` if the circuit is currently Open.
    pub fn check(&self, agent_id: &str) -> Result<(), SafeGateError> {
        let mut states = self.states.lock().unwrap();
        let now = Instant::now();

        if let Some(state) = states.get_mut(agent_id)
            && let Some(opened_at) = state.opened_at
        {
            if now.duration_since(opened_at) < self.cooldown {
                let remaining = self.cooldown.saturating_sub(now.duration_since(opened_at));
                return Err(SafeGateError::CircuitOpen(format!(
                    "agent '{}' is quarantined for policy violations (cooldown remaining: {}s)",
                    agent_id,
                    remaining.as_secs()
                )));
            } else {
                // Cooldown expired → reset state to Closed
                state.opened_at = None;
                state.failures.clear();
            }
        }

        Ok(())
    }

    /// Records a policy violation (Deny) for `agent_id`.
    ///
    /// If the total failures within `FAILURE_WINDOW` reach `FAILURE_THRESHOLD`,
    /// the circuit transitions to Open.
    pub fn record_failure(&self, agent_id: &str) {
        let mut states = self.states.lock().unwrap();
        let now = Instant::now();

        let state = states
            .entry(agent_id.to_owned())
            .or_insert_with(AgentCircuitState::new);

        // If circuit is already open, do nothing
        if let Some(opened_at) = state.opened_at {
            if now.duration_since(opened_at) < self.cooldown {
                return;
            } else {
                state.opened_at = None;
                state.failures.clear();
            }
        }

        state
            .failures
            .retain(|&t| now.duration_since(t) <= self.window);
        state.failures.push(now);

        if state.failures.len() >= self.threshold {
            state.opened_at = Some(now);
            tracing::warn!(
                agent_id = %agent_id,
                failures = state.failures.len(),
                cooldown_secs = self.cooldown.as_secs(),
                "Circuit breaker TRIPPED to Open state; agent quarantined"
            );
        }
    }
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn permits_requests_when_below_threshold() {
        let cb = CircuitBreaker::with_params(3, Duration::from_secs(10), Duration::from_secs(1));

        cb.record_failure("agent-1");
        cb.record_failure("agent-1");

        assert!(cb.check("agent-1").is_ok());
    }

    #[test]
    fn trips_circuit_when_threshold_reached() {
        let cb = CircuitBreaker::with_params(3, Duration::from_secs(10), Duration::from_secs(5));

        cb.record_failure("agent-1");
        cb.record_failure("agent-1");
        cb.record_failure("agent-1");

        let res = cb.check("agent-1");
        assert!(res.is_err());
        if let Err(SafeGateError::CircuitOpen(msg)) = res {
            assert!(msg.contains("agent-1"));
        } else {
            panic!("expected CircuitOpen error");
        }
    }

    #[test]
    fn resets_after_cooldown_expires() {
        let cb = CircuitBreaker::with_params(2, Duration::from_secs(10), Duration::from_millis(50));

        cb.record_failure("agent-2");
        cb.record_failure("agent-2");

        assert!(cb.check("agent-2").is_err());

        sleep(Duration::from_millis(60));

        assert!(cb.check("agent-2").is_ok());
    }

    #[test]
    fn isolates_failures_per_agent() {
        let cb = CircuitBreaker::with_params(2, Duration::from_secs(10), Duration::from_secs(5));

        cb.record_failure("agent-bad");
        cb.record_failure("agent-bad");

        assert!(cb.check("agent-bad").is_err());
        assert!(cb.check("agent-good").is_ok());
    }
}
