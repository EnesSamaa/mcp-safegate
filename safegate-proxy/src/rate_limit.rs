//! Concurrent per-agent sliding-window request limiting.

use dashmap::DashMap;
use safegate_core::SafeGateError;
use tokio::time::{Duration, Instant};

/// In-memory, per-key sliding-window rate limiter.
///
/// Each key is independently locked by [`DashMap`], making a check and timestamp
/// insertion atomic for that key while allowing unrelated agents to proceed concurrently.
#[derive(Debug, Default)]
pub struct RateLimiter {
    requests: DashMap<String, Vec<Instant>>,
}

impl RateLimiter {
    /// Creates an empty rate limiter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records an allowed request for `key`, or returns an error when its quota is exhausted.
    ///
    /// Expired timestamps are removed before evaluating the quota. A request at the
    /// `max_requests` boundary is rejected, so at most `max_requests` requests may
    /// exist in any one `window_duration` interval.
    pub fn check_rate_limit(
        &self,
        key: &str,
        max_requests: usize,
        window_duration: Duration,
    ) -> Result<(), SafeGateError> {
        let now = Instant::now();
        let mut timestamps = self.requests.entry(key.to_owned()).or_default();

        timestamps.retain(|timestamp| now.duration_since(*timestamp) < window_duration);
        if timestamps.len() >= max_requests {
            return Err(SafeGateError::RateLimitExceeded);
        }

        timestamps.push(now);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use safegate_core::SafeGateError;
    use tokio::time::Duration;

    use super::RateLimiter;

    #[tokio::test]
    async fn rejects_requests_after_the_limit_is_reached() {
        let limiter = RateLimiter::new();
        let window = Duration::from_secs(60);

        assert!(limiter.check_rate_limit("agent-a", 2, window).is_ok());
        assert!(limiter.check_rate_limit("agent-a", 2, window).is_ok());
        assert!(matches!(
            limiter.check_rate_limit("agent-a", 2, window),
            Err(SafeGateError::RateLimitExceeded)
        ));
    }

    #[tokio::test]
    async fn permits_requests_after_the_window_expires() {
        let limiter = RateLimiter::new();
        let window = Duration::ZERO;

        assert!(limiter.check_rate_limit("agent-a", 1, window).is_ok());
        assert!(limiter.check_rate_limit("agent-a", 1, window).is_ok());
    }
}
