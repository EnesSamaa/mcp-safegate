//! Prometheus-compatible metrics for the SafeGate reverse proxy.
//!
//! # Metrics exposed
//!
//! | Name | Type | Labels | Description |
//! |------|------|--------|-------------|
//! | `safegate_http_requests_total` | Counter | `status`, `tenant_id` | Total HTTP requests processed |
//! | `safegate_policy_decisions_total` | Counter | `decision` (`allow`/`deny`/`redact`) | WASM policy decisions |
//! | `safegate_proxy_latency_seconds` | Histogram | – | Full request round-trip latency |
//! | `safegate_wasm_execution_latency_seconds` | Histogram | – | Only the WASM engine evaluation time |

use once_cell::sync::Lazy;
use prometheus::{
    Encoder, HistogramOpts, IntCounterVec, Opts, Registry, TextEncoder,
};

/// The shared Prometheus registry for all SafeGate metrics.
///
/// Using a custom registry (instead of `prometheus::default_registry()`) keeps
/// SafeGate metrics isolated from any other Prometheus instrumentation that may
/// run in the same process.
pub static REGISTRY: Lazy<Registry> = Lazy::new(|| {
    Registry::new_custom(Some("safegate".to_owned()), None)
        .expect("custom Prometheus registry should be created")
});

// ── Counters ──────────────────────────────────────────────────────────────────

/// `safegate_http_requests_total` – total requests received by the proxy,
/// partitioned by HTTP status code string and originating tenant.
pub static HTTP_REQUESTS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let opts = Opts::new(
        "http_requests_total",
        "Total HTTP requests processed by the proxy",
    );
    let counter = IntCounterVec::new(opts, &["status", "tenant_id"])
        .expect("HTTP_REQUESTS_TOTAL metric should be created");
    REGISTRY
        .register(Box::new(counter.clone()))
        .expect("HTTP_REQUESTS_TOTAL should register");
    counter
});

/// `safegate_policy_decisions_total` – WASM policy outcomes, labelled by the
/// `decision` variant: `allow`, `deny`, or `redact`.
pub static POLICY_DECISIONS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let opts = Opts::new(
        "policy_decisions_total",
        "Total WASM policy decisions (allow / deny / redact)",
    );
    let counter = IntCounterVec::new(opts, &["decision"])
        .expect("POLICY_DECISIONS_TOTAL metric should be created");
    REGISTRY
        .register(Box::new(counter.clone()))
        .expect("POLICY_DECISIONS_TOTAL should register");
    counter
});

// ── Histograms ────────────────────────────────────────────────────────────────

/// Default latency buckets in seconds (1 ms → 10 s) suitable for an HTTP proxy.
const LATENCY_BUCKETS: &[f64] = &[
    0.001, 0.005, 0.010, 0.025, 0.050, 0.100, 0.250, 0.500, 1.0, 2.5, 5.0, 10.0,
];

/// `safegate_proxy_latency_seconds` – full request processing time (auth,
/// rate-limiting, body read, WASM evaluation, upstream forwarding).
pub static PROXY_LATENCY_SECONDS: Lazy<prometheus::Histogram> = Lazy::new(|| {
    let opts = HistogramOpts::new(
        "proxy_latency_seconds",
        "Full request round-trip latency in seconds",
    )
    .buckets(LATENCY_BUCKETS.to_vec());
    let histogram =
        prometheus::Histogram::with_opts(opts).expect("PROXY_LATENCY_SECONDS should be created");
    REGISTRY
        .register(Box::new(histogram.clone()))
        .expect("PROXY_LATENCY_SECONDS should register");
    histogram
});

/// `safegate_wasm_execution_latency_seconds` – time spent inside the WASM
/// policy engine only (component instantiation + `call_evaluate`).
pub static WASM_EXECUTION_LATENCY_SECONDS: Lazy<prometheus::Histogram> = Lazy::new(|| {
    let opts = HistogramOpts::new(
        "wasm_execution_latency_seconds",
        "WASM policy engine execution latency in seconds",
    )
    .buckets(LATENCY_BUCKETS.to_vec());
    let histogram = prometheus::Histogram::with_opts(opts)
        .expect("WASM_EXECUTION_LATENCY_SECONDS should be created");
    REGISTRY
        .register(Box::new(histogram.clone()))
        .expect("WASM_EXECUTION_LATENCY_SECONDS should register");
    histogram
});

// ── Serialisation helpers ─────────────────────────────────────────────────────

/// Collects all metrics from [`REGISTRY`] and serialises them as a UTF-8
/// Prometheus text exposition string.
///
/// Returns an error string if the encoder fails (which is unlikely in practice).
pub fn gather_metrics_text() -> Result<String, String> {
    // Force initialisation of every metric so they appear in the output even
    // when no requests have been recorded yet.
    let _ = &*HTTP_REQUESTS_TOTAL;
    let _ = &*POLICY_DECISIONS_TOTAL;
    let _ = &*PROXY_LATENCY_SECONDS;
    let _ = &*WASM_EXECUTION_LATENCY_SECONDS;

    let encoder = TextEncoder::new();
    let metric_families = REGISTRY.gather();
    let mut buffer = Vec::new();
    encoder
        .encode(&metric_families, &mut buffer)
        .map_err(|e| format!("prometheus encode error: {e}"))?;
    String::from_utf8(buffer).map_err(|e| format!("prometheus utf8 error: {e}"))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gather_metrics_text_returns_valid_prometheus_output() {
        let text = gather_metrics_text().expect("metrics should serialise");
        // The text exposition format always uses `# HELP` and `# TYPE` headers.
        assert!(
            text.contains("# HELP") || text.is_empty(),
            "metrics output should contain HELP or be empty on first call"
        );
    }

    #[test]
    fn policy_decisions_counter_increments_correctly() {
        // Capture the value before incrementing.
        let before = POLICY_DECISIONS_TOTAL.with_label_values(&["deny"]).get();

        POLICY_DECISIONS_TOTAL.with_label_values(&["deny"]).inc();
        POLICY_DECISIONS_TOTAL.with_label_values(&["deny"]).inc();

        let after = POLICY_DECISIONS_TOTAL.with_label_values(&["deny"]).get();

        assert_eq!(
            after - before,
            2,
            "deny counter should have incremented by 2"
        );
    }

    #[test]
    fn http_requests_total_counter_increments_correctly() {
        let before = HTTP_REQUESTS_TOTAL
            .with_label_values(&["200", "test-tenant"])
            .get();

        HTTP_REQUESTS_TOTAL
            .with_label_values(&["200", "test-tenant"])
            .inc();

        let after = HTTP_REQUESTS_TOTAL
            .with_label_values(&["200", "test-tenant"])
            .get();

        assert_eq!(
            after - before,
            1,
            "HTTP requests counter should have incremented by 1"
        );
    }

    #[test]
    fn gather_metrics_text_contains_all_metric_families() {
        // Touch all counters and histograms so they appear in the output.
        HTTP_REQUESTS_TOTAL
            .with_label_values(&["200", "init-tenant"])
            .inc();
        POLICY_DECISIONS_TOTAL.with_label_values(&["allow"]).inc();
        PROXY_LATENCY_SECONDS.observe(0.001);
        WASM_EXECUTION_LATENCY_SECONDS.observe(0.001);

        let text = gather_metrics_text().expect("metrics should serialise");

        assert!(
            text.contains("http_requests_total"),
            "should contain http_requests_total"
        );
        assert!(
            text.contains("policy_decisions_total"),
            "should contain policy_decisions_total"
        );
        assert!(
            text.contains("proxy_latency_seconds"),
            "should contain proxy_latency_seconds"
        );
        assert!(
            text.contains("wasm_execution_latency_seconds"),
            "should contain wasm_execution_latency_seconds"
        );
    }
}
