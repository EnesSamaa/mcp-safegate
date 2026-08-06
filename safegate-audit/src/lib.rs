//! Immutable, structured audit-log records for SafeGate policy decisions.
//!
//! Each record carries an HMAC-SHA256 signature computed over the serialised
//! record body (excluding the signature field) so that tampered entries can be
//! detected by any reader that holds the shared secret.

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

pub mod writer;

pub use writer::AuditLogger;

// ─── Policy Decision ──────────────────────────────────────────────────────────

/// The outcome of a WASM policy evaluation for a single tool-call request.
///
/// Mirrors [`safegate_wasm::PolicyDecision`] but is defined locally so that
/// the audit crate has no dependency on the WASM runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "detail")]
pub enum AuditDecision {
    /// The request was forwarded to the upstream MCP server unchanged.
    Allow,
    /// The request was blocked with the supplied human-readable reason.
    Deny(String),
    /// The request arguments were rewritten before forwarding upstream.
    RedactArgs(String),
}

// ─── Audit Record ─────────────────────────────────────────────────────────────

/// A single, immutable audit-log entry produced for every proxied tool call.
///
/// The `signature` field contains a hex-encoded HMAC-SHA256 of the canonical
/// JSON serialisation of all other fields combined.  Use
/// [`AuditLogEntry::verify`] to check integrity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    /// Wall-clock time at which the proxy received the request (UTC).
    pub timestamp: DateTime<Utc>,
    /// Randomly generated UUID v4 that uniquely identifies this request.
    pub trace_id: String,
    /// Tenant context extracted from the inbound HTTP headers.
    pub tenant_id: Option<String>,
    /// Agent context extracted from the inbound HTTP headers.
    pub agent_id: String,
    /// MCP tool name from the `tools/call` params, or `"<non-tool>"` for other
    /// JSON-RPC methods.
    pub tool_name: String,
    /// Policy decision that was applied to this request.
    pub decision: AuditDecision,
    /// End-to-end proxy evaluation latency in **microseconds**.
    ///
    /// Measured from the moment the request is received until the policy
    /// decision is recorded (does not include upstream round-trip time).
    pub latency_us: u128,
    /// Hex-encoded HMAC-SHA256 of the canonical body (all fields except
    /// `signature` itself, serialised as compact JSON).
    pub signature: String,
}

impl AuditLogEntry {
    /// Constructs a new entry, computes its HMAC-SHA256 signature, and returns
    /// the fully populated record.
    ///
    /// `hmac_secret` is the raw key bytes shared between the logger and any
    /// downstream log-verification tooling.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        timestamp: DateTime<Utc>,
        trace_id: String,
        tenant_id: Option<String>,
        agent_id: String,
        tool_name: String,
        decision: AuditDecision,
        latency_us: u128,
        hmac_secret: &[u8],
    ) -> Self {
        // Build a stub with an empty signature so we can serialise the body.
        let mut entry = Self {
            timestamp,
            trace_id,
            tenant_id,
            agent_id,
            tool_name,
            decision,
            latency_us,
            signature: String::new(),
        };
        entry.signature = compute_signature(&entry, hmac_secret);
        entry
    }

    /// Returns `true` if the stored `signature` matches a freshly computed MAC
    /// over the entry's body fields.
    ///
    /// A `false` result means the record has been tampered with or was signed
    /// with a different key.
    pub fn verify(&self, hmac_secret: &[u8]) -> bool {
        let expected = compute_signature(self, hmac_secret);
        // Constant-time comparison via HMAC verify machinery.
        let mut mac =
            Hmac::<Sha256>::new_from_slice(hmac_secret).expect("HMAC accepts any key length");
        mac.update(expected.as_bytes());
        let mut mac2 =
            Hmac::<Sha256>::new_from_slice(hmac_secret).expect("HMAC accepts any key length");
        mac2.update(self.signature.as_bytes());
        // Constant-time equality: compare the MACs of both hex strings.
        mac.finalize().into_bytes() == mac2.finalize().into_bytes()
    }
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

/// Serialises `entry` without its `signature` field and computes HMAC-SHA256.
///
/// The canonical body is the compact JSON of a temporary struct that excludes
/// `signature`, ensuring the MAC covers every meaningful field.
fn compute_signature(entry: &AuditLogEntry, key: &[u8]) -> String {
    #[derive(Serialize)]
    struct Body<'a> {
        timestamp: &'a DateTime<Utc>,
        trace_id: &'a str,
        tenant_id: &'a Option<String>,
        agent_id: &'a str,
        tool_name: &'a str,
        decision: &'a AuditDecision,
        latency_us: u128,
    }
    let body = Body {
        timestamp: &entry.timestamp,
        trace_id: &entry.trace_id,
        tenant_id: &entry.tenant_id,
        agent_id: &entry.agent_id,
        tool_name: &entry.tool_name,
        decision: &entry.decision,
        latency_us: entry.latency_us,
    };
    let canonical = serde_json::to_string(&body).expect("audit body serialisation must not fail");

    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(canonical.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

// ─── Unit Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"test-hmac-secret-key";

    fn sample_entry(decision: AuditDecision) -> AuditLogEntry {
        AuditLogEntry::new(
            Utc::now(),
            "trace-abc-123".to_owned(),
            Some("tenant-1".to_owned()),
            "agent-x".to_owned(),
            "dangerous_delete".to_owned(),
            decision,
            42,
            SECRET,
        )
    }

    #[test]
    fn allow_entry_signature_verifies() {
        let entry = sample_entry(AuditDecision::Allow);
        assert!(entry.verify(SECRET), "Allow entry signature must verify");
    }

    #[test]
    fn deny_entry_signature_verifies_with_correct_key() {
        let entry = sample_entry(AuditDecision::Deny("blocked by policy".to_owned()));
        assert!(entry.verify(SECRET), "Deny entry signature must verify");
    }

    #[test]
    fn redact_entry_signature_verifies() {
        let entry = sample_entry(AuditDecision::RedactArgs(
            "{\"query\":\"[REDACTED]\"}".to_owned(),
        ));
        assert!(
            entry.verify(SECRET),
            "RedactArgs entry signature must verify"
        );
    }

    #[test]
    fn tampered_entry_fails_verification() {
        let mut entry = sample_entry(AuditDecision::Allow);
        // Tamper with a field after signing.
        entry.agent_id = "evil-agent".to_owned();
        assert!(
            !entry.verify(SECRET),
            "Tampered entry must NOT verify successfully"
        );
    }

    #[test]
    fn wrong_key_fails_verification() {
        let entry = sample_entry(AuditDecision::Allow);
        assert!(
            !entry.verify(b"wrong-key"),
            "Entry must NOT verify with a different HMAC key"
        );
    }

    #[test]
    fn deny_entry_records_latency() {
        let entry = sample_entry(AuditDecision::Deny("too dangerous".to_owned()));
        assert_eq!(entry.latency_us, 42);
        assert!(matches!(entry.decision, AuditDecision::Deny(_)));
    }

    #[test]
    fn entry_round_trips_through_json() {
        let entry = sample_entry(AuditDecision::Allow);
        let json = serde_json::to_string(&entry).expect("entry must serialise");
        let decoded: AuditLogEntry = serde_json::from_str(&json).expect("entry must deserialise");
        assert_eq!(entry.trace_id, decoded.trace_id);
        assert_eq!(entry.signature, decoded.signature);
        assert!(decoded.verify(SECRET));
    }
}
