//! PII & Secret redaction engine for SafeGate.
//!
//! [`PiiRedactor`] scans free-text strings and recursive JSON values for
//! personally-identifiable information (PII) and secret tokens, replacing
//! them with safe placeholder strings before they leave the trust boundary.
//!
//! # Detectors
//!
//! | Category | Method | Replacement |
//! |----------|--------|-------------|
//! | API keys / secrets | Prefix regex `sk-…` | `[REDACTED_SECRET]` |
//! | Bearer tokens | Header-value regex | `[REDACTED_SECRET]` |
//! | E-mail addresses | RFC-5321 simplified regex | `[REDACTED_EMAIL]` |
//! | Credit cards | 13–19 digit pattern + **Luhn check** | `[REDACTED_CARD]` |
//! | High-entropy strings | Shannon entropy ≥ 4.5 bit/char, len ≥ 20 | `[REDACTED_SECRET]` |
//!
//! # Usage
//!
//! ```
//! use safegate_core::PiiRedactor;
//!
//! let redactor = PiiRedactor::new();
//! let (cleaned, changed) = redactor.sanitize_str("Contact user@example.com");
//! assert!(changed);
//! assert_eq!(cleaned, "Contact [REDACTED_EMAIL]");
//! ```

use regex::{Regex, RegexSet};
use serde_json::Value;

// ── Replacement tokens ────────────────────────────────────────────────────────

const REDACTED_SECRET: &str = "[REDACTED_SECRET]";
const REDACTED_EMAIL: &str = "[REDACTED_EMAIL]";
const REDACTED_CARD: &str = "[REDACTED_CARD]";

// ── Entropy configuration ─────────────────────────────────────────────────────

/// Minimum Shannon entropy (bits per character) to flag a string as a secret.
const ENTROPY_THRESHOLD: f64 = 4.5;

/// Minimum length of a token for entropy analysis to kick in.
/// Shorter strings produce unreliable entropy readings.
const ENTROPY_MIN_LEN: usize = 20;

// ── PiiRedactor ───────────────────────────────────────────────────────────────

/// Stateless PII / secret redaction engine.
///
/// All compiled regexes are built once at construction time and reused across
/// every call, making `PiiRedactor` cheap to clone and share via [`Arc`].
///
/// [`Arc`]: std::sync::Arc
pub struct PiiRedactor {
    /// Matches `sk-` prefixed API keys (OpenAI-style and similar).
    api_key_re: Regex,
    /// Matches `Bearer <token>` strings in HTTP-header style.
    bearer_re: Regex,
    /// Matches common e-mail address formats.
    email_re: Regex,
    /// Matches raw digit sequences that look like payment-card numbers (13–19 digits).
    /// Candidates are verified with the Luhn algorithm before redaction.
    card_candidate_re: Regex,
    /// Fast multi-pattern set used to quickly decide whether any regex *might*
    /// match before running the individual replace passes.
    quick_set: RegexSet,
}

impl PiiRedactor {
    /// Creates a new `PiiRedactor` with all patterns compiled.
    ///
    /// # Panics
    ///
    /// Panics if any of the hard-coded regex patterns fail to compile (which
    /// would be a programming error caught at startup / in tests).
    pub fn new() -> Self {
        let api_key_pattern = r"sk-[A-Za-z0-9]{20,}";
        let bearer_pattern = r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*";
        let email_pattern = r"(?i)[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}";
        // Accepts 13–19 consecutive digits, optionally separated by single
        // spaces or hyphens (e.g. "4111-1111-1111-1111").
        let card_pattern = r"\b(?:\d[ \-]?){12,18}\d\b";

        let quick_set =
            RegexSet::new([api_key_pattern, bearer_pattern, email_pattern, card_pattern])
                .expect("PiiRedactor quick-set should compile");

        Self {
            api_key_re: Regex::new(api_key_pattern).expect("api_key regex should compile"),
            bearer_re: Regex::new(bearer_pattern).expect("bearer regex should compile"),
            email_re: Regex::new(email_pattern).expect("email regex should compile"),
            card_candidate_re: Regex::new(card_pattern)
                .expect("card_candidate regex should compile"),
            quick_set,
        }
    }

    /// Sanitises a plain-text string in-place.
    ///
    /// Returns `(sanitised_string, was_changed)`. If no PII was detected the
    /// original string is returned unchanged and `was_changed` is `false`.
    pub fn sanitize_str(&self, text: &str) -> (String, bool) {
        // Fast path: if no pattern matches at all, skip all replacements.
        let quick_matches = self.quick_set.matches(text);
        let entropy_hit = contains_high_entropy_token(text);

        if !quick_matches.matched_any() && !entropy_hit {
            return (text.to_owned(), false);
        }

        let mut out = text.to_owned();
        let original = text.to_owned();

        // Order matters: run bearer before email to avoid mangling the header.
        if quick_matches.matched(1) {
            out = self
                .bearer_re
                .replace_all(&out, REDACTED_SECRET)
                .into_owned();
        }
        if quick_matches.matched(0) {
            out = self
                .api_key_re
                .replace_all(&out, REDACTED_SECRET)
                .into_owned();
        }
        if quick_matches.matched(2) {
            out = self.email_re.replace_all(&out, REDACTED_EMAIL).into_owned();
        }
        if quick_matches.matched(3) {
            out = redact_cards(&self.card_candidate_re, &out);
        }
        if entropy_hit {
            out = redact_high_entropy_tokens(&out);
        }

        let changed = out != original;
        (out, changed)
    }

    /// Recursively sanitises all string leaves inside a [`serde_json::Value`].
    ///
    /// Returns `true` if at least one value was modified.
    pub fn sanitize_json(&self, value: &mut Value) -> bool {
        match value {
            Value::String(s) => {
                let (cleaned, changed) = self.sanitize_str(s);
                if changed {
                    *s = cleaned;
                }
                changed
            }
            Value::Object(map) => {
                let mut any = false;
                for v in map.values_mut() {
                    any |= self.sanitize_json(v);
                }
                any
            }
            Value::Array(arr) => {
                let mut any = false;
                for v in arr.iter_mut() {
                    any |= self.sanitize_json(v);
                }
                any
            }
            // Numbers, booleans, null — nothing to redact.
            _ => false,
        }
    }
}

impl Default for PiiRedactor {
    fn default() -> Self {
        Self::new()
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Validates a digit sequence (may contain separating spaces/hyphens) using
/// the Luhn algorithm. Returns `true` if the number is a valid card number.
pub(crate) fn luhn_check(digits: &str) -> bool {
    let digits: Vec<u8> = digits
        .chars()
        .filter(|c| c.is_ascii_digit())
        .map(|c| c as u8 - b'0')
        .collect();

    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }

    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                let doubled = d as u32 * 2;
                if doubled > 9 { doubled - 9 } else { doubled }
            } else {
                d as u32
            }
        })
        .sum();

    sum.is_multiple_of(10)
}

/// Replaces card-number-shaped digit sequences that also pass Luhn validation.
fn redact_cards(card_re: &Regex, text: &str) -> String {
    card_re
        .replace_all(text, |caps: &regex::Captures<'_>| {
            let matched = &caps[0];
            if luhn_check(matched) {
                REDACTED_CARD.to_owned()
            } else {
                matched.to_owned()
            }
        })
        .into_owned()
}

/// Computes the Shannon entropy of `s` in bits per character.
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let len = s.len() as f64;
    let mut freq = [0u32; 256];
    for b in s.bytes() {
        freq[b as usize] += 1;
    }
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Returns `true` when `text` contains at least one whitespace-delimited token
/// whose length and Shannon entropy exceed the configured thresholds.
fn contains_high_entropy_token(text: &str) -> bool {
    text.split_whitespace()
        .any(|tok| tok.len() >= ENTROPY_MIN_LEN && shannon_entropy(tok) >= ENTROPY_THRESHOLD)
}

/// Replaces high-entropy whitespace-delimited tokens with `[REDACTED_SECRET]`.
///
/// Tokens that were already replaced by a prior pass (and now equal one of the
/// `[REDACTED_*]` literals) are skipped to avoid double-replacement.
fn redact_high_entropy_tokens(text: &str) -> String {
    text.split(' ')
        .map(|tok| {
            if tok.starts_with('[') && tok.ends_with(']') {
                // Already a replacement placeholder — leave it alone.
                tok.to_owned()
            } else if tok.len() >= ENTROPY_MIN_LEN && shannon_entropy(tok) >= ENTROPY_THRESHOLD {
                REDACTED_SECRET.to_owned()
            } else {
                tok.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn redactor() -> PiiRedactor {
        PiiRedactor::new()
    }

    // ── E-mail ────────────────────────────────────────────────────────────────

    #[test]
    fn redacts_email_address_in_plain_text() {
        let (out, changed) = redactor().sanitize_str("Contact user@example.com for details");
        assert!(changed);
        assert_eq!(out, "Contact [REDACTED_EMAIL] for details");
    }

    #[test]
    fn redacts_email_in_subdomain() {
        let (out, changed) = redactor().sanitize_str("admin@mail.corp.internal");
        assert!(changed);
        assert!(out.contains(REDACTED_EMAIL));
    }

    #[test]
    fn does_not_redact_plain_text_without_pii() {
        let text = "Hello, world! This is a safe message.";
        let (out, changed) = redactor().sanitize_str(text);
        assert!(!changed);
        assert_eq!(out, text);
    }

    // ── API key ───────────────────────────────────────────────────────────────

    #[test]
    fn redacts_sk_prefixed_api_key() {
        let (out, changed) = redactor().sanitize_str("key=sk-abcdefghij1234567890XYZ api_call");
        assert!(changed);
        assert!(out.contains(REDACTED_SECRET));
        assert!(!out.contains("sk-"));
    }

    #[test]
    fn does_not_redact_short_sk_string() {
        // Must be at least 20 chars after "sk-"
        let (out, changed) = redactor().sanitize_str("sk-short");
        assert!(!changed);
        assert_eq!(out, "sk-short");
    }

    // ── Bearer token ──────────────────────────────────────────────────────────

    #[test]
    fn redacts_bearer_token_in_header_value() {
        let (out, changed) =
            redactor().sanitize_str("Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9");
        assert!(changed);
        assert!(out.contains(REDACTED_SECRET));
        assert!(!out.contains("eyJ"));
    }

    #[test]
    fn redacts_bearer_token_case_insensitive() {
        let (out, changed) = redactor().sanitize_str("BEARER MySecretToken12345678");
        assert!(changed);
        assert!(out.contains(REDACTED_SECRET));
    }

    // ── Credit card ───────────────────────────────────────────────────────────

    #[test]
    fn luhn_accepts_valid_test_card_number() {
        // Visa test number
        assert!(luhn_check("4111111111111111"));
        // Mastercard test number
        assert!(luhn_check("5500005555555559"));
        // American Express test number
        assert!(luhn_check("378282246310005"));
    }

    #[test]
    fn luhn_rejects_invalid_card_number() {
        // 1234567890123456 → digit sum 64, not a multiple of 10 → fails Luhn.
        assert!(!luhn_check("1234567890123456"));
        // 9999999999999999 → digit sum mod 10 ≠ 0 → fails Luhn.
        assert!(!luhn_check("9999999999999999"));
    }

    #[test]
    fn redacts_valid_visa_card_in_text() {
        let (out, changed) = redactor().sanitize_str("My card is 4111111111111111 thanks");
        assert!(changed);
        assert!(out.contains(REDACTED_CARD));
        assert!(!out.contains("4111"));
    }

    #[test]
    fn does_not_redact_invalid_card_number() {
        // Same length but fails Luhn — must NOT be redacted.
        let text = "number 1234567890123456 here";
        let (out, changed) = redactor().sanitize_str(text);
        // The card regex matches, but Luhn rejects it, so no redaction of card.
        // (email/key/entropy checks might still not trigger)
        assert!(!out.contains(REDACTED_CARD));
        let _ = changed; // changed may be false or true depending on other detectors
    }

    #[test]
    fn redacts_hyphen_separated_card_number() {
        let (out, changed) = redactor().sanitize_str("Card: 4111-1111-1111-1111 expiry 12/25");
        assert!(changed);
        assert!(out.contains(REDACTED_CARD));
    }

    // ── Shannon entropy ───────────────────────────────────────────────────────

    #[test]
    fn shannon_entropy_of_repeated_char_is_zero() {
        let e = shannon_entropy("aaaaaaaaaa");
        assert!(e < 0.01, "uniform string should have near-zero entropy");
    }

    #[test]
    fn shannon_entropy_of_random_string_is_high() {
        // A base64-encoded random key typically has entropy ~5.5–6.0
        let s = "xK9mP2qL8nRt4vYw3sJh6cBf1oGe7iAu";
        assert!(
            shannon_entropy(s) >= 4.0,
            "random string should have high entropy"
        );
    }

    #[test]
    fn redacts_high_entropy_token_in_text() {
        // 32-char high-entropy random string (typical secret)
        let secret = "aB3kP9mXqL2rTvWn7cYh4oJg8sZu1fEd";
        let text = format!("token={secret} env=production");
        let (out, changed) = redactor().sanitize_str(&text);
        assert!(
            changed,
            "high-entropy token should be detected and redacted"
        );
        assert!(!out.contains(secret), "secret should not appear in output");
    }

    // ── JSON sanitisation ─────────────────────────────────────────────────────

    #[test]
    fn sanitize_json_redacts_email_in_string_value() {
        let mut val = json!({ "contact": "hello@example.com", "count": 42 });
        let changed = redactor().sanitize_json(&mut val);
        assert!(changed);
        assert_eq!(val["contact"], REDACTED_EMAIL);
        // Non-string values must be untouched.
        assert_eq!(val["count"], 42);
    }

    #[test]
    fn sanitize_json_redacts_api_key_in_nested_object() {
        let mut val = json!({
            "config": {
                "api_key": "sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
                "model": "gpt-4"
            }
        });
        let changed = redactor().sanitize_json(&mut val);
        assert!(changed);
        assert_eq!(val["config"]["api_key"], REDACTED_SECRET);
        assert_eq!(val["config"]["model"], "gpt-4");
    }

    #[test]
    fn sanitize_json_redacts_items_in_array() {
        let mut val = json!(["safe text", "user@corp.com", 99]);
        let changed = redactor().sanitize_json(&mut val);
        assert!(changed);
        assert_eq!(val[0], "safe text");
        assert_eq!(val[1], REDACTED_EMAIL);
        assert_eq!(val[2], 99);
    }

    #[test]
    fn sanitize_json_preserves_valid_structure_after_redaction() {
        let mut val = json!({
            "user": "alice@example.com",
            "card": "4111111111111111",
            "note": "clean text",
            "nested": { "key": "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" }
        });
        let changed = redactor().sanitize_json(&mut val);
        assert!(changed);
        // Must still be a valid JSON object with all four keys intact.
        assert!(val.is_object());
        assert!(val.get("user").is_some());
        assert!(val.get("card").is_some());
        assert!(val.get("note").is_some());
        assert!(val.get("nested").is_some());
        // Structural integrity: re-serialize and re-parse must succeed.
        let serialized = serde_json::to_string(&val).expect("must serialize");
        let reparsed: Value = serde_json::from_str(&serialized).expect("must deserialize");
        assert_eq!(reparsed["note"], "clean text");
        assert_eq!(reparsed["user"], REDACTED_EMAIL);
        assert_eq!(reparsed["card"], REDACTED_CARD);
        assert_eq!(reparsed["nested"]["key"], REDACTED_SECRET);
    }

    #[test]
    fn sanitize_json_returns_false_when_no_pii_present() {
        let mut val = json!({ "action": "list_files", "path": "/home/user" });
        let changed = redactor().sanitize_json(&mut val);
        assert!(!changed);
        assert_eq!(val["action"], "list_files");
    }

    #[test]
    fn sanitize_json_handles_mixed_content_in_array() {
        let mut val = json!([
            { "token": "Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0" },
            { "safe": "nothing here" },
            "plain@email.test"
        ]);
        let changed = redactor().sanitize_json(&mut val);
        assert!(changed);
        // Bearer in nested object
        assert!(val[0]["token"].as_str().unwrap().contains(REDACTED_SECRET));
        // Safe object unchanged
        assert_eq!(val[1]["safe"], "nothing here");
        // Email in top-level array element
        assert_eq!(val[2], REDACTED_EMAIL);
    }
}
