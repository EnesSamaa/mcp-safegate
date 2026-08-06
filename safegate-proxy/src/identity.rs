//! Extraction of agent identity from inbound HTTP headers.

use hyper::{HeaderMap, header::AUTHORIZATION};
use safegate_core::AgentContext;
use tracing::warn;

/// Mock bearer token accepted by the development identity interceptor.
pub const DEVELOPMENT_BEARER_TOKEN: &str = "safegate-dev-token";

const ANONYMOUS_AGENT_ID: &str = "anonymous_agent";
const DEFAULT_TENANT_ID: &str = "default_tenant";

/// Extracts the caller's agent context from HTTP request headers.
///
/// Authentication is intentionally a deterministic development-only mock: the
/// bearer token must exactly match [`DEVELOPMENT_BEARER_TOKEN`]. Production
/// deployments should replace this check with the configured identity provider.
pub fn extract_agent_context(headers: &HeaderMap) -> AgentContext {
    let agent_id = header_value(headers, "x-agent-id").unwrap_or_else(|| {
        warn!("request did not include x-agent-id; using anonymous agent context");
        ANONYMOUS_AGENT_ID.to_owned()
    });
    let tenant_id =
        header_value(headers, "x-tenant-id").unwrap_or_else(|| DEFAULT_TENANT_ID.to_owned());

    let authenticated = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .is_some_and(|token| token == DEVELOPMENT_BEARER_TOKEN);

    AgentContext {
        agent_id,
        tenant_id,
        roles: Vec::new(),
        authenticated,
    }
}

/// Reads a UTF-8 header value, ignoring empty values.
fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
    use hyper::{
        HeaderMap,
        header::{AUTHORIZATION, HeaderValue},
    };

    use super::{DEVELOPMENT_BEARER_TOKEN, extract_agent_context};

    #[test]
    fn extracts_supplied_agent_and_tenant_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("x-agent-id", HeaderValue::from_static("research-agent"));
        headers.insert("x-tenant-id", HeaderValue::from_static("tenant-acme"));
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer safegate-dev-token"),
        );

        let context = extract_agent_context(&headers);

        assert_eq!(context.agent_id, "research-agent");
        assert_eq!(context.tenant_id, "tenant-acme");
        assert!(context.authenticated);
        assert!(context.roles.is_empty());
    }

    #[test]
    fn uses_anonymous_agent_when_agent_header_is_missing() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {DEVELOPMENT_BEARER_TOKEN}"))
                .expect("test bearer token is a valid header"),
        );

        let context = extract_agent_context(&headers);

        assert_eq!(context.agent_id, "anonymous_agent");
        assert_eq!(context.tenant_id, "default_tenant");
        assert!(context.authenticated);
    }

    #[test]
    fn rejects_missing_or_invalid_bearer_tokens() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer invalid-token"),
        );

        assert!(!extract_agent_context(&headers).authenticated);
        assert!(!extract_agent_context(&HeaderMap::new()).authenticated);
    }
}
