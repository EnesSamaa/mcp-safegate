//! End-to-end verification for the separately compiled sample policy component.

use std::path::PathBuf;

use safegate_core::{AgentContext, McpToolCallParams};
use safegate_wasm::{PolicyDecision, WasmPolicyEngine};

fn sample_component_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("examples/sample-policy/target/wasm32-wasip2/debug/sample_policy.wasm")
}

/// Requires the component artifact built by the documented command below.
///
/// ```text
/// cargo build --manifest-path safegate-wasm/examples/sample-policy/Cargo.toml --target wasm32-wasip2
/// ```
#[tokio::test]
#[ignore = "requires a separately built wasm32-wasip2 sample policy component"]
async fn sample_policy_component_enforces_tool_safety() {
    let mut engine = WasmPolicyEngine::new().expect("engine should initialize");
    engine
        .load_component_from_file(&sample_component_path())
        .expect("sample component should load");
    let context = AgentContext {
        agent_id: "test-agent".to_owned(),
        tenant_id: "test-tenant".to_owned(),
        roles: vec!["operator".to_owned()],
        authenticated: true,
    };
    let request = McpToolCallParams {
        name: "dangerous_delete".to_owned(),
        arguments: None,
    };

    let decision = engine
        .evaluate_policy(&context, &request)
        .await
        .expect("policy evaluation should succeed");

    assert_eq!(
        decision,
        PolicyDecision::Deny("Unsafe action blocked by WASM policy".to_owned())
    );
}
