//! Example SafeGate policy component compiled for `wasm32-wasip2`.

wit_bindgen::generate!({
    world: "safegate-policy",
    path: "../../wit",
});

struct SamplePolicy;

impl Guest for SamplePolicy {
    fn evaluate(_ctx: AgentContext, req: ToolRequest) -> PolicyDecision {
        evaluate_request(&req)
    }
}

/// Applies the example tool-safety policy.
fn evaluate_request(req: &ToolRequest) -> PolicyDecision {
    if matches!(req.tool_name.as_str(), "dangerous_delete" | "drop_table") {
        return PolicyDecision::Deny("Unsafe action blocked by WASM policy".to_owned());
    }

    if req.arguments_json.contains("secret_key") {
        return PolicyDecision::RedactArgs("Sensitive arguments were redacted".to_owned());
    }

    PolicyDecision::Allow
}

export!(SamplePolicy);

#[cfg(test)]
mod tests {
    use super::{PolicyDecision, ToolRequest, evaluate_request};

    fn request(tool_name: &str, arguments_json: &str) -> ToolRequest {
        ToolRequest {
            tool_name: tool_name.to_owned(),
            arguments_json: arguments_json.to_owned(),
        }
    }

    #[test]
    fn dangerous_tools_are_denied() {
        assert!(matches!(
            evaluate_request(&request("drop_table", "{}")),
            PolicyDecision::Deny(_)
        ));
    }

    #[test]
    fn secret_arguments_are_redacted() {
        assert!(matches!(
            evaluate_request(&request("lookup", r#"{"secret_key":"value"}"#)),
            PolicyDecision::RedactArgs(_)
        ));
    }
}
