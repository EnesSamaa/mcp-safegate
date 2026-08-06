//! Micro-benchmarks for SafeGate's request pre-processing path.

use criterion::{Criterion, criterion_group, criterion_main};
use hyper::{
    HeaderMap,
    header::{AUTHORIZATION, HeaderValue},
};
use safegate_core::JsonRpcRequest;
use safegate_proxy::{identity::extract_agent_context, rate_limit::RateLimiter};
use serde_json::json;
use tokio::runtime::Runtime;
use tokio::time::Duration;

fn benchmark_proxy_preprocessing(c: &mut Criterion) {
    let runtime = Runtime::new().expect("benchmark runtime should start");
    let request_body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"lookup","arguments":{"query":"SafeGate"}}}"#;
    let mut headers = HeaderMap::new();
    headers.insert("x-agent-id", HeaderValue::from_static("benchmark-agent"));
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_static("Bearer safegate-dev-token"),
    );

    c.bench_function("proxy_request_preprocessing", |bench| {
        bench.to_async(&runtime).iter(|| async {
            let agent = extract_agent_context(&headers);
            let limiter = RateLimiter::new();
            limiter
                .check_rate_limit(&agent.agent_id, 1, Duration::from_secs(1))
                .expect("first benchmark request should pass");
            let request: JsonRpcRequest =
                serde_json::from_slice(request_body).expect("fixture should be valid JSON-RPC");
            criterion::black_box(request);
        });
    });
}

fn benchmark_json_rpc_serialization(c: &mut Criterion) {
    let runtime = Runtime::new().expect("benchmark runtime should start");
    let request = JsonRpcRequest {
        jsonrpc: "2.0".to_owned(),
        id: json!(1),
        method: "tools/call".to_owned(),
        params: Some(json!({
            "name": "lookup",
            "arguments": { "query": "SafeGate" }
        })),
    };

    c.bench_function("json_rpc_serialize_deserialize", |bench| {
        bench.to_async(&runtime).iter(|| {
            let request = request.clone();
            async move {
                let encoded = serde_json::to_vec(&request).expect("request should serialize");
                let decoded: JsonRpcRequest =
                    serde_json::from_slice(&encoded).expect("request should deserialize");
                criterion::black_box(decoded);
            }
        });
    });
}

criterion_group!(
    proxy_benches,
    benchmark_proxy_preprocessing,
    benchmark_json_rpc_serialization
);
criterion_main!(proxy_benches);
