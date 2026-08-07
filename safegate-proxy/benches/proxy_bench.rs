//! Micro and pipeline benchmarks for the SafeGate reverse proxy.
//!
//! Benchmark suites:
//! 1. `bench_pii_redactor`: PII scanning & sanitisation (sanitize_str & sanitize_json).
//! 2. `bench_circuit_breaker`: Per-agent failure check and recording.
//! 3. `bench_policy_registry`: Tenant policy resolution via lock-free ArcSwap lookup.
//! 4. `bench_proxy_pipeline`: End-to-end HTTP request processing pipeline.

use std::{path::PathBuf, sync::Arc};

use arc_swap::ArcSwap;
use criterion::{Criterion, criterion_group, criterion_main};
use http_body_util::Full;
use hyper::{
    Request, StatusCode,
    body::Bytes,
    header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue},
};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioIo},
};
use safegate_audit::writer::{AuditLogger, AuditSink};
use safegate_core::PiiRedactor;
use safegate_proxy::{Proxy, ProxyConfig, circuit_breaker::CircuitBreaker};
use safegate_wasm::{PolicyRegistry, WasmPolicyEngine};
use serde_json::json;
use tokio::net::TcpListener;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

type TestBody = Full<Bytes>;

// ── 1. Micro-benchmarks ───────────────────────────────────────────────────────

fn bench_pii_redactor(c: &mut Criterion) {
    let redactor = PiiRedactor::new();
    let plain_text = "Clean text with no PII whatsoever.";
    let pii_text =
        "Contact alice@secret.com or send sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 to API.";

    let mut group = c.benchmark_group("PII_Redactor");

    group.bench_function("sanitize_str_clean", |b| {
        b.iter(|| redactor.sanitize_str(plain_text));
    });

    group.bench_function("sanitize_str_pii", |b| {
        b.iter(|| redactor.sanitize_str(pii_text));
    });

    let json_val = json!({
        "user": "alice@example.com",
        "api_key": "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        "nested": {
            "card": "4111-1111-1111-1111",
            "safe": "hello world"
        }
    });

    group.bench_function("sanitize_json", |b| {
        b.iter(|| {
            let mut clone = json_val.clone();
            redactor.sanitize_json(&mut clone);
        });
    });

    group.finish();
}

fn bench_circuit_breaker(c: &mut Criterion) {
    let cb = CircuitBreaker::new();
    let mut group = c.benchmark_group("CircuitBreaker");

    group.bench_function("check_allowed", |b| {
        b.iter(|| cb.check("agent-normal"));
    });

    group.bench_function("record_failure", |b| {
        b.iter(|| cb.record_failure("agent-failing"));
    });

    group.finish();
}

fn bench_policy_registry(c: &mut Criterion) {
    let engine = WasmPolicyEngine::new().expect("engine should initialize");
    let default_handle = Arc::new(ArcSwap::from_pointee(engine));
    let registry = PolicyRegistry::new(PathBuf::from("./policies/tenants"), default_handle);

    let mut group = c.benchmark_group("PolicyRegistry");

    group.bench_function("get_default_tenant", |b| {
        b.iter(|| registry.get("unknown-tenant"));
    });

    group.finish();
}

// ── 2. Pipeline E2E Benchmarks ────────────────────────────────────────────────

fn bench_proxy_pipeline(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime should build");

    let mut group = c.benchmark_group("Proxy_Pipeline");

    rt.block_on(async {
        let upstream = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_json(json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": { "status": "ok" }
                    })),
            )
            .mount(&upstream)
            .await;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let address = listener.local_addr().expect("listener address");

        let engine = WasmPolicyEngine::new().expect("engine should initialize");
        let default_handle = Arc::new(ArcSwap::from_pointee(engine));
        let registry = Arc::new(PolicyRegistry::new(
            PathBuf::from("./policies/tenants"),
            default_handle,
        ));
        let audit_logger = Arc::new(AuditLogger::new(AuditSink::Stdout, b"bench-key"));

        let proxy = Arc::new(
            Proxy::new(
                ProxyConfig {
                    listen_addr: address,
                    target_mcp_url: upstream.uri(),
                    policy_dir: PathBuf::from("./policies"),
                    tenant_policy_dir: PathBuf::from("./policies/tenants"),
                },
                registry,
                audit_logger,
            )
            .expect("proxy should initialize"),
        );

        tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => break,
                };
                let proxy = Arc::clone(&proxy);
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(move |req| {
                        let proxy = Arc::clone(&proxy);
                        async move { Ok::<_, std::convert::Infallible>(proxy.handle_request(req).await) }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });

        let proxy_url = format!("http://{address}");
        let client: Client<HttpConnector, TestBody> =
            Client::builder(TokioExecutor::new()).build_http();

        group.bench_function("allow_request_pipeline", |b| {
            b.to_async(&rt).iter(|| async {
                let req = Request::builder()
                    .method("POST")
                    .uri(format!("{proxy_url}/"))
                    .header(CONTENT_TYPE, "application/json")
                    .header("x-agent-id", "bench-agent")
                    .header("x-tenant-id", "bench-tenant")
                    .header(
                        AUTHORIZATION,
                        HeaderValue::from_static("Bearer safegate-dev-token"),
                    )
                    .body(Full::new(Bytes::from(
                        json!({
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "tools/call",
                            "params": {
                                "name": "ping",
                                "arguments": { "msg": "hello" }
                            }
                        })
                        .to_string(),
                    )))
                    .unwrap();

                let res = client.request(req).await.unwrap();
                assert_eq!(res.status(), StatusCode::OK);
            });
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_pii_redactor,
    bench_circuit_breaker,
    bench_policy_registry,
    bench_proxy_pipeline
);
criterion_main!(benches);
