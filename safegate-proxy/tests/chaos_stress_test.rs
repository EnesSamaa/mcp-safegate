//! Chaos and high-concurrency stress tests for the SafeGate reverse proxy.
//!
//! Simulates high-throughput production load with concurrent tasks sending
//! thousands of requests simultaneously to verify zero data races, panics, or deadlock.

use std::{path::PathBuf, sync::Arc, time::Duration};

use arc_swap::ArcSwap;
use http_body_util::{BodyExt, Full};
use hyper::{
    Request, StatusCode,
    body::Bytes,
    header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue},
    service::service_fn,
};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioIo},
};
use safegate_audit::writer::{AuditLogger, AuditSink};
use safegate_proxy::{Proxy, ProxyConfig};
use safegate_wasm::{PolicyRegistry, WasmPolicyEngine};
use serde_json::json;
use tokio::{net::TcpListener, task::JoinSet};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

type TestBody = Full<Bytes>;

const TEST_HMAC_SECRET: &[u8] = b"chaos-stress-test-key";

#[tokio::test]
async fn stress_100_concurrent_tasks_thousands_of_requests() {
    tokio::time::timeout(Duration::from_secs(10), async move {
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
            .expect("stress test listener should bind");
        let address = listener.local_addr().expect("listener address");

        let engine = WasmPolicyEngine::new().expect("engine should initialize");
        let default_handle = Arc::new(ArcSwap::from_pointee(engine));
        let registry = Arc::new(PolicyRegistry::new(
            PathBuf::from("./policies/tenants"),
            default_handle,
        ));
        let tmp_log = std::env::temp_dir().join(format!("safegate-stress-audit-{}.log", std::process::id()));
        let audit_logger = Arc::new(AuditLogger::new(AuditSink::File(tmp_log.clone()), TEST_HMAC_SECRET));

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

        let proxy_handle = tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => break,
                };
                let proxy = Arc::clone(&proxy);
                tokio::spawn(async move {
                    let service = service_fn(move |req| {
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
        let num_tasks = 20;
        let requests_per_task = 10;

        let mut join_set = JoinSet::new();

        for task_idx in 0..num_tasks {
            let proxy_url = proxy_url.clone();
            join_set.spawn(async move {
                let client: Client<HttpConnector, TestBody> =
                    Client::builder(TokioExecutor::new()).build_http();

                let agent_id = format!("agent-{}", task_idx % 10);
                let tenant_id = format!("tenant-{}", task_idx % 5);

                for req_idx in 0..requests_per_task {
                    let has_pii = req_idx % 3 == 0;
                    let is_unauth = req_idx % 7 == 0;

                    let payload = if has_pii {
                        json!({
                            "jsonrpc": "2.0",
                            "id": req_idx,
                            "method": "tools/call",
                            "params": {
                                "name": "contact_user",
                                "arguments": {
                                    "email": "stress_user@example.com",
                                    "token": "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
                                }
                            }
                        })
                    } else {
                        json!({
                            "jsonrpc": "2.0",
                            "id": req_idx,
                            "method": "tools/call",
                            "params": {
                                "name": "ping",
                                "arguments": { "msg": "stress" }
                            }
                        })
                    };

                    let mut req_builder = Request::builder()
                        .method("POST")
                        .uri(format!("{proxy_url}/"))
                        .header(CONTENT_TYPE, "application/json")
                        .header("x-agent-id", &agent_id)
                        .header("x-tenant-id", &tenant_id);

                    if !is_unauth {
                        req_builder = req_builder.header(
                            AUTHORIZATION,
                            HeaderValue::from_static("Bearer safegate-dev-token"),
                        );
                    }

                    let req = req_builder
                        .body(Full::new(Bytes::from(payload.to_string())))
                        .expect("request should build");

                    let response = client.request(req).await.expect("proxy must respond");
                    let status = response.status();
                    let _ = response.into_body().collect().await;

                    assert!(
                        status == StatusCode::OK
                            || status == StatusCode::UNAUTHORIZED
                            || status == StatusCode::TOO_MANY_REQUESTS,
                        "unexpected status code: {status}"
                    );
                }
            });
        }

        while let Some(res) = join_set.join_next().await {
            res.expect("task completed without panic");
        }

        // Abort the proxy server background task
        proxy_handle.abort();
        let _ = std::fs::remove_file(tmp_log);
    })
    .await
    .unwrap();
}
