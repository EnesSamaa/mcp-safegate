use std::sync::Arc;

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
use safegate_proxy::{Proxy, ProxyConfig};
use tokio::net::TcpListener;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

type TestBody = Full<Bytes>;

async fn start_proxy(target_mcp_url: String) -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("test proxy listener should bind");
    let address = listener
        .local_addr()
        .expect("test proxy listener should have an address");
    let proxy = Arc::new(
        Proxy::new(ProxyConfig {
            listen_addr: address,
            target_mcp_url,
        })
        .expect("test proxy should initialize"),
    );

    tokio::spawn(async move {
        loop {
            let (stream, _) = listener
                .accept()
                .await
                .expect("test listener should accept");
            let proxy = Arc::clone(&proxy);
            tokio::spawn(async move {
                let service = service_fn(move |request| {
                    let proxy = Arc::clone(&proxy);
                    async move { Ok::<_, std::convert::Infallible>(proxy.handle_request(request).await) }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });

    format!("http://{address}")
}

fn tools_call_request(uri: String, authenticated: bool) -> Request<TestBody> {
    let mut request = Request::builder()
        .method("POST")
        .uri(uri)
        .header(CONTENT_TYPE, "application/json")
        .header("x-agent-id", "e2e-agent")
        .header("x-tenant-id", "test-tenant");
    if authenticated {
        request = request.header(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer safegate-dev-token"),
        );
    }
    request
        .body(Full::new(Bytes::from_static(
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"lookup"}}"#,
        )))
        .expect("test request should be valid")
}

#[tokio::test]
async fn forwards_authenticated_json_rpc_calls_to_upstream() {
    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_json(serde_json::json!({"jsonrpc":"2.0","id":1,"result":{"ok":true}})),
        )
        .mount(&upstream)
        .await;
    let proxy_url = start_proxy(upstream.uri()).await;
    let client: Client<HttpConnector, TestBody> =
        Client::builder(TokioExecutor::new()).build_http();

    let response = client
        .request(tools_call_request(proxy_url, true))
        .await
        .expect("proxy should respond");
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body should read")
        .to_bytes();

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).expect("response must be JSON"),
        serde_json::json!({"jsonrpc":"2.0","id":1,"result":{"ok":true}})
    );
}

#[tokio::test]
async fn rejects_unauthenticated_requests_before_upstream() {
    let upstream = MockServer::start().await;
    let proxy_url = start_proxy(upstream.uri()).await;
    let client: Client<HttpConnector, TestBody> =
        Client::builder(TokioExecutor::new()).build_http();

    let response = client
        .request(tools_call_request(proxy_url, false))
        .await
        .expect("proxy should respond");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
