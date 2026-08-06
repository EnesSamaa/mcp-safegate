//! SafeGate's asynchronous MCP reverse proxy executable.

use std::sync::Arc;

use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tracing::{error, info};

use safegate_proxy::{Proxy, ProxyConfig};
use safegate_wasm::{WasmPolicyEngine, watcher::PolicyWatcher};

/// Starts the SafeGate reverse proxy.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_target(false)
        .compact()
        .init();

    let config = ProxyConfig::default();

    // ── Hot-reload watcher setup ──────────────────────────────────────────────
    let engine = WasmPolicyEngine::new().unwrap_or_else(|error| {
        // This is a fatal startup failure; the process cannot continue without
        // a working Wasmtime component-model engine.
        panic!("failed to initialise WASM policy engine: {error}");
    });

    let policy_watcher = PolicyWatcher::new(config.policy_dir.clone(), engine);
    let policy_handle = policy_watcher.shared();

    // The watcher task runs for the lifetime of the process.
    // Dropping `_watcher_task` would *detach* it (it keeps running), but we
    // bind it to a variable so clippy does not warn about the unused future.
    let _watcher_task = policy_watcher.start();

    info!(
        dir = %config.policy_dir.display(),
        "WASM policy hot-reload watcher started"
    );
    // ─────────────────────────────────────────────────────────────────────────

    let listener = TcpListener::bind(config.listen_addr).await?;
    let proxy = Arc::new(Proxy::new(config.clone(), policy_handle)?);

    info!(
        "SafeGate Proxy listening on http://{} → forwarding to {}",
        config.listen_addr, config.target_mcp_url
    );

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let proxy = Arc::clone(&proxy);

        tokio::spawn(async move {
            let service = service_fn(move |request| {
                let proxy = Arc::clone(&proxy);
                async move { Ok::<_, std::convert::Infallible>(proxy.handle_request(request).await) }
            });

            if let Err(error) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await
            {
                error!(%peer_addr, %error, "client connection failed");
            }
        });
    }
}
