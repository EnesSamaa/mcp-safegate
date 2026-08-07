//! SafeGate's asynchronous MCP reverse proxy executable.

use std::sync::Arc;

use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use safegate_audit::writer::{AuditLogger, AuditSink};
use tokio::net::TcpListener;
use tracing::{error, info};

use safegate_proxy::{Proxy, ProxyConfig};
use safegate_wasm::{PolicyRegistry, WasmPolicyEngine, watcher::PolicyWatcher};

/// Starts the SafeGate reverse proxy.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_target(false)
        .compact()
        .init();

    let config = ProxyConfig::default();

    // ── Default WASM hot-reload watcher ──────────────────────────────────────
    // Watches `policy_dir` for the single default policy (default.wasm).
    let engine = WasmPolicyEngine::new().unwrap_or_else(|error| {
        panic!("failed to initialise WASM policy engine: {error}");
    });
    let policy_watcher = PolicyWatcher::new(config.policy_dir.clone(), engine);
    let default_handle = policy_watcher.shared();
    let _watcher_task = policy_watcher.start();
    info!(
        dir = %config.policy_dir.display(),
        "WASM default policy hot-reload watcher started"
    );

    // ── Multi-tenant policy registry ─────────────────────────────────────────
    // Watches `tenant_policy_dir` (e.g. policies/tenants/) and maps each
    // `<tenant_id>.wasm` to its own engine.  Falls back to `default_handle`.
    let policy_registry = Arc::new(PolicyRegistry::new(
        config.tenant_policy_dir.clone(),
        default_handle,
    ));
    let _registry_watcher_task = policy_registry.start();
    info!(
        dir = %config.tenant_policy_dir.display(),
        "multi-tenant policy registry watcher started"
    );

    // ── Audit logger ──────────────────────────────────────────────────────────
    // In production replace `AuditSink::Stdout` with `AuditSink::File(path)`.
    let hmac_secret = std::env::var("SAFEGATE_AUDIT_HMAC_SECRET")
        .unwrap_or_else(|_| "change-me-in-production".to_owned());
    let audit_logger = Arc::new(AuditLogger::new(AuditSink::Stdout, hmac_secret.as_bytes()));
    info!("audit logger started (stdout)");

    // ── Proxy ─────────────────────────────────────────────────────────────────
    let listener = TcpListener::bind(config.listen_addr).await?;
    let proxy = Arc::new(Proxy::new(config.clone(), policy_registry, audit_logger)?);

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
