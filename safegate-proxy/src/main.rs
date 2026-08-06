//! SafeGate's asynchronous MCP reverse proxy executable.

mod config;
mod proxy;

use std::sync::Arc;

use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tracing::{error, info};

use crate::config::ProxyConfig;
use crate::proxy::Proxy;

/// Starts the SafeGate reverse proxy.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_target(false)
        .compact()
        .init();

    let config = ProxyConfig::default();
    let listener = TcpListener::bind(config.listen_addr).await?;
    let proxy = Arc::new(Proxy::new(config.clone())?);

    info!(
        "[SafeGate Proxy] Listening on http://{} -> Forwarding to {}",
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
