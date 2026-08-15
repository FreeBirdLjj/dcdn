use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use dcdn::forward::sniff_host_and_forward;
use dcdn::fwdhttp::parse_http_host;
use dcdn::fwdtls::parse_tls_server_name;
use dcdn::proxy::from_environment;
use dcdn::server::{Handler, serve};

#[tokio::main]
async fn main() -> io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let env = Arc::new(from_environment());
    let token = CancellationToken::new();

    // Listen addresses default to :80/:443. Constructed as SocketAddr directly
    // because the ":80" string form goes through getaddrinfo, which fails on
    // Android bionic for an empty host (EAI_NONAME).
    let http_listener = TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], 80))).await?;
    let https_listener = TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], 443))).await?;

    // Handlers log errors but never exit the process
    let http_up = env.clone();
    let http_handler: Handler = Arc::new(move |conn| {
        let up = http_up.clone();
        tokio::spawn(async move {
            if let Err(e) = sniff_host_and_forward(parse_http_host, conn, &up).await {
                tracing::error!("http forward failed: {e}");
            }
        });
    });
    let https_up = env.clone();
    let https_handler: Handler = Arc::new(move |conn| {
        let up = https_up.clone();
        tokio::spawn(async move {
            if let Err(e) = sniff_host_and_forward(parse_tls_server_name, conn, &up).await {
                tracing::error!("https forward failed: {e}");
            }
        });
    });

    let server_tasks = vec![
        tokio::spawn(serve(http_listener, token.clone(), http_handler)),
        tokio::spawn(serve(https_listener, token.clone(), https_handler)),
    ];

    // Wait for SIGINT / SIGTERM, then shut the servers down gracefully. SIGKILL
    // cannot be caught and is therefore not handled. Listener errors never exit
    // the process: the servers log errors and keep running until shutdown.
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut int = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
    }
    tracing::info!("dcdn shutting down");
    token.cancel();
    let _ = futures_util::future::join_all(server_tasks).await;
    Ok(())
}
