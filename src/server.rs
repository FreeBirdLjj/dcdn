use std::io;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

pub type Handler = Arc<dyn Fn(TcpStream) + Send + Sync>;

/// Accept loop: spawns one task per accepted connection so handlers run concurrently.
pub async fn serve(
    listener: TcpListener,
    token: CancellationToken,
    handler: Handler,
) -> io::Result<()> {
    loop {
        tokio::select! {
            _ = token.cancelled() => return Ok(()),
            res = listener.accept() => {
                let (conn, _addr) = match res {
                    Ok(x) => x,
                    Err(e) => {
                        tracing::error!("failed to accept new connection: {e}");
                        continue; // tolerate transient accept errors and keep serving
                    }
                };
                let conn = match configure_conn(conn) {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::error!("failed to configure connection: {e}");
                        continue;
                    }
                };
                let handler = handler.clone();
                tokio::spawn(async move { handler(conn) });
            }
        }
    }
}

/// Connection setup: enable TCP keepalive (15s idle probe + 15s interval)
fn configure_conn(conn: TcpStream) -> io::Result<TcpStream> {
    let std_stream = conn.into_std()?;
    enable_keepalive(&std_stream);
    TcpStream::from_std(std_stream)
}

fn enable_keepalive(stream: &std::net::TcpStream) {
    use socket2::{SockRef, TcpKeepalive};
    use std::time::Duration;
    let sock = SockRef::from(stream);
    let _ = sock.set_tcp_keepalive(
        &TcpKeepalive::new()
            .with_time(Duration::from_secs(15))
            .with_interval(Duration::from_secs(15)),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::oneshot;

    #[tokio::test]
    async fn serve_dispatches_connection_to_handler() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let token = CancellationToken::new();
        let (tx, rx) = oneshot::channel();
        // Fn closures can only capture immutably; take through a Mutex
        let tx = Arc::new(std::sync::Mutex::new(Some(tx)));
        let handler: Handler = Arc::new(move |_conn| {
            if let Some(tx) = tx.lock().unwrap().take() {
                let _ = tx.send(());
            }
        });
        let task = tokio::spawn(serve(listener, token.clone(), handler));
        let _client = TcpStream::connect(addr).await.unwrap();
        rx.await.expect("handler should have run");
        token.cancel();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn serve_returns_ok_when_cancelled() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let token = CancellationToken::new();
        let handler: Handler = Arc::new(|_conn| {});
        let task = tokio::spawn(serve(listener, token.clone(), handler));
        token.cancel();
        task.await.unwrap().unwrap();
    }
}
