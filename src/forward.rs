use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};
use tokio::net::TcpStream;

use crate::proxy::{ProxyEnv, ProxyError, connect};

#[derive(Debug, thiserror::Error)]
pub enum ForwardError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("sniff failed: {0}")]
    Sniff(String),
    #[error(transparent)]
    Proxy(#[from] ProxyError),
}

pub const SNIFF_BUF_LIMIT: usize = 64 * 1024;

pub type SniffFn = fn(&[u8]) -> Result<Option<String>, String>;

/// Prefix replay: first drain the bytes buffered during sniffing, then read the
/// underlying stream. Data read during sniffing (including over-read bytes) is
/// replayed verbatim into the forwarding stream via this wrapper.
pub struct Prepend<R> {
    prefix: Vec<u8>,
    pos: usize,
    inner: R,
}

impl<R> Prepend<R> {
    pub fn new(prefix: Vec<u8>, inner: R) -> Self {
        Self {
            prefix,
            pos: 0,
            inner,
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for Prepend<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.pos < self.prefix.len() {
            let n = std::cmp::min(buf.remaining(), self.prefix.len() - self.pos);
            buf.put_slice(&self.prefix[self.pos..self.pos + n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

pub async fn sniff_host_and_forward(
    parse: SniffFn,
    mut client: TcpStream,
    env: &ProxyEnv,
) -> Result<(), ForwardError> {
    let lport = client.local_addr()?.port();
    let caddr = client.peer_addr()?;

    // 1. Sniff: accumulate until host is parsed (strict: malformed => Err, EOF without host => Err, 64KB cap)
    let mut buf: Vec<u8> = Vec::new();
    let host = loop {
        match parse(&buf) {
            Ok(Some(host)) => break host,
            Ok(None) => {
                if buf.len() >= SNIFF_BUF_LIMIT {
                    return Err(ForwardError::Sniff("sniff buffer exceeded 64KB".into()));
                }
                let n = client.read_buf(&mut buf).await?;
                if n == 0 {
                    return Err(ForwardError::Sniff("EOF while sniffing host".into()));
                }
            }
            Err(e) => return Err(ForwardError::Sniff(e)),
        }
    };

    let saddr = format!("{host}:{lport}");
    tracing::info!(%caddr, lport, saddr, "connecting");

    // 2. Dial (honoring no_proxy exemptions)
    let mut upstream_conn = connect(env, &host, lport).await?;
    tracing::info!(%caddr, lport, saddr, "connected");

    // 3. Bidirectional relay: close everything as soon as either direction finishes
    //    (EOF or error). The upstream side is split with io::split because two &mut
    //    borrows cannot be given to the two select futures.
    let (client_rd, mut client_wr) = client.into_split();
    let mut src = Prepend::new(buf, client_rd);
    let (mut upstream_rd, mut upstream_wr) = tokio::io::split(&mut upstream_conn);
    tokio::select! {
        r1 = tokio::io::copy(&mut src, &mut upstream_wr) => {
            r1?;
            tracing::info!(%caddr, lport, saddr, "finished transporting");
        }
        r2 = tokio::io::copy(&mut upstream_rd, &mut client_wr) => {
            r2?;
            tracing::info!(%caddr, lport, saddr, "finished transporting");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    /// First accept runs the forwarder; second accept is the mock target.
    /// The client sends 20 bytes while parse resolves the host after 4 bytes,
    /// proving the 16 over-read bytes survive through Prepend.
    #[tokio::test]
    async fn forwards_all_sniffed_prefix_data() {
        let listener = Arc::new(TcpListener::bind("127.0.0.1:0").await.unwrap());
        let addr = listener.local_addr().unwrap();

        let parse: SniffFn = |buf: &[u8]| {
            if buf.len() >= 4 {
                Ok(Some("localhost".to_string()))
            } else {
                Ok(None)
            }
        };

        // Mock target: read 20 bytes, reply 11 bytes, close
        let mock_listener = listener.clone();
        let mock = tokio::spawn(async move {
            let (mut conn, _) = mock_listener.accept().await.unwrap();
            let mut data = [0u8; 20];
            conn.read_exact(&mut data).await.unwrap();
            conn.write_all(b"from-target").await.unwrap();
        });

        // Forwarder
        let fwd_listener = listener.clone();
        let fwd = tokio::spawn(async move {
            let (conn, _) = fwd_listener.accept().await.unwrap();
            let env = ProxyEnv {
                upstream: crate::proxy::Upstream::Direct,
                no_proxy: String::new(),
            };
            sniff_host_and_forward(parse, conn, &env).await.unwrap();
        });

        // Client
        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(b"hello-from-client-xx").await.unwrap(); // 20 bytes
        let mut resp = [0u8; 11];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(&resp, b"from-target");
        drop(client);

        mock.await.unwrap();
        fwd.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_when_parse_fails() {
        let listener = Arc::new(TcpListener::bind("127.0.0.1:0").await.unwrap());
        let addr = listener.local_addr().unwrap();

        let parse: SniffFn = |_buf: &[u8]| Err("malformed".to_string());

        let fwd_listener = listener.clone();
        let fwd = tokio::spawn(async move {
            let (conn, _) = fwd_listener.accept().await.unwrap();
            let env = ProxyEnv {
                upstream: crate::proxy::Upstream::Direct,
                no_proxy: String::new(),
            };
            sniff_host_and_forward(parse, conn, &env).await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(b"garbage").await.unwrap();
        let err = fwd.await.unwrap().unwrap_err();
        assert!(err.to_string().contains("malformed"));
    }
}
