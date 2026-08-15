use super::ProxyError;
use super::env::{ProxyEnv, Upstream, no_proxy_matches};
use super::http_connect;
use super::socks;
use super::types::DynStreamBox;

/// Dial to `host:port` according to the proxy environment.
/// - no_proxy exemptions: matching hosts bypass the proxy and dial directly
/// - Otherwise the upstream (Direct / Socks5 / HttpConnect) determines the path
pub async fn connect(env: &ProxyEnv, host: &str, port: u16) -> Result<DynStreamBox, ProxyError> {
    if !env.no_proxy.is_empty() && no_proxy_matches(host, &env.no_proxy) {
        return Ok(Box::new(
            tokio::net::TcpStream::connect((host, port)).await?,
        ));
    }
    match &env.upstream {
        Upstream::Direct => Ok(Box::new(
            tokio::net::TcpStream::connect((host, port)).await?,
        )),
        Upstream::Socks5 { addr, user, pass } => {
            socks::socks5_connect(addr, host, port, user.as_deref(), pass.as_deref()).await
        }
        Upstream::HttpConnect { url } => {
            http_connect::HttpConnectDialer {
                url: url.clone(),
                root_certs: None,
            }
            .connect(host, port)
            .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use url::Url;

    #[tokio::test]
    async fn connect_direct_connects_locally() {
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut conn, _) = listener.accept().await.unwrap();
            let mut b = [0u8; 3];
            conn.read_exact(&mut b).await.unwrap();
            conn.write_all(&b).await.unwrap();
        });
        let env = ProxyEnv {
            upstream: Upstream::Direct,
            no_proxy: String::new(),
        };
        let mut conn = connect(&env, "127.0.0.1", addr.port()).await.unwrap();
        conn.write_all(b"xyz").await.unwrap();
        let mut resp = [0u8; 3];
        conn.read_exact(&mut resp).await.unwrap();
        assert_eq!(&resp, b"xyz");
    }

    #[tokio::test]
    async fn connect_bypasses_proxy_when_no_proxy_matches() {
        use tokio::net::TcpListener;
        // Target listener: when no_proxy matches, connect must succeed directly
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut conn, _) = listener.accept().await.unwrap();
            let mut b = [0u8; 3];
            conn.read_exact(&mut b).await.unwrap();
            conn.write_all(&b).await.unwrap();
        });
        // Upstream points at a proxy that cannot connect: if no_proxy did not take effect
        // (i.e. traffic went through the proxy) the connect would fail
        let env = ProxyEnv {
            upstream: Upstream::HttpConnect {
                url: Url::parse("http://127.0.0.1:1").unwrap(),
            },
            no_proxy: "127.0.0.1".to_string(),
        };
        let mut conn = connect(&env, "127.0.0.1", addr.port()).await.unwrap();
        conn.write_all(b"xyz").await.unwrap();
        let mut resp = [0u8; 3];
        conn.read_exact(&mut resp).await.unwrap();
        assert_eq!(&resp, b"xyz");
    }
}
