use fast_socks5::client::{Config, Socks5Stream};
#[cfg(test)]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(test)]
use tokio::net::TcpListener;
#[cfg(test)]
use tokio::sync::oneshot;

use super::{DynStreamBox, ProxyError};

/// SOCKS5 client with socks5h semantics (target domain resolved by the proxy,
/// no local DNS), backed by fast-socks5.
pub async fn socks5_connect(
    proxy_addr: &str,
    host: &str,
    port: u16,
    user: Option<&str>,
    pass: Option<&str>,
) -> Result<DynStreamBox, ProxyError> {
    let config = Config::default();
    let socket = match (user, pass) {
        (Some(u), Some(p)) => Socks5Stream::connect_with_password(
            proxy_addr,
            host.to_string(),
            port,
            u.to_string(),
            p.to_string(),
            config,
        )
        .await
        .map_err(|e| ProxyError::Socks(e.to_string()))?,
        _ => Socks5Stream::connect(proxy_addr, host.to_string(), port, config)
            .await
            .map_err(|e| ProxyError::Socks(e.to_string()))?,
    };
    Ok(Box::new(socket))
}

/// Mock SOCKS5 server: no-auth / user-pass negotiation + domain CONNECT + echo 3 bytes
#[cfg(test)]
async fn start_mock_socks5(with_auth: bool) -> (String, oneshot::Receiver<(String, u16)>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        let (mut conn, _) = listener.accept().await.unwrap();
        let mut g = [0u8; 2];
        conn.read_exact(&mut g).await.unwrap();
        assert_eq!(g[0], 0x05);
        // Read and discard the methods list (greeting = version(1) + nmethods(1) + methods(n))
        let mut methods = vec![0u8; g[1] as usize];
        conn.read_exact(&mut methods).await.unwrap();
        if with_auth {
            // Client sends [0x05, 0x02, 0x00, 0x02]; we pick user/pass
            conn.write_all(&[0x05, 0x02]).await.unwrap();
            let mut auth = [0u8; 2];
            conn.read_exact(&mut auth).await.unwrap();
            assert_eq!(auth[0], 0x01);
            // Auth head = [ver, ulen]; read the username directly by ulen
            let mut u = vec![0u8; auth[1] as usize];
            conn.read_exact(&mut u).await.unwrap();
            let mut plen = [0u8; 1];
            conn.read_exact(&mut plen).await.unwrap();
            let mut p = vec![0u8; plen[0] as usize];
            conn.read_exact(&mut p).await.unwrap();
            assert_eq!(u, b"user");
            assert_eq!(p, b"pass");
            conn.write_all(&[0x01, 0x00]).await.unwrap();
        } else {
            conn.write_all(&[0x05, 0x00]).await.unwrap();
        }
        let mut hdr = [0u8; 4];
        conn.read_exact(&mut hdr).await.unwrap();
        assert_eq!(hdr, [0x05, 0x01, 0x00, 0x03]); // CONNECT + domain type
        let mut len = [0u8; 1];
        conn.read_exact(&mut len).await.unwrap();
        let mut host = vec![0u8; len[0] as usize];
        conn.read_exact(&mut host).await.unwrap();
        let mut port = [0u8; 2];
        conn.read_exact(&mut port).await.unwrap();
        let _ = tx.send((String::from_utf8(host).unwrap(), u16::from_be_bytes(port)));
        conn.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut e = [0u8; 3];
        conn.read_exact(&mut e).await.unwrap();
        conn.write_all(&e).await.unwrap();
    });
    (format!("127.0.0.1:{}", addr.port()), rx)
}

#[tokio::test]
async fn socks5_sends_domain_to_proxy_and_tunnels() {
    let (proxy_addr, received) = start_mock_socks5(false).await;
    let mut conn = socks5_connect(&proxy_addr, "target.example", 443, None, None)
        .await
        .unwrap();
    conn.write_all(b"abc").await.unwrap();
    let mut resp = [0u8; 3];
    conn.read_exact(&mut resp).await.unwrap();
    assert_eq!(&resp, b"abc");
    let (host, port) = received.await.unwrap();
    assert_eq!(host, "target.example");
    assert_eq!(port, 443);
}

#[tokio::test]
async fn socks5_with_user_pass_auth() {
    let (proxy_addr, received) = start_mock_socks5(true).await;
    let mut conn = socks5_connect(
        &proxy_addr,
        "target.example",
        443,
        Some("user"),
        Some("pass"),
    )
    .await
    .unwrap();
    conn.write_all(b"abc").await.unwrap();
    let mut resp = [0u8; 3];
    conn.read_exact(&mut resp).await.unwrap();
    assert_eq!(&resp, b"abc");
    let (host, _port) = received.await.unwrap();
    assert_eq!(host, "target.example");
}
