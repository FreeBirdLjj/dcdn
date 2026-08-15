use base64::Engine;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(test)]
use tokio::net::TcpListener;
use tokio::net::TcpStream;
#[cfg(test)]
use tokio::sync::oneshot;
use url::Url;

use super::{DynStream, DynStreamBox, ProxyError};

pub struct HttpConnectDialer {
    pub url: Url,
    pub root_certs: Option<Vec<u8>>,
}

impl HttpConnectDialer {
    pub async fn connect(&self, host: &str, port: u16) -> Result<DynStreamBox, ProxyError> {
        let proxy_addr = canonical_addr(&self.url)?;
        let mut conn: DynStreamBox = match self.url.scheme() {
            "https" => {
                let tcp = TcpStream::connect(&proxy_addr).await?;
                self.tls_to_proxy(tcp).await?
            }
            _ => Box::new(TcpStream::connect(&proxy_addr).await?),
        };
        send_connect(&mut conn, host, port, &self.url).await?;
        Ok(conn)
    }

    async fn tls_to_proxy(&self, tcp: TcpStream) -> Result<DynStreamBox, ProxyError> {
        let mut roots = rustls::RootCertStore::empty();
        match &self.root_certs {
            Some(pem) => {
                let mut reader = std::io::BufReader::new(pem.as_slice());
                for cert in rustls_pemfile::certs(&mut reader) {
                    roots
                        .add(cert.map_err(|e| ProxyError::Tls(e.to_string()))?)
                        .map_err(|e| ProxyError::Tls(e.to_string()))?;
                }
            }
            None => {
                let native = rustls_native_certs::load_native_certs();
                for cert in native.certs {
                    roots
                        .add(cert)
                        .map_err(|e| ProxyError::Tls(e.to_string()))?;
                }
            }
        }
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let hostname = self
            .url
            .host_str()
            .ok_or_else(|| ProxyError::InvalidUrl("no host in proxy url".into()))?;
        let server_name = rustls::pki_types::ServerName::try_from(hostname.to_string())
            .map_err(|e| ProxyError::Tls(e.to_string()))?;
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let tls = connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| ProxyError::Tls(e.to_string()))?;
        // The CONNECT request must be written inside the TLS stream; return TlsStream as-is
        Ok(Box::new(tls))
    }
}

/// Always has a port: defaults http→80 / https→443
fn canonical_addr(url: &Url) -> Result<String, ProxyError> {
    let host = url
        .host_str()
        .ok_or_else(|| ProxyError::InvalidUrl("no host in proxy url".into()))?;
    let port = url.port().unwrap_or(match url.scheme() {
        "http" => 80,
        "https" => 443,
        _ => {
            return Err(ProxyError::InvalidUrl(format!(
                "unsupported scheme: {}",
                url.scheme()
            )));
        }
    });
    Ok(format!("{host}:{port}"))
}

async fn send_connect(
    conn: &mut dyn DynStream,
    host: &str,
    port: u16,
    url: &Url,
) -> Result<(), ProxyError> {
    let mut req = format!("CONNECT {host}:{port} HTTP/1.1\r\nProxy-Connection: Keep-Alive\r\n");
    if !url.username().is_empty() {
        let user = url.username();
        let pass = url.password().unwrap_or("");
        let auth = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
        req.push_str(&format!("Proxy-Authorization: Basic {auth}\r\n"));
    }
    req.push_str("\r\n");
    conn.write_all(req.as_bytes()).await?;

    // Read the response head (httparse) until a complete head is available
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut resp = httparse::Response::new(&mut headers);
        match resp.parse(&buf) {
            Ok(httparse::Status::Complete(n)) => {
                let code = resp
                    .code
                    .ok_or_else(|| ProxyError::Socks("no status code".into()))?;
                if code != 200 {
                    // Read the remaining body (capped at 4KB to avoid hanging), fold it into the error
                    let mut body: Vec<u8> = buf[n..].to_vec();
                    while body.len() < 4096 {
                        let r = conn.read_buf(&mut body).await?;
                        if r == 0 {
                            break;
                        }
                    }
                    return Err(ProxyError::ConnectFailed {
                        code,
                        body: String::from_utf8_lossy(&body).into_owned(),
                    });
                }
                return Ok(());
            }
            Ok(httparse::Status::Partial) => {
                let n = conn.read_buf(&mut buf).await?;
                if n == 0 {
                    return Err(ProxyError::Socks(
                        "proxy closed during CONNECT handshake".into(),
                    ));
                }
            }
            Err(e) => return Err(ProxyError::Socks(format!("bad proxy response: {e}"))),
        }
    }
}

/// Start a mock CONNECT proxy: validate the request head → reply with status → echo 5 bytes (200 only)
#[cfg(test)]
async fn start_mock_connect_proxy(status: u16) -> (String, oneshot::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        let (mut conn, _) = listener.accept().await.unwrap();
        let mut buf = Vec::new();
        loop {
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
            let n = conn.read_buf(&mut buf).await.unwrap();
            if n == 0 {
                panic!("proxy conn closed early");
            }
        }
        let _ = tx.send(String::from_utf8_lossy(&buf).into_owned());
        if status == 200 {
            conn.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
            let mut echo = [0u8; 5];
            conn.read_exact(&mut echo).await.unwrap();
            conn.write_all(&echo).await.unwrap();
        } else {
            let body = format!("denied by proxy: {status}");
            conn.write_all(
                format!(
                    "HTTP/1.1 {status} Denied\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        }
    });
    (format!("http://{addr}"), rx)
}

#[tokio::test]
async fn http_connect_tunnels_and_sends_correct_request() {
    let (proxy_url, received) = start_mock_connect_proxy(200).await;
    let dialer = HttpConnectDialer {
        url: Url::parse(&proxy_url).unwrap(),
        root_certs: None,
    };
    let mut conn = dialer.connect("target.example", 1234).await.unwrap();
    conn.write_all(b"hello").await.unwrap();
    let mut resp = [0u8; 5];
    conn.read_exact(&mut resp).await.unwrap();
    assert_eq!(&resp, b"hello");
    let req = received.await.unwrap();
    assert!(req.starts_with("CONNECT target.example:1234 HTTP/1.1\r\n"));
    assert!(req.contains("Proxy-Connection: Keep-Alive"));
    assert!(!req.contains("Proxy-Authorization"));
}

#[tokio::test]
async fn http_connect_sends_basic_auth() {
    let (proxy_url, received) = start_mock_connect_proxy(200).await;
    let url = Url::parse(&proxy_url.replacen("http://", "http://user:pass@", 1)).unwrap();
    let dialer = HttpConnectDialer {
        url,
        root_certs: None,
    };
    let mut conn = dialer.connect("target.example", 1234).await.unwrap();
    conn.write_all(b"hello").await.unwrap();
    let mut resp = [0u8; 5];
    conn.read_exact(&mut resp).await.unwrap();
    let req = received.await.unwrap();
    // base64("user:pass") == "dXNlcjpwYXNz"
    assert!(req.contains("Proxy-Authorization: Basic dXNlcjpwYXNz"));
}

#[tokio::test]
async fn http_connect_rejects_non_200() {
    let (proxy_url, _received) = start_mock_connect_proxy(407).await;
    let dialer = HttpConnectDialer {
        url: Url::parse(&proxy_url).unwrap(),
        root_certs: None,
    };
    let err = dialer.connect("target.example", 1234).await.unwrap_err();
    match err {
        ProxyError::ConnectFailed { code, body } => {
            assert_eq!(code, 407);
            assert!(body.contains("denied by proxy"));
        }
        other => panic!("expected ConnectFailed, got {other:?}"),
    }
}

#[tokio::test]
async fn https_proxy_uses_tls_to_proxy() {
    // rcgen self-signed cert (SAN=localhost), injected via root_certs
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_pem = cert.cert.pem();
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into()),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (conn, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(conn).await.unwrap();
        // Read the CONNECT request head
        let mut buf = Vec::new();
        loop {
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
            let n = tls.read_buf(&mut buf).await.unwrap();
            if n == 0 {
                panic!("tls conn closed early");
            }
        }
        assert!(buf.starts_with(b"CONNECT target.example:1234"));
        tls.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();
        let mut echo = [0u8; 5];
        tls.read_exact(&mut echo).await.unwrap();
        tls.write_all(&echo).await.unwrap();
    });

    let url = Url::parse(&format!("https://localhost:{}", addr.port())).unwrap();
    let dialer = HttpConnectDialer {
        url,
        root_certs: Some(cert_pem.as_bytes().to_vec()),
    };
    let mut conn = dialer.connect("target.example", 1234).await.unwrap();
    conn.write_all(b"hello").await.unwrap();
    let mut resp = [0u8; 5];
    conn.read_exact(&mut resp).await.unwrap();
    assert_eq!(&resp, b"hello");
}
