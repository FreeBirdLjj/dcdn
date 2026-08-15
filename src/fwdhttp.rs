/// Strict-mode HTTP Host sniffer: parse the request head from accumulated bytes and extract Host.
/// - Ok(Some(host)): request head complete and has Host
/// - Ok(None): head incomplete (httparse Partial), caller should read more
/// - Err: malformed request / missing Host (strict mode: reject the connection)
pub fn parse_http_host(buf: &[u8]) -> Result<Option<String>, String> {
    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(buf) {
        Ok(httparse::Status::Complete(_n)) => {
            let host = req
                .headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case("host"))
                .ok_or_else(|| "missing Host header".to_string())?;
            Ok(Some(String::from_utf8_lossy(host.value).into_owned()))
        }
        Ok(httparse::Status::Partial) => Ok(None),
        Err(e) => Err(format!("malformed http request: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_host_from_request_head() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: t\r\n\r\n";
        assert_eq!(
            parse_http_host(req).unwrap(),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn returns_none_for_partial_head() {
        let req = b"GET / HTTP/1.1\r\nHost: exa";
        assert_eq!(parse_http_host(req).unwrap(), None);
    }

    #[test]
    fn rejects_missing_host() {
        let req = b"GET / HTTP/1.0\r\n\r\n";
        assert!(parse_http_host(req).is_err());
    }

    #[test]
    fn rejects_malformed_request_line() {
        let req = b"NOT A REQUEST LINE\r\n\r\n";
        assert!(parse_http_host(req).is_err());
    }
}
