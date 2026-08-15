/// Strict-mode TLS SNI sniffer: parse the server_name extension from a ClientHello
/// in the accumulated bytes.
/// - Ok(Some(host)): SNI found
/// - Ok(None): not enough data yet (record incomplete), caller should read more
/// - Err: malformed (length fields overflow, etc.), strict mode rejects the connection
pub fn parse_tls_server_name(buf: &[u8]) -> Result<Option<String>, String> {
    let mut pos = 0;
    while pos + 5 <= buf.len() {
        let content_type = buf[pos];
        let record_len = u16::from_be_bytes([buf[pos + 3], buf[pos + 4]]) as usize;
        let record_start = pos + 5;
        if record_start + record_len > buf.len() {
            return Ok(None); // record incomplete, wait for more data
        }
        if content_type == 0x16 {
            // handshake record: split into messages
            let mut hp = record_start;
            let record_end = record_start + record_len;
            while hp + 4 <= record_end {
                let msg_type = buf[hp];
                let msg_len = ((buf[hp + 1] as usize) << 16)
                    | ((buf[hp + 2] as usize) << 8)
                    | buf[hp + 3] as usize;
                let msg_start = hp + 4;
                if msg_start + msg_len > record_end {
                    return Err("malformed handshake: message exceeds record".into());
                }
                if msg_type == 1
                    && let Some(sni) = parse_client_hello_sni(&buf[msg_start..msg_start + msg_len])?
                {
                    return Ok(Some(sni));
                }
                hp = msg_start + msg_len;
            }
        }
        pos = record_start + record_len;
    }
    Ok(None)
}

fn parse_client_hello_sni(ch: &[u8]) -> Result<Option<String>, String> {
    let mut s = ch;
    if s.len() < 34 {
        return Err("malformed client hello: truncated header".into());
    }
    s = &s[34..]; // legacy_version(2) + random(32)

    if s.is_empty() {
        return Err("malformed client hello: missing session id".into());
    }
    let sid_len = s[0] as usize;
    s = &s[1..];
    if s.len() < sid_len {
        return Err("malformed client hello: truncated session id".into());
    }
    s = &s[sid_len..];

    if s.len() < 2 {
        return Err("malformed client hello: missing cipher suites".into());
    }
    let cs_len = u16::from_be_bytes([s[0], s[1]]) as usize;
    s = &s[2..];
    if s.len() < cs_len {
        return Err("malformed client hello: truncated cipher suites".into());
    }
    s = &s[cs_len..];

    if s.is_empty() {
        return Err("malformed client hello: missing compression".into());
    }
    let comp_len = s[0] as usize;
    s = &s[1..];
    if s.len() < comp_len {
        return Err("malformed client hello: truncated compression".into());
    }
    s = &s[comp_len..];

    if s.len() < 2 {
        return Err("malformed client hello: missing extensions".into());
    }
    let ext_total = u16::from_be_bytes([s[0], s[1]]) as usize;
    s = &s[2..];
    if s.len() < ext_total {
        return Err("malformed client hello: truncated extensions".into());
    }
    let mut p = 0;
    while p + 4 <= ext_total {
        let ext_type = u16::from_be_bytes([s[p], s[p + 1]]);
        let ext_len = u16::from_be_bytes([s[p + 2], s[p + 3]]) as usize;
        if p + 4 + ext_len > ext_total {
            return Err("malformed client hello: extension exceeds list".into());
        }
        if ext_type == 0 {
            // RFC 6066 server_name
            let name_data = &s[p + 4..p + 4 + ext_len];
            if name_data.len() < 2 {
                return Err("malformed server_name extension".into());
            }
            let list_len = u16::from_be_bytes([name_data[0], name_data[1]]) as usize;
            let mut np = 2;
            if np + list_len > name_data.len() {
                return Err("malformed server_name list".into());
            }
            while np + 3 <= 2 + list_len {
                let name_type = name_data[np];
                let name_len = u16::from_be_bytes([name_data[np + 1], name_data[np + 2]]) as usize;
                if np + 3 + name_len > 2 + list_len {
                    return Err("malformed server_name entry".into());
                }
                if name_type == 0 {
                    return Ok(Some(
                        String::from_utf8_lossy(&name_data[np + 3..np + 3 + name_len]).into_owned(),
                    ));
                }
                np += 3 + name_len;
            }
        }
        p += 4 + ext_len;
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn client_hello(server_name: &str) -> Vec<u8> {
        // Generate a real ClientHello with a rustls client
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let server_name: rustls::pki_types::ServerName =
            server_name.to_string().try_into().unwrap();
        let mut client = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
        let mut out = Vec::new();
        client.write_tls(&mut out).unwrap();
        out
    }

    #[test]
    fn extracts_sni_from_client_hello() {
        let hello = client_hello("server.name");
        assert_eq!(
            parse_tls_server_name(&hello).unwrap(),
            Some("server.name".to_string())
        );
    }

    #[test]
    fn returns_none_for_incomplete_record() {
        let hello = client_hello("server.name");
        let partial = &hello[..hello.len() - 3];
        assert_eq!(parse_tls_server_name(partial).unwrap(), None);
    }

    #[test]
    fn rejects_malformed_client_hello() {
        // Complete record header + message length larger than the record payload (strict: malformed)
        let hello = client_hello("server.name");
        let mut bad = hello.clone();
        // The message length field sits after the 5-byte record header; make it exceed the record payload
        bad[5] = 0x7f;
        bad[6] = 0xff;
        bad[7] = 0xff;
        assert!(parse_tls_server_name(&bad).is_err());
    }

    #[test]
    fn ignores_non_handshake_records() {
        // Prepend an application_data record, then the ClientHello
        let hello = client_hello("server.name");
        let mut mixed = vec![0x17, 0x03, 0x03, 0x00, 0x00]; // empty app data record
        mixed.extend_from_slice(&hello);
        assert_eq!(
            parse_tls_server_name(&mixed).unwrap(),
            Some("server.name".to_string())
        );
    }
}
