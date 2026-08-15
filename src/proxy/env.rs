use url::Url;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Upstream {
    Direct,
    Socks5 {
        addr: String,
        user: Option<String>,
        pass: Option<String>,
    },
    HttpConnect {
        url: Url,
    },
}

/// Proxy environment: resolves all_proxy + no_proxy once at startup
#[derive(Debug, Clone)]
pub struct ProxyEnv {
    pub upstream: Upstream,
    pub no_proxy: String,
}

/// Environment resolution rules:
/// - Variable precedence: ALL_PROXY before all_proxy; NO_PROXY before no_proxy
/// - Empty / URL parse failure / unknown scheme => Direct (socks4/socks4a/socks unregistered => Direct)
/// - socks5/socks5h without a port => default 1080
/// - Note: env vars are read once per process; main calls this exactly once
pub fn from_environment() -> ProxyEnv {
    let all_proxy = std::env::var("ALL_PROXY")
        .or_else(|_| std::env::var("all_proxy"))
        .unwrap_or_default();
    let upstream = if all_proxy.is_empty() {
        Upstream::Direct
    } else {
        match Url::parse(&all_proxy) {
            Ok(url) => match url.scheme() {
                "socks5" | "socks5h" => {
                    let host = url.host_str().unwrap_or_default();
                    let port = url.port().unwrap_or(1080);
                    Upstream::Socks5 {
                        addr: format!("{host}:{port}"),
                        user: (!url.username().is_empty()).then(|| url.username().to_string()),
                        pass: url.password().map(String::from),
                    }
                }
                "http" | "https" => Upstream::HttpConnect { url },
                _ => Upstream::Direct,
            },
            Err(_) => Upstream::Direct,
        }
    };
    let no_proxy = std::env::var("NO_PROXY")
        .or_else(|_| std::env::var("no_proxy"))
        .unwrap_or_default();
    ProxyEnv { upstream, no_proxy }
}

/// no_proxy matching rules:
/// - Domain entries: exact match (trailing "." stripped); subdomains need `*.example.com` form
/// - `*.zone`: matches the zone itself and its subdomains
/// - IP: exact; CIDR: only matches when host is a literal IP
/// - Port entries unsupported: "host:port" is stored verbatim as a domain, never matches
pub fn no_proxy_matches(host: &str, no_proxy: &str) -> bool {
    for entry in no_proxy.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        // CIDR (ignore the entry if it fails to parse, like ParseCIDR)
        if entry.contains('/') {
            if let Some((net, prefix)) = parse_cidr(entry)
                && let Ok(ip) = host.parse::<std::net::IpAddr>()
                && cidr_contains(net, prefix, ip)
            {
                return true;
            }
            continue;
        }
        // IP (compare as IPs so "::1" and "0:0:0:0:0:0:0:1" match)
        if let Ok(entry_ip) = entry.parse::<std::net::IpAddr>()
            && let Ok(host_ip) = host.parse::<std::net::IpAddr>()
        {
            if entry_ip == host_ip {
                return true;
            }
            continue;
        }
        // `*.zone`: matches the zone itself + subdomains
        if let Some(zone) = entry.strip_prefix("*.") {
            let zone = zone.trim_end_matches('.');
            if host == zone || host.ends_with(&format!(".{zone}")) {
                return true;
            }
            continue;
        }
        // Domain: exact match (entry with trailing "." stripped == host)
        if host == entry.trim_end_matches('.') {
            return true;
        }
    }
    false
}

fn parse_cidr(s: &str) -> Option<(std::net::IpAddr, u8)> {
    let (ip, prefix) = s.split_once('/')?;
    let ip: std::net::IpAddr = ip.parse().ok()?;
    let prefix: u8 = prefix.parse().ok()?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    if prefix > max {
        return None;
    }
    Some((ip, prefix))
}

fn cidr_contains(net: std::net::IpAddr, prefix: u8, ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match (net, ip) {
        (IpAddr::V4(n), IpAddr::V4(i)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix as u32)
            };
            (u32::from(n) & mask) == (u32::from(i) & mask)
        }
        (IpAddr::V6(n), IpAddr::V6(i)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix as u32)
            };
            (u128::from(n) & mask) == (u128::from(i) & mask)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // set_var/remove_var are unsafe fns under edition 2024; wrap them so tests need no unsafe
    fn set_env(k: &str, v: &str) {
        unsafe { std::env::set_var(k, v) }
    }
    fn rm_env(k: &str) {
        unsafe { std::env::remove_var(k) }
    }

    // Env-var tests live in a single fn to avoid parallel test interference
    #[test]
    fn from_environment_branches() {
        let saved_all = std::env::var("all_proxy").ok();
        let saved_upper = std::env::var("ALL_PROXY").ok();
        let saved_no = std::env::var("no_proxy").ok();
        let saved_no_upper = std::env::var("NO_PROXY").ok();
        rm_env("all_proxy");
        rm_env("ALL_PROXY");
        rm_env("no_proxy");
        rm_env("NO_PROXY");

        // No variables => Direct
        assert_eq!(from_environment().upstream, Upstream::Direct);

        // Uppercase variable takes effect
        set_env("ALL_PROXY", "socks5://1.2.3.4:1080");
        assert_eq!(
            from_environment().upstream,
            Upstream::Socks5 {
                addr: "1.2.3.4:1080".into(),
                user: None,
                pass: None
            }
        );

        // Uppercase wins over lowercase
        set_env("all_proxy", "http://u:p@proxy.example:3128");
        set_env("ALL_PROXY", "socks5://5.6.7.8:1081");
        assert_eq!(
            from_environment().upstream,
            Upstream::Socks5 {
                addr: "5.6.7.8:1081".into(),
                user: None,
                pass: None
            }
        );
        rm_env("ALL_PROXY");
        // Lowercase alone takes effect
        assert_eq!(
            from_environment().upstream,
            Upstream::HttpConnect {
                url: Url::parse("http://u:p@proxy.example:3128").unwrap()
            }
        );

        // Parse failure => Direct
        set_env("all_proxy", "://bad url");
        assert_eq!(from_environment().upstream, Upstream::Direct);

        // Unknown scheme => Direct (socks4/socks4a/socks unregistered, also Direct)
        set_env("all_proxy", "ftp://proxy.example:21");
        assert_eq!(from_environment().upstream, Upstream::Direct);
        set_env("all_proxy", "socks4://proxy.example:1080");
        assert_eq!(from_environment().upstream, Upstream::Direct);

        // socks5 without port => default 1080
        set_env("all_proxy", "socks5://proxy.example");
        assert_eq!(
            from_environment().upstream,
            Upstream::Socks5 {
                addr: "proxy.example:1080".into(),
                user: None,
                pass: None
            }
        );

        // no_proxy also prefers the uppercase variable
        set_env("all_proxy", "socks5://proxy.example:1080");
        set_env("no_proxy", "a.com");
        set_env("NO_PROXY", "b.com");
        let env = from_environment();
        assert!(no_proxy_matches("b.com", &env.no_proxy));
        assert!(!no_proxy_matches("a.com", &env.no_proxy));

        // Restore
        match saved_all {
            Some(v) => set_env("all_proxy", &v),
            None => rm_env("all_proxy"),
        }
        match saved_upper {
            Some(v) => set_env("ALL_PROXY", &v),
            None => rm_env("ALL_PROXY"),
        }
        match saved_no {
            Some(v) => set_env("no_proxy", &v),
            None => rm_env("no_proxy"),
        }
        match saved_no_upper {
            Some(v) => set_env("NO_PROXY", &v),
            None => rm_env("NO_PROXY"),
        }
    }

    #[test]
    fn no_proxy_matches_exact_domain_zone_ip_cidr() {
        // Domain: exact match
        assert!(no_proxy_matches("example.com", "example.com"));
        assert!(!no_proxy_matches("api.example.com", "example.com"));
        assert!(no_proxy_matches("example.com", "example.com.")); // trailing dot stripped from entry
        // zone (*.example.com): matches itself + subdomains
        assert!(no_proxy_matches("api.example.com", "*.example.com"));
        assert!(no_proxy_matches("example.com", "*.example.com"));
        assert!(!no_proxy_matches("notexample.com", "*.example.com"));
        // IP / CIDR
        assert!(no_proxy_matches("10.1.2.3", "10.1.2.3"));
        assert!(no_proxy_matches("10.1.2.99", "10.1.2.0/24"));
        assert!(!no_proxy_matches("10.2.2.99", "10.1.2.0/24"));
        assert!(!no_proxy_matches("api.example.com", "10.1.2.0/24")); // domain never matches a CIDR
        // Comma-separated, empty entries and whitespace are skipped
        assert!(no_proxy_matches("api.a.com", " example.com , , *.a.com"));
        assert!(!no_proxy_matches("b.example.com", "a.com"));
        // Port entries unsupported: "host:port" is stored verbatim as a domain, never matches
        assert!(!no_proxy_matches("example.com", "example.com:8080"));
    }
}
