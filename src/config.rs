use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, io, net::IpAddr, path::Path};

pub const UPSTREAM_VERSION: &str = "1.10.2";
pub const UPSTREAM_COMMIT: &str = "f200e33fd283143a9f101d62aaf9d8c1468a23fe";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub web_host: String,
    pub web_port: u16,
    pub secret: String,
    pub dc_redirects: BTreeMap<i16, String>,
    pub buffer_size: usize,
    pub pool_size: usize,
    pub max_connections: usize,
    pub connect_timeout_secs: u64,
    pub idle_timeout_secs: u64,
    pub proxy_protocol: bool,
    pub force_test_dc: bool,
    pub sni_fronting: bool,
    pub cfproxy: bool,
    pub cfproxy_user_domains: Vec<String>,
    pub cfproxy_worker_domains: Vec<String>,
    pub domain_refresh: bool,
    pub fake_tls_domain: String,
    pub link_host: String,
    pub web_user: String,
    pub web_password: String,
    pub verbose: bool,
    // Keep legacy and future options on disk when editing a migrated config.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".into(),
            port: 1433,
            web_host: "0.0.0.0".into(),
            web_port: 1434,
            secret: String::new(),
            dc_redirects: [(2, "149.154.167.220".into()), (4, "149.154.167.220".into())].into(),
            buffer_size: 16384,
            pool_size: 0,
            max_connections: 64,
            connect_timeout_secs: 10,
            idle_timeout_secs: 300,
            proxy_protocol: false,
            force_test_dc: false,
            sni_fronting: false,
            cfproxy: true,
            cfproxy_user_domains: vec![],
            cfproxy_worker_domains: vec![],
            domain_refresh: true,
            fake_tls_domain: String::new(),
            link_host: String::new(),
            web_user: "admin".into(),
            web_password: String::new(),
            verbose: false,
            extra: BTreeMap::new(),
        }
    }
}

pub fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

pub fn random_hex() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    hex(&bytes)
}

pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 15) as usize] as char);
    }
    output
}

pub fn valid_domain(domain: &str) -> bool {
    domain.len() <= 253
        && domain.contains('.')
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
}

impl Config {
    pub fn from_value(mut value: serde_json::Value) -> io::Result<Self> {
        let map = value
            .as_object_mut()
            .ok_or_else(|| invalid("config must be a JSON object"))?;
        // Missing list means legacy format; explicit [] deliberately clears it.
        for (old, new) in [
            ("cfproxy_user_domain", "cfproxy_user_domains"),
            ("cfproxy_worker_domain", "cfproxy_worker_domains"),
        ] {
            if !map.contains_key(new) {
                if let Some(old_value) = map.get(old).and_then(|v| v.as_str()) {
                    let domains: Vec<_> = old_value
                        .split(|c: char| c.is_whitespace() || c == ',' || c == ';')
                        .filter(|s| !s.is_empty())
                        .map(str::to_owned)
                        .collect();
                    map.insert(new.into(), serde_json::json!(domains));
                }
            }
            map.remove(old);
        }
        let mut cfg: Self = serde_json::from_value(value).map_err(|e| invalid(e.to_string()))?;
        for domains in [
            &mut cfg.cfproxy_user_domains,
            &mut cfg.cfproxy_worker_domains,
        ] {
            let mut normalized = Vec::new();
            for domain in domains.iter() {
                let domain = domain.trim().to_ascii_lowercase();
                if !domain.is_empty() && !normalized.contains(&domain) {
                    normalized.push(domain);
                }
            }
            *domains = normalized;
        }
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn load(path: &Path) -> io::Result<Self> {
        let data = fs::read(path)?;
        if data.len() > 65536 {
            return Err(invalid("config exceeds 64 KiB"));
        }
        let value = serde_json::from_slice(&data)
            .map_err(|e| invalid(format!("invalid config JSON: {e}")))?;
        Self::from_value(value)
    }

    pub fn validate(&self) -> io::Result<()> {
        self.host
            .parse::<IpAddr>()
            .map_err(|_| invalid("host must be an IP address"))?;
        self.web_host
            .parse::<IpAddr>()
            .map_err(|_| invalid("web_host must be an IP address"))?;
        if self.port == 0 || self.web_port == 0 || self.port == self.web_port {
            return Err(invalid("proxy and web ports must be nonzero and different"));
        }
        self.secret_bytes()?;
        if !(4096..=262144).contains(&self.buffer_size) {
            return Err(invalid("buffer_size must be 4096..262144"));
        }
        if self.pool_size > 4 {
            return Err(invalid(
                "pool_size must be 0..4 per DC on this router build",
            ));
        }
        if !(1..=1024).contains(&self.max_connections) {
            return Err(invalid("max_connections must be 1..1024"));
        }
        if !(1..=60).contains(&self.connect_timeout_secs)
            || !(10..=86400).contains(&self.idle_timeout_secs)
        {
            return Err(invalid(
                "connect_timeout_secs must be 1..60; idle_timeout_secs 10..86400",
            ));
        }
        for (dc, ip) in &self.dc_redirects {
            if ![1, 2, 3, 4, 5, 203].contains(dc) {
                return Err(invalid(format!("unknown DC {dc}")));
            }
            ip.parse::<IpAddr>()
                .map_err(|_| invalid(format!("invalid IP for DC {dc}")))?;
        }
        for domains in [&self.cfproxy_user_domains, &self.cfproxy_worker_domains] {
            if domains.len() > 16 {
                return Err(invalid("at most 16 domains per fallback list"));
            }
            for domain in domains {
                if !valid_domain(domain) {
                    return Err(invalid(format!(
                        "invalid domain {domain}: use a hostname without scheme, port or path"
                    )));
                }
            }
        }
        if !self.fake_tls_domain.is_empty() && !valid_domain(&self.fake_tls_domain) {
            return Err(invalid("invalid fake_tls_domain"));
        }
        if !self.link_host.is_empty()
            && self.link_host.parse::<IpAddr>().is_err()
            && !valid_domain(&self.link_host)
        {
            return Err(invalid("link_host must be an IP address or DNS hostname"));
        }
        if self.web_user.contains(':') || self.web_user.len() > 128 || self.web_password.len() > 256
        {
            return Err(invalid("invalid web credentials"));
        }
        if !self.web_password.is_empty() && self.web_user.is_empty() {
            return Err(invalid("web_user is required with web_password"));
        }
        Ok(())
    }

    pub fn secret_bytes(&self) -> io::Result<[u8; 16]> {
        if self.secret.len() != 32 || !self.secret.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err(invalid(
                "secret must contain exactly 32 hexadecimal characters",
            ));
        }
        let mut bytes = [0u8; 16];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&self.secret[2 * i..2 * i + 2], 16)
                .map_err(|_| invalid("invalid secret"))?;
        }
        Ok(bytes)
    }

    pub fn save(&self, path: &Path) -> io::Result<()> {
        self.validate()?;
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let result = (|| {
            use io::Write;
            let mut file = options.open(&tmp)?;
            serde_json::to_writer_pretty(&mut file, self).map_err(io::Error::other)?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            drop(file);
            fs::rename(&tmp, path)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result
    }

    pub fn link(&self, request_host: &str) -> String {
        let host = if self.link_host.is_empty() {
            request_host
        } else {
            &self.link_host
        };
        let host = if host.is_empty() { "127.0.0.1" } else { host };
        let host = host.replace('%', "%25").replace(':', "%3A");
        let secret = if self.fake_tls_domain.is_empty() {
            format!("dd{}", self.secret)
        } else {
            format!("ee{}{}", self.secret, hex(self.fake_tls_domain.as_bytes()))
        };
        format!(
            "tg://proxy?server={host}&port={}&secret={secret}",
            self.port
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> Config {
        Config {
            secret: "00112233445566778899aabbccddeeff".into(),
            ..Config::default()
        }
    }
    #[test]
    fn legacy_migration_preserves_keys_and_explicit_empty() {
        let mut value = serde_json::to_value(config()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .remove("cfproxy_user_domains");
        value["cfproxy_user_domain"] = "one.example, two.example".into();
        value["log_max_mb"] = 5.into();
        let loaded = Config::from_value(value.clone()).unwrap();
        assert_eq!(loaded.cfproxy_user_domains, ["one.example", "two.example"]);
        assert_eq!(loaded.secret, config().secret);
        assert_eq!(loaded.extra["log_max_mb"], 5);
        value["cfproxy_user_domains"] = serde_json::json!([]);
        assert!(Config::from_value(value)
            .unwrap()
            .cfproxy_user_domains
            .is_empty());
    }
    #[test]
    fn rejects_invalid_secret_limits_and_header_injection() {
        let mut cfg = config();
        cfg.buffer_size = usize::MAX;
        assert!(cfg.validate().is_err());
        cfg = config();
        cfg.fake_tls_domain = "example.org\r\nX: x".into();
        assert!(cfg.validate().is_err());
        cfg = config();
        cfg.secret = "щ".repeat(16);
        assert!(cfg.validate().is_err());
        assert!(!valid_domain("https://example.org/path"));
        assert!(!valid_domain("-bad.example"));
    }
    #[test]
    fn fake_tls_and_ipv6_links() {
        let mut cfg = config();
        cfg.fake_tls_domain = "example.org".into();
        assert!(cfg.link("::1").contains("server=%3A%3A1"));
        assert!(cfg
            .link("::1")
            .ends_with(&format!("ee{}{}", cfg.secret, hex(b"example.org"))));
    }
}
