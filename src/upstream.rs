//! Telegram routes, bounded warm sockets, and validated fallback-domain refresh.
use crate::{
    config::Config,
    stats::Stats,
    websocket::{self, WebSocket},
};
use rand::seq::SliceRandom;
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    time::{sleep, timeout},
};
use tokio_native_tls::TlsConnector;

const DC_IDS: [i16; 6] = [1, 2, 3, 4, 5, 203];
const POOL_MAX_AGE: Duration = Duration::from_secs(100);
const DOMAIN_LIMIT: usize = 64 * 1024;
const ENCODED_DOMAINS: &str = "virkgj.com\nvmmzovy.com\nmkuosckvso.com\nzaewayzmplad.com\ntwdmbzcm.com\nawzwsldi.com\nclngqrflngqin.com\ntjacxbqtj.com\nbxaxtxmrw.com\ndmohrsgmohcrwb.com\nvwbmtmoi.com\nkhgrre.com\nulihssf.com\ntmhqsdqmfpmk.com\nxwuwoqbm.com\norgcnunpj.com\nzhkuldz.com\nzypoljnslxa.com\nefabnxaowuzs.com\nzaftuzsftqdq.com";

// This short-lived return value avoids adding a heap allocation to every upgrade.
#[allow(clippy::large_enum_variant)]
pub enum Route {
    WebSocket(WebSocket, bool),
    Tcp(TcpStream),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum PoolKey {
    Direct(i16, bool),
    Worker(i16),
}
struct Idle {
    socket: WebSocket,
    created: Instant,
}
#[derive(Default)]
struct Bucket {
    idle: Vec<Idle>,
    failures: u32,
    retry: Option<Instant>,
}
#[derive(Default)]
struct State {
    domains: Vec<String>,
    preferred: BTreeMap<i16, String>,
    pools: BTreeMap<PoolKey, Bucket>,
    blacklisted: BTreeSet<(i16, bool, bool)>,
    failed_dc: BTreeMap<(i16, bool, bool), Instant>,
    failed_ip: BTreeMap<String, Instant>,
}

pub struct Upstream {
    config: Arc<Config>,
    stats: Arc<Stats>,
    verified: TlsConnector,
    direct: TlsConnector,
    state: Mutex<State>,
}

impl Upstream {
    pub fn new(config: Arc<Config>, stats: Arc<Stats>) -> io::Result<Arc<Self>> {
        let verified = native_tls::TlsConnector::builder()
            .build()
            .map_err(io::Error::other)?;
        // Native Telegram fronts may present a certificate for their original host.
        // MTProto still authenticates/encrypts payloads; never use this connector for CF or GitHub.
        let direct = native_tls::TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .build()
            .map_err(io::Error::other)?;
        let domains = if config.cfproxy_user_domains.is_empty() {
            parse_domain_pool(ENCODED_DOMAINS)
        } else {
            config.cfproxy_user_domains.clone()
        };
        let mut state = State {
            domains,
            ..State::default()
        };
        if config.pool_size > 0 && !config.force_test_dc {
            for dc in config.dc_redirects.keys() {
                for media in [false, true] {
                    state
                        .pools
                        .insert(PoolKey::Direct(*dc, media), Bucket::default());
                }
            }
            if !config.cfproxy_worker_domains.is_empty() {
                for dc in DC_IDS {
                    state.pools.insert(PoolKey::Worker(dc), Bucket::default());
                }
            }
        }
        Ok(Arc::new(Self {
            config,
            stats,
            verified: verified.into(),
            direct: direct.into(),
            state: Mutex::new(state),
        }))
    }
    fn idle(&self) -> Duration {
        Duration::from_secs(self.config.idle_timeout_secs)
    }
    fn connect_limit(&self) -> Duration {
        Duration::from_secs(self.config.connect_timeout_secs)
    }
    async fn ws(
        &self,
        host: &str,
        domain: &str,
        sni: &str,
        path: &str,
        direct: bool,
        limit: Duration,
    ) -> io::Result<WebSocket> {
        WebSocket::connect(
            if direct { &self.direct } else { &self.verified },
            host,
            domain,
            sni,
            path,
            limit,
            self.idle(),
            self.config.buffer_size,
        )
        .await
    }

    pub async fn connect(&self, dc: i16, media: bool, test: bool) -> io::Result<Route> {
        // A client may not occupy its admission slot forever while every fallback is down.
        timeout(
            Duration::from_secs(50) + self.connect_limit(),
            self.connect_inner(dc, media, test),
        )
        .await
        .map_err(websocket::timed_out)?
    }
    async fn connect_inner(&self, dc: i16, media: bool, test: bool) -> io::Result<Route> {
        if let Ok(Some(socket)) =
            timeout(Duration::from_secs(15), self.direct_route(dc, media, test)).await
        {
            self.stats.ws();
            return Ok(Route::WebSocket(socket, true));
        }
        let target = fallback_ip(dc, test).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "unsupported Telegram DC")
        })?;
        if !self.config.cfproxy_worker_domains.is_empty() {
            let pooled = if !test {
                self.take_pool(PoolKey::Worker(dc)).await
            } else {
                None
            };
            if let Some(socket) = pooled {
                self.stats.cf();
                return Ok(Route::WebSocket(socket, false));
            }
            if let Ok(Ok(socket)) = timeout(Duration::from_secs(15), self.worker(dc, target)).await
            {
                self.stats.cf();
                return Ok(Route::WebSocket(socket, false));
            }
        }
        if self.config.cfproxy && !test {
            if let Ok(Some(socket)) = timeout(Duration::from_secs(15), self.cf_route(dc)).await {
                self.stats.cf();
                return Ok(Route::WebSocket(socket, true));
            }
        }
        let remote = timeout(self.connect_limit(), TcpStream::connect((target, 443)))
            .await
            .map_err(websocket::timed_out)??;
        remote.set_nodelay(true)?;
        let socket = socket2::SockRef::from(&remote);
        let _ = socket.set_recv_buffer_size(self.config.buffer_size);
        let _ = socket.set_send_buffer_size(self.config.buffer_size);
        self.stats.tcp();
        Ok(Route::Tcp(remote))
    }
    async fn cf_route(&self, dc: i16) -> Option<WebSocket> {
        for base in self.domains_for(dc) {
            let domain = format!("kws{dc}.{base}");
            match self
                .ws(
                    &domain,
                    &domain,
                    &domain,
                    "/apiws",
                    false,
                    self.connect_limit(),
                )
                .await
            {
                Ok(socket) => {
                    self.state.lock().unwrap().preferred.insert(dc, base);
                    return Some(socket);
                }
                Err(_) => self.stats.ws_error(),
            }
        }
        None
    }

    async fn direct_route(&self, dc: i16, media: bool, test: bool) -> Option<WebSocket> {
        let ip = self.config.dc_redirects.get(&dc)?;
        let key = (dc, media, test);
        if self.state.lock().unwrap().blacklisted.contains(&key) {
            return None;
        }
        if !test {
            if let Some(socket) = self.take_pool(PoolKey::Direct(dc, media)).await {
                self.direct_success(key, ip);
                return Some(socket);
            }
        }
        let has_cf =
            (!test && self.config.cfproxy) || !self.config.cfproxy_worker_domains.is_empty();
        let (ip_cooldown, dc_cooldown) = {
            let state = self.state.lock().unwrap();
            (
                state.failed_ip.get(ip).is_some_and(|t| *t > Instant::now()),
                state
                    .failed_dc
                    .get(&key)
                    .is_some_and(|t| *t > Instant::now()),
            )
        };
        if has_cf && ip_cooldown {
            return None;
        }
        let limit = self
            .connect_limit()
            .min(Duration::from_secs(if dc_cooldown { 2 } else { 5 }));
        let path = if test { "/apiws_test" } else { "/apiws" };
        let mut all_redirects = true;
        for domain in ws_domains(dc, media) {
            match self.ws(ip, &domain, &domain, path, true, limit).await {
                Ok(socket) => {
                    self.direct_success(key, ip);
                    return Some(socket);
                }
                Err(error) => {
                    self.stats.ws_error();
                    if websocket::is_redirect(&error) {
                        continue;
                    }
                    all_redirects = false;
                    if self.config.sni_fronting && should_front(&error) {
                        if let Ok(socket) = self
                            .ws(ip, &domain, "sprinthost.ru", path, true, limit)
                            .await
                        {
                            self.direct_success(key, ip);
                            self.stats.fronting();
                            return Some(socket);
                        }
                    }
                    if error.kind() == io::ErrorKind::TimedOut {
                        self.state
                            .lock()
                            .unwrap()
                            .failed_ip
                            .insert(ip.clone(), Instant::now() + Duration::from_secs(3600));
                        break;
                    }
                }
            }
        }
        let mut state = self.state.lock().unwrap();
        if all_redirects {
            state.blacklisted.insert(key);
        } else {
            state
                .failed_dc
                .insert(key, Instant::now() + Duration::from_secs(60));
        }
        None
    }
    fn direct_success(&self, key: (i16, bool, bool), ip: &str) {
        let mut s = self.state.lock().unwrap();
        s.failed_dc.remove(&key);
        s.failed_ip.remove(ip);
        if let Some(b) = s.pools.get_mut(&PoolKey::Direct(key.0, key.1)) {
            b.failures = 0;
            b.retry = None;
        }
    }
    async fn worker(&self, dc: i16, ip: &str) -> io::Result<WebSocket> {
        let mut domains = self.config.cfproxy_worker_domains.clone();
        domains.shuffle(&mut rand::thread_rng());
        let mut error = io::Error::new(io::ErrorKind::NotConnected, "no workers available");
        for domain in domains {
            match self
                .ws(
                    &domain,
                    &domain,
                    &domain,
                    &worker_path(dc, ip),
                    false,
                    self.connect_limit(),
                )
                .await
            {
                Ok(socket) => return Ok(socket),
                Err(e) => {
                    self.stats.ws_error();
                    error = e;
                }
            }
        }
        Err(error)
    }
    fn domains_for(&self, dc: i16) -> Vec<String> {
        let state = self.state.lock().unwrap();
        let active = state.preferred.get(&dc);
        let mut domains: Vec<_> = state
            .domains
            .iter()
            .filter(|d| Some(*d) != active)
            .cloned()
            .collect();
        domains.shuffle(&mut rand::thread_rng());
        if let Some(active) = active {
            domains.insert(0, active.clone());
        }
        domains
    }
    async fn take_pool(&self, key: PoolKey) -> Option<WebSocket> {
        if self.config.pool_size == 0 {
            return None;
        }
        loop {
            let candidate = self
                .state
                .lock()
                .unwrap()
                .pools
                .get_mut(&key)
                .and_then(|b| b.idle.pop());
            let Some(mut item) = candidate else {
                self.stats.pool_miss();
                return None;
            };
            if item.created.elapsed() < POOL_MAX_AGE && item.socket.idle_healthy().await {
                self.stats.pool_hit();
                return Some(item.socket);
            }
        }
    }

    /// One background dial at a time intentionally limits TLS handshake RAM on routers.
    /// Own this future under the proxy's JoinSet so restart cancels in-flight dials too.
    pub async fn maintain(&self) {
        if self.config.pool_size == 0 || self.config.force_test_dc {
            return;
        }
        loop {
            let keys: Vec<_> = self.state.lock().unwrap().pools.keys().copied().collect();
            for key in keys {
                let needed = {
                    let mut state = self.state.lock().unwrap();
                    let bucket = state.pools.get_mut(&key).unwrap();
                    bucket.idle.retain(|s| s.created.elapsed() < POOL_MAX_AGE);
                    let cap = match key {
                        PoolKey::Direct(..) => self.config.pool_size,
                        PoolKey::Worker(..) => 1,
                    };
                    bucket.idle.len() < cap && bucket.retry.is_none_or(|t| t <= Instant::now())
                };
                if !needed {
                    continue;
                }
                let result = match key {
                    PoolKey::Direct(dc, media) => self.pool_direct(dc, media).await,
                    PoolKey::Worker(dc) => self.worker(dc, fallback_ip(dc, false).unwrap()).await,
                };
                let mut state = self.state.lock().unwrap();
                let bucket = state.pools.get_mut(&key).unwrap();
                match result {
                    Ok(socket) => {
                        bucket.idle.push(Idle {
                            socket,
                            created: Instant::now(),
                        });
                        bucket.failures = 0;
                        bucket.retry = None;
                    }
                    Err(_) => {
                        bucket.failures = bucket.failures.saturating_add(1);
                        bucket.retry = Some(Instant::now() + refill_backoff(bucket.failures));
                    }
                }
            }
            sleep(Duration::from_secs(5)).await;
        }
    }
    async fn pool_direct(&self, dc: i16, media: bool) -> io::Result<WebSocket> {
        let ip = &self.config.dc_redirects[&dc];
        let mut last = io::Error::new(io::ErrorKind::NotConnected, "no direct WebSocket route");
        for domain in ws_domains(dc, media) {
            match self
                .ws(ip, &domain, &domain, "/apiws", true, self.connect_limit())
                .await
            {
                Ok(socket) => return Ok(socket),
                Err(error) => {
                    if websocket::is_redirect(&error) {
                        last = error;
                        continue;
                    }
                    if self.config.sni_fronting && should_front(&error) {
                        let result = self
                            .ws(
                                ip,
                                &domain,
                                "sprinthost.ru",
                                "/apiws",
                                true,
                                self.connect_limit(),
                            )
                            .await;
                        if result.is_ok() {
                            self.stats.fronting();
                        }
                        return result;
                    }
                    return Err(error);
                }
            }
        }
        Err(last)
    }

    pub async fn refresh_domains(&self) {
        if !self.config.domain_refresh
            || !self.config.cfproxy
            || !self.config.cfproxy_user_domains.is_empty()
        {
            return;
        }
        loop {
            let mut fetched = self.fetch_domains("185.199.109.133").await;
            if fetched.is_err() {
                fetched = self.fetch_domains("raw.githubusercontent.com").await;
            }
            match fetched {
                Ok(domains) => {
                    let mut s = self.state.lock().unwrap();
                    let old: BTreeSet<_> = s.domains.iter().collect();
                    let new: BTreeSet<_> = domains.iter().collect();
                    if old != new {
                        s.domains = domains;
                        s.preferred.clear();
                    }
                }
                Err(_) => {
                    if self.config.verbose {
                        eprintln!("tgws: domain refresh failed; keeping current fallback pool");
                    }
                }
            }
            sleep(Duration::from_secs(3600)).await;
        }
    }
    async fn fetch_domains(&self, host: &str) -> io::Result<Vec<String>> {
        timeout(self.connect_limit(),async {
            let tcp=TcpStream::connect((host,443)).await?;
            let tls=self.verified.connect("raw.githubusercontent.com",tcp).await.map_err(io::Error::other)?;
            let mut wire=BufReader::with_capacity(4096,tls);
            wire.write_all(b"GET /Flowseal/tg-ws-proxy/main/.github/cfproxy-domains.txt HTTP/1.1\r\nHost: raw.githubusercontent.com\r\nUser-Agent: tgws-rust/1.10.2\r\nAccept-Encoding: identity\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n").await?;
            wire.flush().await?;
            let (status,headers)=websocket::read_http_headers(&mut wire).await?;
            if status!=200 { return Err(io::Error::other(websocket::HttpError(status))); }
            if headers.get("content-encoding").is_some_and(|v| v!="identity") { return Err(invalid("encoded domain response unsupported")); }
            let body=read_body(&mut wire,&headers).await?;
            let text=std::str::from_utf8(&body).map_err(|_|invalid("invalid domain response encoding"))?;
            let domains=parse_domain_pool(text);
            if domains.len()<3 { return Err(invalid("fewer than three valid distinct domains")); }
            Ok(domains)
        }).await.map_err(websocket::timed_out)?
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn should_front(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::ConnectionReset
    )
}
pub fn refill_backoff(failures: u32) -> Duration {
    Duration::from_secs((1u64 << failures.saturating_sub(1).min(12)).min(3600))
}
pub fn fallback_ip(dc: i16, test: bool) -> Option<&'static str> {
    if test {
        return match dc {
            1 => Some("149.154.175.10"),
            2 => Some("149.154.167.40"),
            3 => Some("149.154.175.117"),
            _ => None,
        };
    }
    match dc {
        1 => Some("149.154.175.50"),
        2 => Some("149.154.167.51"),
        3 => Some("149.154.175.100"),
        4 => Some("149.154.167.91"),
        5 => Some("149.154.171.5"),
        203 => Some("91.105.192.100"),
        _ => None,
    }
}
pub fn ws_domains(dc: i16, media: bool) -> [String; 2] {
    let dc = if dc == 203 { 2 } else { dc };
    let regular = format!("kws{dc}.web.telegram.org");
    let media_domain = format!("kws{dc}-1.web.telegram.org");
    if media {
        [media_domain, regular]
    } else {
        [regular, media_domain]
    }
}
fn worker_path(dc: i16, ip: &str) -> String {
    format!("/apiws?dc={dc}&dst={ip}")
}
pub fn valid_domain(domain: &str) -> bool {
    if domain.len() > 253 || !domain.contains('.') {
        return false;
    }
    let labels: Vec<_> = domain.split('.').collect();
    if labels.iter().any(|s| {
        s.is_empty()
            || s.len() > 63
            || s.starts_with('-')
            || s.ends_with('-')
            || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    }) {
        return false;
    }
    let last = labels.last().unwrap();
    last.len() >= 2 && last.bytes().any(|b| b.is_ascii_alphabetic())
}
fn decode_domain(line: &str) -> String {
    let Some(body) = line.strip_suffix(".com") else {
        return line.to_owned();
    };
    let shift = body.bytes().filter(u8::is_ascii_alphabetic).count() % 26;
    let mut out: String = body
        .bytes()
        .map(|b| {
            if b.is_ascii_alphabetic() {
                let base = if b.is_ascii_lowercase() { b'a' } else { b'A' };
                (base + ((b - base) as usize + 26 - shift) as u8 % 26) as char
            } else {
                b as char
            }
        })
        .collect();
    out.push_str(".co.uk");
    out
}
pub fn parse_domain_pool(text: &str) -> Vec<String> {
    let mut seen = BTreeSet::new();
    text.lines()
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.starts_with('#'))
        .map(|s| decode_domain(&s.to_ascii_lowercase()))
        .filter(|s| valid_domain(s) && seen.insert(s.clone()))
        .take(128)
        .collect()
}

async fn read_body<R: tokio::io::AsyncRead + Unpin>(
    r: &mut R,
    headers: &BTreeMap<String, String>,
) -> io::Result<Vec<u8>> {
    if let Some(transfer) = headers.get("transfer-encoding") {
        if !transfer.eq_ignore_ascii_case("chunked") {
            return Err(invalid("unsupported transfer encoding"));
        }
        let mut body = Vec::new();
        loop {
            let mut line = Vec::new();
            loop {
                if line.len() >= 128 {
                    return Err(invalid("oversized chunk header"));
                }
                let b = r.read_u8().await?;
                line.push(b);
                if line.ends_with(b"\r\n") {
                    break;
                }
            }
            let text = std::str::from_utf8(&line).map_err(|_| invalid("invalid chunk header"))?;
            let length = usize::from_str_radix(text.trim().split(';').next().unwrap(), 16)
                .map_err(|_| invalid("invalid chunk length"))?;
            if length == 0 {
                return Ok(body);
            }
            if length > DOMAIN_LIMIT - body.len() {
                return Err(invalid("domain response too large"));
            }
            let offset = body.len();
            body.resize(offset + length, 0);
            r.read_exact(&mut body[offset..]).await?;
            if r.read_u16().await? != 0x0d0a {
                return Err(invalid("invalid chunk terminator"));
            }
        }
    }
    if let Some(length) = headers.get("content-length") {
        let length = length
            .parse::<usize>()
            .map_err(|_| invalid("invalid content length"))?;
        if length > DOMAIN_LIMIT {
            return Err(invalid("domain response too large"));
        }
        let mut body = vec![0; length];
        r.read_exact(&mut body).await?;
        return Ok(body);
    }
    let mut body = Vec::new();
    r.take((DOMAIN_LIMIT + 1) as u64)
        .read_to_end(&mut body)
        .await?;
    if body.len() > DOMAIN_LIMIT {
        return Err(invalid("domain response too large"));
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn routing_isolates_test_environment() {
        assert_eq!(fallback_ip(2, true), Some("149.154.167.40"));
        assert_eq!(fallback_ip(4, true), None);
        assert_eq!(
            ws_domains(203, true),
            ["kws2-1.web.telegram.org", "kws2.web.telegram.org"]
        );
        assert_eq!(
            worker_path(2, "149.154.167.40"),
            "/apiws?dc=2&dst=149.154.167.40"
        );
    }
    #[test]
    fn domain_refresh_filters_bad_data_and_deduplicates() {
        assert_eq!(parse_domain_pool(ENCODED_DOMAINS).len(), 20);
        assert_eq!(decode_domain("virkgj.com"), "pclead.co.uk");
        assert_eq!(parse_domain_pool("#ignore\nhello.example\nHELLO.EXAMPLE\n<html>\nhttps://evil.example\n-a.example\n127.0.0.1\n"),["hello.example"]);
    }
    #[test]
    fn exponential_backoff_is_bounded() {
        for (n, want) in [
            (0, 1),
            (1, 1),
            (2, 2),
            (12, 2048),
            (13, 3600),
            (u32::MAX, 3600),
        ] {
            assert_eq!(refill_backoff(n).as_secs(), want);
        }
    }
    #[tokio::test]
    async fn bounded_http_body_handles_chunks_and_truncation() {
        let chunked = BTreeMap::from([("transfer-encoding".into(), "chunked".into())]);
        assert_eq!(
            read_body(
                &mut &b"3\r\nabc\r\n2;ext=x\r\nde\r\n0\r\n\r\n"[..],
                &chunked
            )
            .await
            .unwrap(),
            b"abcde"
        );
        assert!(read_body(&mut &b"10001\r\n"[..], &chunked).await.is_err());
        let length = BTreeMap::from([("content-length".into(), "4".into())]);
        assert!(read_body(&mut &b"abc"[..], &length).await.is_err());
    }
}
