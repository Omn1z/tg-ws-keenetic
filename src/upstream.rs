//! Telegram routes, bounded warm sockets, and validated fallback-domain refresh.
use crate::{
    cf_h2::{CfH2Pool, H2Channel},
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
    sync::Notify,
    time::{sleep, timeout},
};
use tokio_native_tls::TlsConnector;

const DC_IDS: [i16; 6] = [1, 2, 3, 4, 5, 203];
const DIRECT_POOL_MAX_AGE: Duration = Duration::from_secs(120);
const WORKER_POOL_MAX_AGE: Duration = Duration::from_secs(100);
const DOMAIN_LIMIT: usize = 64 * 1024;
const ENCODED_DOMAINS: &str = "virkgj.com\nvmmzovy.com\nmkuosckvso.com\nzaewayzmplad.com\ntwdmbzcm.com\nawzwsldi.com\nclngqrflngqin.com\ntjacxbqtj.com\nbxaxtxmrw.com\ndmohrsgmohcrwb.com\nvwbmtmoi.com\nkhgrre.com\nulihssf.com\ntmhqsdqmfpmk.com\nxwuwoqbm.com\norgcnunpj.com\nzhkuldz.com\nzypoljnslxa.com\nefabnxaowuzs.com\nzaftuzsftqdq.com";

// This short-lived return value avoids adding a heap allocation to every upgrade.
#[allow(clippy::large_enum_variant)]
pub enum Route {
    H2(H2Channel),
    WebSocket(WebSocket, bool),
    Tcp(TcpStream),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum PoolKey {
    Direct(i16, bool, bool),
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
    refill_requested: bool,
}
#[derive(Default)]
struct State {
    domains: Vec<String>,
    preferred: BTreeMap<i16, String>,
    pools: BTreeMap<PoolKey, Bucket>,
    blacklisted: BTreeSet<(i16, bool, bool)>,
    failed_dc: BTreeMap<(i16, bool, bool), Instant>,
    failed_ip: BTreeMap<String, Instant>,
    tcp_failures: BTreeMap<(String, u16), u32>,
    tcp_retry_after: BTreeMap<(String, u16), Instant>,
    tcp_connecting: BTreeSet<(String, u16)>,
    h2_retry_after: BTreeMap<i16, Instant>,
}

/// Releases the per-destination TCP dial slot if its future is cancelled.
struct TcpAttempt<'a> {
    state: &'a Mutex<State>,
    key: (String, u16),
}

impl<'a> TcpAttempt<'a> {
    fn begin(state: &'a Mutex<State>, key: (String, u16), now: Instant) -> Option<Self> {
        let mut shared = state.lock().unwrap();
        if shared.tcp_connecting.contains(&key)
            || shared
                .tcp_retry_after
                .get(&key)
                .is_some_and(|retry| *retry > now)
        {
            return None;
        }
        shared.tcp_connecting.insert(key.clone());
        drop(shared);
        Some(Self { state, key })
    }

    fn success(&self) {
        let mut state = self.state.lock().unwrap();
        state.tcp_failures.remove(&self.key);
        state.tcp_retry_after.remove(&self.key);
    }

    fn failure(&self, now: Instant) -> Duration {
        let mut state = self.state.lock().unwrap();
        let failures = state.tcp_failures.entry(self.key.clone()).or_default();
        *failures = failures.saturating_add(1);
        let delay = tcp_fallback_backoff(*failures);
        state.tcp_retry_after.insert(self.key.clone(), now + delay);
        delay
    }
}

impl Drop for TcpAttempt<'_> {
    fn drop(&mut self) {
        self.state.lock().unwrap().tcp_connecting.remove(&self.key);
    }
}

pub struct Upstream {
    config: Arc<Config>,
    stats: Arc<Stats>,
    verified: TlsConnector,
    direct: TlsConnector,
    h2: Option<Arc<CfH2Pool>>,
    pool_wakeup: Notify,
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
        let h2 = if config.h2_enabled() {
            let mut builder = native_tls::TlsConnector::builder();
            builder.request_alpns(&["h2"]);
            let connector = builder.build().map_err(io::Error::other)?;
            Some(CfH2Pool::new(
                connector.into(),
                Duration::from_secs(config.connect_timeout_secs),
                config.buffer_size,
                stats.clone(),
            ))
        } else {
            None
        };
        let domains = if config.cfproxy_user_domains.is_empty() {
            parse_domain_pool(ENCODED_DOMAINS)
        } else {
            config.cfproxy_user_domains.clone()
        };
        let mut state = State {
            domains,
            ..State::default()
        };
        if config.pool_size > 0 {
            for dc in config.dc_redirects.keys() {
                for media in [false, true] {
                    state.pools.insert(
                        PoolKey::Direct(*dc, media, config.force_test_dc),
                        Bucket::default(),
                    );
                }
            }
            // Test DC sessions deliberately bypass the Worker pool, so do not
            // keep six unused production Worker sockets warm in forced-test mode.
            if !config.force_test_dc && !config.cfproxy_worker_domains.is_empty() {
                for dc in DC_IDS {
                    // Match upstream warmup: a Worker socket is useful only for
                    // DCs without a configured direct target.  Other DCs still
                    // open a Worker on demand after a direct-pool miss.
                    if !config.dc_redirects.contains_key(&dc) {
                        state.pools.insert(PoolKey::Worker(dc), Bucket::default());
                    }
                }
            }
        }
        Ok(Arc::new(Self {
            config,
            stats,
            verified: verified.into(),
            direct: direct.into(),
            h2,
            pool_wakeup: Notify::new(),
            state: Mutex::new(state),
        }))
    }
    fn idle(&self) -> Duration {
        Duration::from_secs(self.config.idle_timeout_secs)
    }
    fn connect_limit(&self) -> Duration {
        Duration::from_secs(self.config.connect_timeout_secs)
    }

    pub async fn close(&self) {
        if let Some(h2) = &self.h2 {
            h2.close().await;
        }
    }
    #[allow(clippy::too_many_arguments)]
    async fn ws(
        &self,
        host: &str,
        domain: &str,
        sni: &str,
        path: &str,
        direct: bool,
        secure: bool,
        limit: Duration,
    ) -> io::Result<WebSocket> {
        WebSocket::connect(
            if direct { &self.direct } else { &self.verified },
            host,
            domain,
            sni,
            path,
            secure,
            limit,
            self.idle(),
            self.config.buffer_size,
        )
        .await
    }

    pub async fn connect(
        &self,
        dc: i16,
        media: bool,
        test: bool,
        relay_init: &[u8],
    ) -> io::Result<Route> {
        // A client may not occupy its admission slot forever while every fallback is down.
        timeout(
            // Direct, Worker, H2 and CF WebSocket each have their own bounded
            // setup phase.  Leave the final TCP fallback its complete timeout.
            Duration::from_secs(60) + self.connect_limit(),
            self.connect_inner(dc, media, test, relay_init),
        )
        .await
        .map_err(websocket::timed_out)?
    }
    async fn connect_inner(
        &self,
        dc: i16,
        media: bool,
        test: bool,
        relay_init: &[u8],
    ) -> io::Result<Route> {
        if let Ok(Some(socket)) =
            timeout(Duration::from_secs(15), self.direct_route(dc, media, test)).await
        {
            self.stats.ws();
            return Ok(Route::WebSocket(socket, true));
        }
        if self.config.verbose {
            eprintln!("tgws: dc={dc} direct WebSocket unavailable; trying fallbacks");
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
            match timeout(Duration::from_secs(15), self.worker(dc, target)).await {
                Ok(Ok(socket)) => {
                    self.stats.cf();
                    return Ok(Route::WebSocket(socket, false));
                }
                Ok(Err(error)) if self.config.verbose => {
                    eprintln!("tgws: dc={dc} Worker fallback failed: {error}");
                }
                Err(_) if self.config.verbose => {
                    eprintln!("tgws: dc={dc} Worker fallback timed out");
                }
                _ => {}
            }
        }
        if self.config.cfproxy && !test {
            if media && self.h2.is_some() {
                match timeout(Duration::from_secs(8), self.h2_route(dc)).await {
                    Ok(Some(channel)) => {
                        self.stats.cf();
                        self.stats.h2();
                        return Ok(Route::H2(channel));
                    }
                    Ok(None) => {
                        if self.config.verbose {
                            eprintln!("tgws: dc={dc} media H2 unavailable; trying CF WebSocket");
                        }
                    }
                    Err(_) => {
                        self.stats.h2_error();
                        self.h2_cool_down(dc);
                        if self.config.verbose {
                            eprintln!(
                                "tgws: dc={dc} media H2 setup timed out; trying CF WebSocket"
                            );
                        }
                    }
                }
            }
            match timeout(Duration::from_secs(15), self.cf_route(dc)).await {
                Ok(Some(socket)) => {
                    self.stats.cf();
                    return Ok(Route::WebSocket(socket, true));
                }
                Ok(None) if self.config.verbose => {
                    eprintln!("tgws: dc={dc} CF fallback exhausted");
                }
                Err(_) if self.config.verbose => {
                    eprintln!("tgws: dc={dc} CF fallback timed out");
                }
                _ => {}
            }
        }
        let remote = self.tcp_fallback(target, 443, relay_init).await?;
        self.stats.tcp();
        Ok(Route::Tcp(remote))
    }

    fn h2_cool_down(&self, dc: i16) {
        self.state
            .lock()
            .unwrap()
            .h2_retry_after
            .insert(dc, Instant::now() + Duration::from_secs(30));
    }

    async fn h2_route(&self, dc: i16) -> Option<H2Channel> {
        let pool = self.h2.as_ref()?;
        {
            let mut state = self.state.lock().unwrap();
            if state
                .h2_retry_after
                .get(&dc)
                .is_some_and(|until| *until > Instant::now())
            {
                return None;
            }
            state.h2_retry_after.remove(&dc);
        }
        for base in self.domains_for(dc) {
            let host = format!("kws{dc}.{base}");
            match pool.open(&host).await {
                Ok(Some(channel)) => {
                    self.state.lock().unwrap().preferred.insert(dc, base);
                    return Some(channel);
                }
                Ok(None) => {}
                Err(error) => {
                    if self.config.verbose {
                        eprintln!("tgws: dc={dc} H2 domain={host} failed: {error}");
                    }
                }
            }
        }
        self.h2_cool_down(dc);
        None
    }

    async fn tcp_fallback(
        &self,
        target: &str,
        port: u16,
        relay_init: &[u8],
    ) -> io::Result<TcpStream> {
        let key = (target.to_owned(), port);
        let Some(attempt) = TcpAttempt::begin(&self.state, key, Instant::now()) else {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "TCP fallback is connecting or backing off",
            ));
        };
        let result = timeout(self.connect_limit(), async {
            let mut remote = TcpStream::connect((target, port)).await?;
            remote.set_nodelay(true)?;
            let socket = socket2::SockRef::from(&remote);
            let _ = socket.set_recv_buffer_size(self.config.buffer_size);
            let _ = socket.set_send_buffer_size(self.config.buffer_size);
            // Treat delivery of the MTProto relay header as part of setup. A peer
            // that accepts TCP and immediately resets must enter the same backoff.
            remote.write_all(relay_init).await?;
            Ok(remote)
        })
        .await
        .map_err(websocket::timed_out)
        .and_then(|result| result);
        match result {
            Ok(remote) => {
                attempt.success();
                Ok(remote)
            }
            Err(error) => {
                let delay = attempt.failure(Instant::now());
                if self.config.verbose {
                    eprintln!(
                        "tgws: TCP fallback {target}:{port} failed: {error}; retry in {}s",
                        delay.as_secs()
                    );
                }
                Err(error)
            }
        }
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
                    !self.config.disable_secure,
                    self.connect_limit(),
                )
                .await
            {
                Ok(socket) => {
                    self.state.lock().unwrap().preferred.insert(dc, base);
                    return Some(socket);
                }
                Err(error) => {
                    self.stats.ws_error();
                    if self.config.verbose {
                        eprintln!("tgws: dc={dc} CF domain={domain} failed: {error}");
                    }
                }
            }
        }
        None
    }

    async fn direct_route(&self, dc: i16, media: bool, test: bool) -> Option<WebSocket> {
        let ip = self.config.dc_redirects.get(&dc)?;
        let key = (dc, media, test);
        if self.config.pool_size > 0 {
            let pool_key = PoolKey::Direct(dc, media, test);
            self.state
                .lock()
                .unwrap()
                .pools
                .entry(pool_key)
                .or_default();
            if let Some(socket) = self.take_pool(pool_key).await {
                self.direct_success(key, ip);
                return Some(socket);
            }
            // Upstream v1.11 uses prepared direct sockets only. Keeping the old
            // on-demand path when pooling is disabled preserves low-RAM router
            // configs whose pool_size has historically defaulted to zero.
            return None;
        }
        if self.state.lock().unwrap().blacklisted.contains(&key) {
            return None;
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
        let path = ws_path(test);
        let mut all_redirects = true;
        for domain in ws_domains(dc, media) {
            match self.ws(ip, &domain, &domain, path, true, true, limit).await {
                Ok(socket) => {
                    self.direct_success(key, ip);
                    return Some(socket);
                }
                Err(error) => {
                    self.stats.ws_error();
                    if self.config.verbose {
                        eprintln!("tgws: dc={dc} direct domain={domain} failed: {error}");
                    }
                    if websocket::is_redirect(&error) {
                        continue;
                    }
                    all_redirects = false;
                    if self.config.sni_fronting && should_front(&error) {
                        if let Ok(socket) = self
                            .ws(ip, &domain, "sprinthost.ru", path, true, true, limit)
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
                    !self.config.disable_secure,
                    self.connect_limit(),
                )
                .await
            {
                Ok(socket) => return Ok(socket),
                Err(e) => {
                    self.stats.ws_error();
                    error = e;
                    if self.config.verbose {
                        eprintln!("tgws: dc={dc} Worker domain={domain} failed: {error}");
                    }
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
                self.request_refill(key);
                return None;
            };
            if item.created.elapsed() < pool_max_age(key) && item.socket.idle_healthy().await {
                self.stats.pool_hit();
                self.request_refill(key);
                return Some(item.socket);
            }
        }
    }

    fn request_refill(&self, key: PoolKey) {
        let notify = {
            let mut state = self.state.lock().unwrap();
            state.pools.get_mut(&key).is_some_and(|bucket| {
                if bucket.refill_requested {
                    false
                } else {
                    bucket.refill_requested = true;
                    true
                }
            })
        };
        if notify {
            self.pool_wakeup.notify_one();
        }
    }

    /// One background dial at a time intentionally limits TLS handshake RAM on routers.
    /// Own this future under the proxy's JoinSet so restart cancels in-flight dials too.
    pub async fn maintain(&self) {
        if self.config.pool_size == 0 {
            return;
        }
        loop {
            let mut attempted = false;
            let mut next_retry: Option<Instant> = None;
            let keys: Vec<_> = self.state.lock().unwrap().pools.keys().copied().collect();
            for key in keys {
                let needed = {
                    let mut state = self.state.lock().unwrap();
                    let bucket = state.pools.get_mut(&key).unwrap();
                    bucket
                        .idle
                        .retain(|socket| socket.created.elapsed() < pool_max_age(key));
                    let cap = match key {
                        PoolKey::Direct(..) => self.config.pool_size,
                        PoolKey::Worker(..) => 1,
                    };
                    let capacity_missing = bucket.idle.len() < cap;
                    // A refill notification may arrive while the previous
                    // dial is still running.  Once that dial fills the bucket,
                    // consume the stale flag so the next checkout can wake us.
                    if !capacity_missing {
                        bucket.refill_requested = false;
                    }
                    let needed =
                        capacity_missing && bucket.retry.is_none_or(|t| t <= Instant::now());
                    if capacity_missing {
                        if let Some(retry) = bucket.retry.filter(|retry| *retry > Instant::now()) {
                            next_retry =
                                Some(next_retry.map_or(retry, |current| current.min(retry)));
                        }
                    }
                    if needed {
                        bucket.refill_requested = false;
                    }
                    needed
                };
                if !needed {
                    continue;
                }
                attempted = true;
                let result = match key {
                    PoolKey::Direct(dc, media, test) => self.pool_direct(dc, media, test).await,
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
            // Fill every missing slot immediately, but keep the actual TLS
            // handshakes sequential to cap CPU/RAM spikes on small routers.
            if attempted {
                continue;
            }
            let delay = next_retry
                .map(|retry| retry.saturating_duration_since(Instant::now()))
                .unwrap_or(Duration::from_secs(5))
                .min(Duration::from_secs(5));
            tokio::select! {
                _ = sleep(delay) => {}
                _ = self.pool_wakeup.notified() => {}
            }
        }
    }
    async fn pool_direct(&self, dc: i16, media: bool, test: bool) -> io::Result<WebSocket> {
        let ip = &self.config.dc_redirects[&dc];
        let path = ws_path(test);
        let mut last = io::Error::new(io::ErrorKind::NotConnected, "no direct WebSocket route");
        for domain in ws_domains(dc, media) {
            match self
                .ws(ip, &domain, &domain, path, true, true, self.connect_limit())
                .await
            {
                Ok(socket) => return Ok(socket),
                Err(error) => {
                    self.stats.ws_error();
                    let try_fronting = self.config.sni_fronting && should_front(&error);
                    last = error;
                    if try_fronting {
                        match self
                            .ws(
                                ip,
                                &domain,
                                "sprinthost.ru",
                                path,
                                true,
                                true,
                                self.connect_limit(),
                            )
                            .await
                        {
                            Ok(socket) => {
                                self.stats.fronting();
                                return Ok(socket);
                            }
                            Err(error) => {
                                self.stats.ws_error();
                                last = error;
                            }
                        }
                    }
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
            wire.write_all(b"GET /Flowseal/tg-ws-proxy/main/.github/cfproxy-domains.txt HTTP/1.1\r\nHost: raw.githubusercontent.com\r\nUser-Agent: tgws-rust/1.11.1\r\nAccept-Encoding: identity\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n").await?;
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
fn tcp_fallback_backoff(failures: u32) -> Duration {
    let exponent = failures.saturating_sub(1).min(7);
    Duration::from_secs((30u64 << exponent).min(3600))
}
fn pool_max_age(key: PoolKey) -> Duration {
    match key {
        PoolKey::Direct(..) => DIRECT_POOL_MAX_AGE,
        PoolKey::Worker(..) => WORKER_POOL_MAX_AGE,
    }
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
pub fn ws_domains(dc: i16, media: bool) -> Vec<String> {
    let dc = if dc == 203 { 2 } else { dc };
    let regular = format!("kws{dc}.web.telegram.org");
    if media {
        vec![format!("kws{dc}-1.web.telegram.org"), regular]
    } else {
        vec![regular]
    }
}
fn ws_path(test: bool) -> &'static str {
    if test {
        "/apiws_test"
    } else {
        "/apiws"
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
        assert_eq!(ws_domains(203, false), vec!["kws2.web.telegram.org"]);
        assert_eq!(
            ws_domains(203, true),
            vec!["kws2-1.web.telegram.org", "kws2.web.telegram.org"]
        );
        assert_eq!(ws_path(false), "/apiws");
        assert_eq!(ws_path(true), "/apiws_test");
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
        assert_eq!(
            pool_max_age(PoolKey::Direct(2, false, false)).as_secs(),
            120
        );
        assert_eq!(pool_max_age(PoolKey::Worker(2)).as_secs(), 100);
    }
    #[test]
    fn tcp_fallback_is_single_flight_and_has_upstream_backoff() {
        let state = Mutex::new(State::default());
        let key = ("192.0.2.1".to_owned(), 443);
        let now = Instant::now();

        let first = TcpAttempt::begin(&state, key.clone(), now).unwrap();
        assert!(TcpAttempt::begin(&state, key.clone(), now).is_none());
        assert!(TcpAttempt::begin(&state, ("192.0.2.2".into(), 443), now).is_some());
        drop(first);
        assert!(state.lock().unwrap().tcp_connecting.is_empty());

        let mut clock = now;
        for expected in [30, 60, 120, 240, 480, 960, 1920, 3600, 3600] {
            let attempt = TcpAttempt::begin(&state, key.clone(), clock).unwrap();
            let delay = attempt.failure(clock);
            assert_eq!(delay.as_secs(), expected);
            drop(attempt);
            assert!(TcpAttempt::begin(&state, key.clone(), clock).is_none());
            clock += delay;
        }

        let attempt = TcpAttempt::begin(&state, key.clone(), clock).unwrap();
        attempt.success();
        drop(attempt);
        let shared = state.lock().unwrap();
        assert!(!shared.tcp_failures.contains_key(&key));
        assert!(!shared.tcp_retry_after.contains_key(&key));
        assert!(!shared.tcp_connecting.contains(&key));
    }
    #[tokio::test]
    async fn pool_keys_and_paths_keep_production_and_test_sockets_separate() {
        let config = Config {
            pool_size: 1,
            cfproxy: false,
            dc_redirects: [(2, "192.0.2.1".to_owned())].into(),
            ..Config::default()
        };
        let upstream = Upstream::new(Arc::new(config), Arc::new(Stats::default())).unwrap();

        assert!(upstream
            .state
            .lock()
            .unwrap()
            .pools
            .contains_key(&PoolKey::Direct(2, false, false)));
        assert!(upstream.direct_route(2, false, true).await.is_none());
        let state = upstream.state.lock().unwrap();
        assert!(state.pools.contains_key(&PoolKey::Direct(2, false, false)));
        assert!(state.pools.contains_key(&PoolKey::Direct(2, false, true)));
        drop(state);

        let worker = Config {
            pool_size: 1,
            dc_redirects: [(2, "192.0.2.1".to_owned())].into(),
            cfproxy_worker_domains: vec!["worker.example".into()],
            ..Config::default()
        };
        let worker = Upstream::new(Arc::new(worker), Arc::new(Stats::default())).unwrap();
        let worker = worker.state.lock().unwrap();
        assert!(worker.pools.contains_key(&PoolKey::Worker(1)));
        assert!(!worker.pools.contains_key(&PoolKey::Worker(2)));
        drop(worker);

        let forced = Config {
            pool_size: 1,
            force_test_dc: true,
            dc_redirects: [(2, "192.0.2.1".to_owned())].into(),
            cfproxy_worker_domains: vec!["worker.example".into()],
            ..Config::default()
        };
        let forced = Upstream::new(Arc::new(forced), Arc::new(Stats::default())).unwrap();
        let forced = forced.state.lock().unwrap();
        assert!(forced.pools.contains_key(&PoolKey::Direct(2, false, true)));
        assert!(!forced.pools.contains_key(&PoolKey::Direct(2, false, false)));
        assert!(!forced
            .pools
            .keys()
            .any(|key| matches!(key, PoolKey::Worker(_))));
    }
    #[tokio::test]
    async fn tcp_fallback_sends_relay_header_before_releasing_single_flight() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let peer = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut relay = [0; 6];
            socket.read_exact(&mut relay).await.unwrap();
            relay
        });
        let config = Config {
            connect_timeout_secs: 1,
            ..Config::default()
        };
        let upstream = Upstream::new(Arc::new(config), Arc::new(Stats::default())).unwrap();
        let remote = upstream
            .tcp_fallback("127.0.0.1", port, b"relay!")
            .await
            .unwrap();
        assert_eq!(peer.await.unwrap(), *b"relay!");
        drop(remote);
        let key = ("127.0.0.1".to_owned(), port);
        let state = upstream.state.lock().unwrap();
        assert!(!state.tcp_connecting.contains(&key));
        assert!(!state.tcp_failures.contains_key(&key));
        assert!(!state.tcp_retry_after.contains_key(&key));
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
