//! HTTP/2 Cloudflare media fallback.
//!
//! A [`CfH2Pool`] keeps one TLS/H2 connection (a "lane") per Cloudflare
//! origin.  Independent native MTProto clients become lightweight
//! [`H2Channel`]s on that lane.  The module intentionally uses `h2` directly:
//! this keeps the router binary smaller than a general purpose HTTP client and
//! lets us put hard limits on streams and buffered bytes.

use crate::{
    crypto::{AesCtr, CryptoContext, Protocol},
    framing,
    stats::Stats,
};
use bytes::{Buf, Bytes};
use ctr::cipher::StreamCipher;
use h2::client::{ResponseFuture, SendRequest};
use http::{header, Method, Request, StatusCode, Version};
use rand::{rngs::OsRng, RngCore};
use socket2::SockRef;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    future::poll_fn,
    io,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex, Weak,
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::{mpsc, oneshot, Mutex as AsyncMutex, Notify, OwnedSemaphorePermit, Semaphore},
    task::{AbortHandle, JoinHandle},
    time::{sleep, timeout},
};
use tokio_native_tls::TlsConnector;

pub const MAX_PACKET: usize = 4 * 1024 * 1024;
const MAX_PADDED_PACKET: usize = MAX_PACKET + 15;
const MAX_CHANNEL_REQUESTS: usize = 8;
const MAX_CHANNEL_BYTES: usize = 8 * 1024 * 1024;
const MAX_CHANNEL_REPLY_BYTES: usize = 8 * 1024 * 1024;
const MAX_LANE_REQUESTS: usize = 64;
const MAX_LANE_BYTES: usize = 32 * 1024 * 1024;
const MAX_LANE_REPLY_BYTES: usize = 32 * 1024 * 1024;
const MAX_GLOBAL_REQUEST_BYTES: usize = MAX_PADDED_PACKET * 2;
const MAX_GLOBAL_REPLY_BYTES: usize = MAX_PACKET * 2;
const MAX_GLOBAL_HISTORY_BYTES: usize = 2 * 1024 * 1024;
const MAX_GLOBAL_REQUESTS: usize = 64;
const MAX_GLOBAL_REPLIES: usize = 64;
const MAX_GLOBAL_HISTORY_PACKETS: usize = 128;
const MAX_CACHED_LANES: usize = 8;
const MAX_LIVE_LANES: usize = MAX_CACHED_LANES;
const MAX_RESPONSE_CHUNKS: usize = 1024;
const MAX_HEADER_LIST_SIZE: u32 = 16 * 1024;
const STREAM_RECEIVE_WINDOW: u32 = 256 * 1024;
const CONNECTION_RECEIVE_WINDOW: u32 = 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(65);
const SETUP_TIMEOUT: Duration = Duration::from_secs(8);
const DOMAIN_COOLDOWN: Duration = Duration::from_secs(30);
const REPLAY_CHECK: Duration = Duration::from_millis(250);
const REPLAY_IDLE: Duration = Duration::from_secs(1);
const REPLAY_REQUEST: Duration = Duration::from_secs(3);
const REPLAY_RETRY: Duration = Duration::from_secs(2);
const REPLAY_MAX_AGE: Duration = Duration::from_secs(30);
const REPLAY_SLOT: Duration = Duration::from_secs(30);
const REPLAY_HISTORY_BYTES: usize = 64 * 1024;
const REPLAY_HISTORY_PACKETS: usize = 16;
const REPLAY_MAX_ATTEMPTS: u8 = 3;
const MAX_CHANNEL_REPLAYS: usize = 2;

fn other(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}

fn timed_out(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, message)
}

#[derive(Debug)]
enum PostError {
    /// An endpoint status that must be reported as an MTProto error packet.
    Transport(i32),
    /// A per-native-channel resource failure.  The shared origin is healthy.
    Channel(io::Error),
    /// An origin, protocol, or connection failure.  Cool down this lane.
    Route(io::Error),
}

impl PostError {
    fn route(error: impl std::fmt::Display) -> Self {
        Self::Route(other(error))
    }
}

/// A response body whose shared-lane memory charge remains held until the
/// native client has consumed or dropped it.
pub struct BufferedReply {
    parts: Vec<Bytes>,
    length: usize,
    _lane_charge: ReplyCharge,
    _channel_charge: Option<ChannelReplyCharge>,
}

impl BufferedReply {
    pub fn len(&self) -> usize {
        self.length
    }

    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    pub fn chunks(&self) -> impl Iterator<Item = &[u8]> {
        self.parts.iter().map(Bytes::as_ref)
    }
}

impl std::fmt::Debug for BufferedReply {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BufferedReply")
            .field("length", &self.length)
            .finish()
    }
}

/// A complete response ready to be encoded in the client's native transport.
#[derive(Debug)]
pub enum H2Reply {
    Packet(BufferedReply),
    TransportError(i32),
}

#[derive(Default)]
struct BudgetState {
    requests: usize,
    bytes: usize,
}

struct Budget {
    max_requests: usize,
    max_bytes: usize,
    state: Mutex<BudgetState>,
    changed: Notify,
}

impl Budget {
    fn new(max_requests: usize, max_bytes: usize) -> Arc<Self> {
        Arc::new(Self {
            max_requests,
            max_bytes,
            state: Mutex::new(BudgetState::default()),
            changed: Notify::new(),
        })
    }

    fn has_capacity(&self, bytes: usize) -> bool {
        let state = self.state.lock().unwrap();
        state.requests < self.max_requests
            && state
                .bytes
                .checked_add(bytes)
                .is_some_and(|n| n <= self.max_bytes)
    }

    fn try_acquire(self: &Arc<Self>, bytes: usize) -> Option<BudgetPermit> {
        let mut state = self.state.lock().unwrap();
        if state.requests >= self.max_requests || state.bytes.checked_add(bytes)? > self.max_bytes {
            return None;
        }
        state.requests += 1;
        state.bytes += bytes;
        Some(BudgetPermit {
            budget: self.clone(),
            bytes,
        })
    }

    async fn acquire(self: &Arc<Self>, bytes: usize, limit: Duration) -> io::Result<BudgetPermit> {
        let deadline = Instant::now() + limit;
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            // notify_waiters() does not retain a permit.  Register this waiter
            // before checking the protected state so a concurrent release
            // cannot land in the check-to-await gap.
            changed.as_mut().enable();
            if let Some(permit) = self.try_acquire(bytes) {
                return Ok(permit);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(timed_out("H2 request capacity exhausted"));
            }
            timeout(remaining, changed)
                .await
                .map_err(|_| timed_out("H2 request capacity exhausted"))?;
        }
    }
}

#[derive(Clone)]
struct PayloadBudgets {
    requests: Arc<Budget>,
    replies: Arc<Budget>,
    history: Arc<Budget>,
}

impl PayloadBudgets {
    fn process_defaults() -> Self {
        Self {
            requests: Budget::new(MAX_GLOBAL_REQUESTS, MAX_GLOBAL_REQUEST_BYTES),
            replies: Budget::new(MAX_GLOBAL_REPLIES, MAX_GLOBAL_REPLY_BYTES),
            history: Budget::new(MAX_GLOBAL_HISTORY_PACKETS, MAX_GLOBAL_HISTORY_BYTES),
        }
    }
}

struct BudgetPermit {
    budget: Arc<Budget>,
    bytes: usize,
}

impl BudgetPermit {
    fn try_extend_bytes(&mut self, bytes: usize) -> bool {
        let mut state = self.budget.state.lock().unwrap();
        let Some(total) = state.bytes.checked_add(bytes) else {
            return false;
        };
        if total > self.budget.max_bytes {
            return false;
        }
        state.bytes = total;
        self.bytes += bytes;
        true
    }

    fn shrink_bytes(&mut self, bytes: usize) {
        debug_assert!(bytes <= self.bytes);
        let mut state = self.budget.state.lock().unwrap();
        self.bytes -= bytes;
        state.bytes = state.bytes.saturating_sub(bytes);
        drop(state);
        self.budget.changed.notify_waiters();
    }
}

struct Activity {
    last: Mutex<Instant>,
    changed: Notify,
}

impl Activity {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            last: Mutex::new(Instant::now()),
            changed: Notify::new(),
        })
    }

    fn touch(&self) {
        *self.last.lock().unwrap() = Instant::now();
        self.changed.notify_waiters();
    }

    async fn expired(&self, idle_timeout: Duration) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let remaining = idle_timeout.saturating_sub(
                Instant::now().saturating_duration_since(*self.last.lock().unwrap()),
            );
            if remaining.is_zero() {
                return;
            }
            if timeout(remaining, changed).await.is_err() {
                return;
            }
        }
    }
}

struct RequestCapacity {
    channel: BudgetPermit,
    lane: BudgetPermit,
    global: BudgetPermit,
}

impl Drop for BudgetPermit {
    fn drop(&mut self) {
        let mut state = self.budget.state.lock().unwrap();
        state.requests = state.requests.saturating_sub(1);
        state.bytes = state.bytes.saturating_sub(self.bytes);
        drop(state);
        self.budget.changed.notify_waiters();
    }
}

#[derive(Default)]
struct ConnectionState {
    generation: usize,
    sender: Option<SendRequest<Bytes>>,
    driver: Option<JoinHandle<()>>,
}

struct Lane {
    host: String,
    connector: TlsConnector,
    stats: Arc<Stats>,
    connect_timeout: Duration,
    buffer_size: usize,
    connection: Mutex<ConnectionState>,
    retired_drivers: Mutex<Vec<JoinHandle<()>>>,
    connect_lock: AsyncMutex<()>,
    budget: Arc<Budget>,
    payload_budgets: PayloadBudgets,
    reply_bytes: Mutex<usize>,
    channels: Mutex<Vec<Weak<ChannelInner>>>,
    last_used: Mutex<Instant>,
    failed_until: Mutex<Option<Instant>>,
    closed: AtomicBool,
    next_channel: AtomicUsize,
    next_task: AtomicUsize,
    request_tasks: Mutex<HashMap<usize, JoinHandle<()>>>,
    _slot: Option<OwnedSemaphorePermit>,
}

impl Lane {
    fn new(
        host: String,
        connector: TlsConnector,
        connect_timeout: Duration,
        buffer_size: usize,
        stats: Arc<Stats>,
        payload_budgets: PayloadBudgets,
        slot: Option<OwnedSemaphorePermit>,
    ) -> Arc<Self> {
        Arc::new(Self {
            host,
            connector,
            stats,
            connect_timeout,
            buffer_size,
            connection: Mutex::new(ConnectionState::default()),
            retired_drivers: Mutex::new(Vec::new()),
            connect_lock: AsyncMutex::new(()),
            budget: Budget::new(MAX_LANE_REQUESTS, MAX_LANE_BYTES),
            payload_budgets,
            reply_bytes: Mutex::new(0),
            channels: Mutex::new(Vec::new()),
            last_used: Mutex::new(Instant::now()),
            failed_until: Mutex::new(None),
            closed: AtomicBool::new(false),
            next_channel: AtomicUsize::new(1),
            next_task: AtomicUsize::new(1),
            request_tasks: Mutex::new(HashMap::new()),
            _slot: slot,
        })
    }

    fn available(&self) -> bool {
        if self.closed.load(Ordering::Acquire) {
            return false;
        }
        let mut failed = self.failed_until.lock().unwrap();
        if failed.is_some_and(|until| Instant::now() >= until) {
            *failed = None;
        }
        failed.is_none()
    }

    fn cool_down(&self) {
        *self.failed_until.lock().unwrap() = Some(Instant::now() + DOMAIN_COOLDOWN);
    }

    fn register(&self, channel: &Arc<ChannelInner>) {
        self.touch();
        let mut channels = self.channels.lock().unwrap();
        channels.retain(|item| item.strong_count() > 0);
        channels.push(Arc::downgrade(channel));
    }

    fn touch(&self) {
        *self.last_used.lock().unwrap() = Instant::now();
    }

    fn has_live_channels(&self) -> bool {
        let mut channels = self.channels.lock().unwrap();
        channels.retain(|channel| channel.strong_count() > 0);
        !channels.is_empty()
    }

    fn last_used(&self) -> Instant {
        *self.last_used.lock().unwrap()
    }

    fn next_channel_id(&self) -> usize {
        self.next_channel.fetch_add(1, Ordering::Relaxed)
    }

    fn next_task_id(&self) -> usize {
        self.next_task.fetch_add(1, Ordering::Relaxed)
    }

    fn register_task(&self, task: usize, handle: JoinHandle<()>) {
        let mut tasks = self.request_tasks.lock().unwrap();
        tasks.retain(|_, task| !task.is_finished());
        tasks.insert(task, handle);
    }

    fn charge_reply(self: &Arc<Self>, bytes: usize) -> Result<ReplyCharge, PostError> {
        let global = self
            .payload_budgets
            .replies
            .try_acquire(bytes)
            .ok_or_else(|| {
                PostError::Channel(io::Error::other(
                    "H2 process payload buffers exceeded bound",
                ))
            })?;
        let mut total = self.reply_bytes.lock().unwrap();
        if total
            .checked_add(bytes)
            .is_none_or(|n| n > MAX_LANE_REPLY_BYTES)
        {
            return Err(PostError::Channel(io::Error::other(
                "H2 lane response buffers exceeded bound",
            )));
        }
        *total += bytes;
        Ok(ReplyCharge {
            lane: self.clone(),
            bytes,
            _global: global,
        })
    }

    fn retain_driver(&self, driver: JoinHandle<()>) {
        let mut retired = self.retired_drivers.lock().unwrap();
        retired.retain(|task| !task.is_finished());
        retired.push(driver);
    }

    fn invalidate_connection(&self, generation: usize) {
        let mut state = self.connection.lock().unwrap();
        if state.generation == generation {
            state.sender = None;
            if let Some(driver) = state.driver.take() {
                driver.abort();
                self.retain_driver(driver);
            }
        }
    }

    fn connection_finished(&self, generation: usize) {
        let mut state = self.connection.lock().unwrap();
        if state.generation == generation {
            state.sender = None;
        }
    }

    async fn connect(self: &Arc<Self>) -> io::Result<(SendRequest<Bytes>, usize)> {
        if self.closed.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "H2 lane closed",
            ));
        }
        {
            let state = self.connection.lock().unwrap();
            if let Some(sender) = state.sender.clone() {
                return Ok((sender, state.generation));
            }
        }

        let _guard = self.connect_lock.lock().await;
        self.retired_drivers
            .lock()
            .unwrap()
            .retain(|task| !task.is_finished());
        if self.closed.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "H2 lane closed",
            ));
        }
        {
            let state = self.connection.lock().unwrap();
            if let Some(sender) = state.sender.clone() {
                return Ok((sender, state.generation));
            }
        }

        let tcp = timeout(self.connect_timeout, TcpStream::connect((&*self.host, 443)))
            .await
            .map_err(|_| timed_out("H2 TCP connect timed out"))??;
        tcp.set_nodelay(true)?;
        let socket = SockRef::from(&tcp);
        let _ = socket.set_recv_buffer_size(self.buffer_size);
        let _ = socket.set_send_buffer_size(self.buffer_size);
        let tls = timeout(
            self.connect_timeout,
            self.connector.connect(&self.host, tcp),
        )
        .await
        .map_err(|_| timed_out("H2 TLS connect timed out"))?
        .map_err(other)?;
        let negotiated = tls.get_ref().negotiated_alpn().map_err(other)?;
        if negotiated.as_deref() != Some(b"h2") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Cloudflare origin did not negotiate h2",
            ));
        }

        let mut builder = h2::client::Builder::new();
        builder
            .initial_window_size(STREAM_RECEIVE_WINDOW)
            .initial_connection_window_size(CONNECTION_RECEIVE_WINDOW)
            .max_header_list_size(MAX_HEADER_LIST_SIZE)
            .enable_push(false);
        let (sender, connection) = timeout(self.connect_timeout, builder.handshake(tls))
            .await
            .map_err(|_| timed_out("H2 protocol handshake timed out"))?
            .map_err(other)?;
        let mut state = self.connection.lock().unwrap();
        if self.closed.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "H2 lane closed",
            ));
        }
        state.generation = state.generation.wrapping_add(1);
        let generation = state.generation;
        if let Some(previous) = state.driver.take() {
            self.retain_driver(previous);
        }
        let weak = Arc::downgrade(self);
        let task = tokio::spawn(async move {
            let _ = connection.await;
            if let Some(lane) = weak.upgrade() {
                lane.connection_finished(generation);
            }
        });
        state.sender = Some(sender.clone());
        state.driver = Some(task);
        self.stats.h2_tcp();
        Ok((sender, generation))
    }

    async fn ready_sender(self: &Arc<Self>) -> io::Result<SendRequest<Bytes>> {
        // Reconnect once if an idle connection died before a request acquired a
        // stream.  Never retry after request headers or body were submitted.
        for attempt in 0..2 {
            let (sender, generation) = self.connect().await?;
            match sender.ready().await {
                Ok(sender) => return Ok(sender),
                Err(_) if attempt == 0 => {
                    self.invalidate_connection(generation);
                }
                Err(error) => return Err(other(error)),
            }
        }
        unreachable!()
    }

    async fn start_request(
        self: &Arc<Self>,
        method: Method,
        body: Bytes,
    ) -> io::Result<(ResponseFuture, h2::SendStream<Bytes>)> {
        let mut sender = self.ready_sender().await?;
        let uri = format!("https://{}/api", self.host);
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .version(Version::HTTP_2)
            .header(header::ACCEPT_ENCODING, "identity");
        if !body.is_empty() {
            request = request
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .header(header::CONTENT_LENGTH, body.len());
        }
        let request = request.body(()).map_err(other)?;
        sender.send_request(request, body.is_empty()).map_err(other)
    }

    async fn send_body(mut stream: h2::SendStream<Bytes>, mut body: Bytes) -> io::Result<()> {
        while body.has_remaining() {
            stream.reserve_capacity(body.remaining());
            let granted = poll_fn(|cx| stream.poll_capacity(cx))
                .await
                .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "H2 stream closed"))?
                .map_err(other)?;
            if granted == 0 {
                continue;
            }
            let count = granted.min(body.remaining());
            let chunk = body.split_to(count);
            stream.send_data(chunk, body.is_empty()).map_err(other)?;
        }
        Ok(())
    }

    async fn preflight(self: &Arc<Self>) -> io::Result<()> {
        let (response, _stream) = self.start_request(Method::HEAD, Bytes::new()).await?;
        let response = response.await.map_err(other)?;
        match response.status() {
            status if status.is_success() => Ok(()),
            StatusCode::METHOD_NOT_ALLOWED | StatusCode::NOT_IMPLEMENTED => Ok(()),
            status => Err(io::Error::other(format!(
                "Cloudflare /api preflight HTTP {}",
                status.as_u16()
            ))),
        }
    }

    async fn post<F, G>(
        self: &Arc<Self>,
        body: Bytes,
        sent: F,
        headers_received: G,
    ) -> Result<Option<BufferedReply>, PostError>
    where
        F: FnOnce(),
        G: FnOnce(),
    {
        self.stats.h2_request();
        let (response, stream) = self
            .start_request(Method::POST, body.clone())
            .await
            .map_err(PostError::route)?;
        Self::send_body(stream, body)
            .await
            .map_err(PostError::route)?;
        sent();
        let response = response.await.map_err(PostError::route)?;
        headers_received();
        let status = response.status().as_u16();
        if matches!(status, 403 | 404 | 429 | 444) {
            // Do not consume a possible Cloudflare HTML error page.  Dropping
            // RecvStream resets only this H2 stream.
            return Err(PostError::Transport(-(status as i32)));
        }
        if status != 200 {
            return Err(PostError::Route(io::Error::other(format!(
                "Cloudflare /api HTTP {status}"
            ))));
        }
        if response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.to_ascii_lowercase().contains("text/html"))
        {
            return Err(PostError::Route(io::Error::new(
                io::ErrorKind::InvalidData,
                "Cloudflare /api returned HTML instead of MTProto",
            )));
        }
        let declared = response
            .headers()
            .get(header::CONTENT_LENGTH)
            .map(|value| {
                value
                    .to_str()
                    .map_err(other)?
                    .parse::<usize>()
                    .map_err(other)
            })
            .transpose()
            .map_err(PostError::Route)?;
        if declared.is_some_and(|length| length > MAX_PACKET) {
            return Err(PostError::Route(io::Error::new(
                io::ErrorKind::InvalidData,
                "H2 response Content-Length exceeds MTProto packet bound",
            )));
        }
        if let Some(encoding) = response.headers().get(header::CONTENT_ENCODING) {
            let encoding = encoding.to_str().map_err(PostError::route)?;
            if !encoding.eq_ignore_ascii_case("identity") {
                return Err(PostError::Route(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Cloudflare /api returned unsupported Content-Encoding",
                )));
            }
        }
        let mut stream = response.into_body();
        // Charge a declared body before reserving it.  Without Content-Length,
        // retain bounded zero-copy DATA chunks and merge their accounting into
        // one charge; native framing can stream those chunks without a second
        // packet-sized allocation.
        let mut charge = None;
        let mut content = if let Some(length) = declared {
            charge = Some(self.charge_reply(length)?);
            let mut body = Vec::new();
            body.try_reserve_exact(length)
                .map_err(|error| PostError::Channel(other(error)))?;
            Some(body)
        } else {
            None
        };
        let mut chunks = Vec::new();
        let mut received = 0usize;
        while let Some(chunk) = stream.data().await {
            let chunk = chunk.map_err(PostError::route)?;
            let chunk_len = chunk.len();
            if received
                .checked_add(chunk_len)
                .is_none_or(|length| length > MAX_PACKET)
            {
                return Err(PostError::Route(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "H2 response exceeds MTProto packet bound",
                )));
            }
            received += chunk_len;
            if let Some(body) = &mut content {
                if received > declared.unwrap() {
                    return Err(PostError::Route(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "H2 response exceeded Content-Length",
                    )));
                }
                body.extend_from_slice(&chunk);
            } else {
                if chunk_len == 0 {
                    continue;
                }
                if chunks.len() >= MAX_RESPONSE_CHUNKS {
                    return Err(PostError::Route(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "H2 response is excessively fragmented",
                    )));
                }
                if let Some(charge) = &mut charge {
                    charge.try_extend(chunk_len)?;
                } else {
                    charge = Some(self.charge_reply(chunk_len)?);
                }
                chunks.push(chunk);
            }
            stream
                .flow_control()
                .release_capacity(chunk_len)
                .map_err(PostError::route)?;
        }
        if declared.is_some_and(|length| length != received) {
            return Err(PostError::Route(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "incomplete H2 response body",
            )));
        }
        let parts = match content {
            Some(content) => vec![Bytes::from(content)],
            None => chunks,
        };
        if received % 4 != 0 {
            return Err(PostError::Route(io::Error::new(
                io::ErrorKind::InvalidData,
                "Cloudflare /api response is not an aligned MTProto packet",
            )));
        }
        if received == 4 {
            let mut encoded = [0_u8; 4];
            let mut offset = 0;
            for part in &parts {
                encoded[offset..offset + part.len()].copy_from_slice(part);
                offset += part.len();
            }
            let code = i32::from_le_bytes(encoded);
            if code < 0 {
                return Err(PostError::Transport(code));
            }
        }
        if received == 0 {
            return Ok(None);
        }
        let lane_charge = charge.expect("non-empty H2 response must retain its lane memory charge");
        Ok(Some(BufferedReply {
            parts,
            length: received,
            _lane_charge: lane_charge,
            _channel_charge: None,
        }))
    }

    fn make_room(&self, waiting: &ChannelInner, bytes: usize) {
        let channel_full = !waiting.budget.has_capacity(bytes);
        let lane_full = !self.budget.has_capacity(bytes);
        if !channel_full && !lane_full {
            return;
        }
        let now = Instant::now();
        let channels = if channel_full {
            vec![waiting.weak_self()]
        } else {
            let mut channels = self.channels.lock().unwrap();
            channels.retain(|channel| channel.strong_count() > 0);
            channels.clone()
        };
        let mut candidates = Vec::new();
        for weak in channels {
            let Some(channel) = weak.upgrade() else {
                continue;
            };
            let state = channel.state.lock().unwrap();
            for (&id, pending) in &state.pending {
                let Some(sent_at) = pending.sent_at else {
                    continue;
                };
                if pending.receiving || now.duration_since(sent_at) < REPLAY_REQUEST {
                    continue;
                }
                let retained = pending.replay
                    || pending
                        .entry
                        .is_some_and(|seq| state.history.iter().any(|entry| entry.sequence == seq));
                if retained {
                    candidates.push((!pending.replay, sent_at, Arc::downgrade(&channel), id));
                }
            }
        }
        candidates.sort_by_key(|(original, sent, _, _)| (*original, *sent));
        if let Some((_, _, channel, id)) = candidates.into_iter().next() {
            if let Some(channel) = channel.upgrade() {
                channel.retire_and_abort(id);
            }
        }
    }

    fn abort(&self) {
        self.closed.store(true, Ordering::Release);
        {
            let mut state = self.connection.lock().unwrap();
            state.sender = None;
            if let Some(driver) = &state.driver {
                driver.abort();
            }
        }
        for driver in self.retired_drivers.lock().unwrap().iter() {
            driver.abort();
        }
        let channels = {
            let mut channels = self.channels.lock().unwrap();
            channels.retain(|channel| channel.strong_count() > 0);
            channels.clone()
        };
        for channel in channels {
            if let Some(channel) = channel.upgrade() {
                channel.fail(Terminal::Error(
                    io::ErrorKind::NotConnected,
                    "H2 pool closed".into(),
                ));
            }
        }
        for task in self.request_tasks.lock().unwrap().values() {
            task.abort();
        }
    }

    fn start_close(&self) -> Vec<JoinHandle<()>> {
        self.abort();
        let mut tasks = Vec::new();
        if let Some(driver) = self.connection.lock().unwrap().driver.take() {
            tasks.push(driver);
        }
        tasks.extend(std::mem::take(&mut *self.retired_drivers.lock().unwrap()));
        self.channels.lock().unwrap().clear();
        tasks.extend(std::mem::take(&mut *self.request_tasks.lock().unwrap()).into_values());
        tasks
    }

    fn reap_if_quiescent(&self) -> bool {
        if !self.closed.load(Ordering::Acquire) || self.has_live_channels() {
            return false;
        }
        {
            let mut state = self.connection.lock().unwrap();
            if state.driver.as_ref().is_some_and(|task| task.is_finished()) {
                state.driver = None;
            }
            if state.driver.is_some() {
                return false;
            }
        }
        {
            let mut drivers = self.retired_drivers.lock().unwrap();
            drivers.retain(|task| !task.is_finished());
            if !drivers.is_empty() {
                return false;
            }
        }
        let mut requests = self.request_tasks.lock().unwrap();
        requests.retain(|_, task| !task.is_finished());
        requests.is_empty()
    }

    async fn settle_close(&self) -> Vec<JoinHandle<()>> {
        // Wait out a connect already inside TCP/TLS/H2 setup.  connect()
        // rechecks closed before publishing, and holding this guard prevents a
        // later publisher until the final state drain below is complete.
        let _connect = self.connect_lock.lock().await;
        self.start_close()
    }

    fn close(&self) {
        // Keep aborted handles owned by the lane so CfH2Pool::close can still
        // await them after a cancelled cold open or failed setup.
        self.abort();
    }
}

impl Drop for Lane {
    fn drop(&mut self) {
        let state = self.connection.get_mut().unwrap();
        state.sender = None;
        if let Some(driver) = state.driver.take() {
            driver.abort();
        }
        for driver in self.retired_drivers.get_mut().unwrap().drain(..) {
            driver.abort();
        }
    }
}

struct LaneSetupGuard {
    lane: Option<Arc<Lane>>,
}

impl LaneSetupGuard {
    fn new(lane: Arc<Lane>) -> Self {
        Self { lane: Some(lane) }
    }

    fn disarm(&mut self) {
        self.lane = None;
    }
}

impl Drop for LaneSetupGuard {
    fn drop(&mut self) {
        if let Some(lane) = &self.lane {
            lane.close();
        }
    }
}

struct ReplyCharge {
    lane: Arc<Lane>,
    bytes: usize,
    _global: BudgetPermit,
}

impl ReplyCharge {
    fn try_extend(&mut self, bytes: usize) -> Result<(), PostError> {
        // An unknown-length response is still one reply no matter how many
        // DATA frames carry it.  Grow its byte charge without consuming a new
        // process reply-count slot for every frame.
        if !self._global.try_extend_bytes(bytes) {
            return Err(PostError::Channel(io::Error::other(
                "H2 process payload buffers exceeded bound",
            )));
        }
        let mut total = self.lane.reply_bytes.lock().unwrap();
        if total
            .checked_add(bytes)
            .is_none_or(|n| n > MAX_LANE_REPLY_BYTES)
        {
            drop(total);
            self._global.shrink_bytes(bytes);
            return Err(PostError::Channel(io::Error::other(
                "H2 lane response buffers exceeded bound",
            )));
        }
        *total += bytes;
        self.bytes += bytes;
        Ok(())
    }
}

struct ChannelReplyCharge {
    channel: Weak<ChannelInner>,
    bytes: usize,
}

impl Drop for ChannelReplyCharge {
    fn drop(&mut self) {
        if let Some(channel) = self.channel.upgrade() {
            let mut state = channel.state.lock().unwrap();
            state.reply_bytes = state.reply_bytes.saturating_sub(self.bytes);
        }
    }
}

impl Drop for ReplyCharge {
    fn drop(&mut self) {
        let mut total = self.lane.reply_bytes.lock().unwrap();
        *total = total.saturating_sub(self.bytes);
    }
}

struct ReplayEntry {
    sent_at: Instant,
    body: Bytes,
    sequence: usize,
    attempts: u8,
    last_attempt: Option<Instant>,
    pending: Option<usize>,
    originals: BTreeSet<usize>,
    retired: bool,
    _history_permit: BudgetPermit,
}

struct Pending {
    abort: AbortHandle,
    replay: bool,
    entry: Option<usize>,
    sent_at: Option<Instant>,
    receiving: bool,
}

enum Terminal {
    Transport(i32),
    Error(io::ErrorKind, String),
}

#[derive(Default)]
struct ChannelState {
    next_request: usize,
    pending: BTreeMap<usize, Pending>,
    history: VecDeque<ReplayEntry>,
    replay_key: Option<[u8; 8]>,
    reply_bytes: usize,
    terminal: Option<Terminal>,
    last_progress: Option<Instant>,
    delivering: bool,
    waiting_upload: Option<(Instant, usize)>,
}

struct ChannelInner {
    id: usize,
    lane: Arc<Lane>,
    budget: Arc<Budget>,
    state: Mutex<ChannelState>,
    replies: mpsc::Sender<BufferedReply>,
    receiver: AsyncMutex<mpsc::Receiver<BufferedReply>>,
    terminal_changed: Notify,
    progress_changed: Notify,
    closed: AtomicBool,
    self_ref: Mutex<Weak<ChannelInner>>,
}

impl ChannelInner {
    fn new(lane: Arc<Lane>) -> Arc<Self> {
        let (replies, receiver) = mpsc::channel(16);
        let channel = Arc::new(Self {
            id: lane.next_channel_id(),
            lane,
            budget: Budget::new(MAX_CHANNEL_REQUESTS, MAX_CHANNEL_BYTES),
            state: Mutex::new(ChannelState {
                last_progress: Some(Instant::now()),
                ..ChannelState::default()
            }),
            replies,
            receiver: AsyncMutex::new(receiver),
            terminal_changed: Notify::new(),
            progress_changed: Notify::new(),
            closed: AtomicBool::new(false),
            self_ref: Mutex::new(Weak::new()),
        });
        *channel.self_ref.lock().unwrap() = Arc::downgrade(&channel);
        channel.lane.register(&channel);
        channel
    }

    fn weak_self(&self) -> Weak<Self> {
        self.self_ref.lock().unwrap().clone()
    }

    fn terminal(&self) -> Option<Terminal> {
        self.state.lock().unwrap().terminal.take()
    }

    fn fail(&self, terminal: Terminal) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        let aborts = {
            let mut state = self.state.lock().unwrap();
            state.terminal = Some(terminal);
            state.history.clear();
            state.waiting_upload = None;
            state
                .pending
                .values()
                .map(|pending| pending.abort.clone())
                .collect::<Vec<_>>()
        };
        for abort in aborts {
            abort.abort();
        }
        self.terminal_changed.notify_waiters();
        self.budget.changed.notify_waiters();
    }

    fn remember(
        &self,
        state: &mut ChannelState,
        body: &Bytes,
        request: usize,
        now: Instant,
    ) -> Option<usize> {
        if body.len() > REPLAY_HISTORY_BYTES || body.len() < 8 || body[..8] == [0; 8] {
            return None;
        }
        let key: [u8; 8] = body[..8].try_into().unwrap();
        if state.replay_key != Some(key) {
            state.history.clear();
            state.replay_key = Some(key);
        }
        let sequence =
            if let Some(entry) = state.history.iter_mut().find(|entry| entry.body == *body) {
                entry.originals.insert(request);
                entry.sequence
            } else {
                let history_permit = self.lane.payload_budgets.history.try_acquire(body.len())?;
                let sequence = request;
                state.history.push_back(ReplayEntry {
                    sent_at: now,
                    body: body.clone(),
                    sequence,
                    attempts: 0,
                    last_attempt: None,
                    pending: None,
                    originals: BTreeSet::from([request]),
                    retired: false,
                    _history_permit: history_permit,
                });
                sequence
            };
        let mut retained = state
            .history
            .iter()
            .map(|entry| entry.body.len())
            .sum::<usize>();
        while state.history.len() > REPLAY_HISTORY_PACKETS || retained > REPLAY_HISTORY_BYTES {
            let index = state
                .history
                .iter()
                .position(|entry| {
                    entry.originals.is_empty()
                        && !(entry.retired
                            && entry.attempts < REPLAY_MAX_ATTEMPTS
                            && now.duration_since(entry.sent_at) <= REPLAY_MAX_AGE)
                })
                .unwrap_or(0);
            if let Some(entry) = state.history.remove(index) {
                retained = retained.saturating_sub(entry.body.len());
            }
        }
        Some(sequence)
    }

    async fn reserve(self: &Arc<Self>, bytes: usize) -> io::Result<RequestCapacity> {
        if self.closed.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "H2 channel closed",
            ));
        }
        {
            self.state.lock().unwrap().waiting_upload = Some((Instant::now(), bytes));
        }
        let channel = match self.budget.acquire(bytes, REQUEST_TIMEOUT).await {
            Ok(permit) => permit,
            Err(error) => {
                self.state.lock().unwrap().waiting_upload = None;
                return Err(error);
            }
        };
        let lane = self.lane.budget.acquire(bytes, REQUEST_TIMEOUT).await;
        let global = match lane {
            Ok(lane) => (
                lane,
                self.lane
                    .payload_budgets
                    .requests
                    .acquire(bytes, REQUEST_TIMEOUT)
                    .await,
            ),
            Err(error) => {
                self.state.lock().unwrap().waiting_upload = None;
                return Err(error);
            }
        };
        self.state.lock().unwrap().waiting_upload = None;
        let (lane, global) = global;
        Ok(RequestCapacity {
            channel,
            lane,
            global: global?,
        })
    }

    fn send_reserved(self: &Arc<Self>, body: Bytes, capacity: RequestCapacity) -> io::Result<()> {
        self.launch(
            body,
            false,
            capacity.channel,
            capacity.lane,
            capacity.global,
            None,
        )
    }

    fn try_replay(self: &Arc<Self>, sequence: usize, body: Bytes) -> bool {
        let Some(channel_permit) = self.budget.try_acquire(body.len()) else {
            return false;
        };
        let Some(lane_permit) = self.lane.budget.try_acquire(body.len()) else {
            return false;
        };
        let Some(global_permit) = self.lane.payload_budgets.requests.try_acquire(body.len()) else {
            return false;
        };
        self.launch(
            body,
            true,
            channel_permit,
            lane_permit,
            global_permit,
            Some(sequence),
        )
        .is_ok()
    }

    fn launch(
        self: &Arc<Self>,
        body: Bytes,
        replay: bool,
        channel_permit: BudgetPermit,
        lane_permit: BudgetPermit,
        global_permit: BudgetPermit,
        replay_sequence: Option<usize>,
    ) -> io::Result<()> {
        let now = Instant::now();
        // Insertion and the closed check share the state lock with fail().
        // If fail wins, no task is spawned; if launch wins, fail observes and
        // aborts the newly inserted request.  The start gate prevents the task
        // from completing before Pending becomes visible.
        let mut state = self.state.lock().unwrap();
        if self.closed.load(Ordering::Acquire) || state.terminal.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "H2 channel closed",
            ));
        }
        if let Some(sequence) = replay_sequence {
            let valid = state
                .history
                .iter()
                .any(|entry| entry.sequence == sequence && entry.pending.is_none());
            if !valid {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "H2 replay is no longer eligible",
                ));
            }
        }
        state.next_request = state.next_request.wrapping_add(1);
        let request = state.next_request;
        let weak = Arc::downgrade(self);
        let lane = self.lane.clone();
        let task_id = lane.next_task_id();
        let task_lane = lane.clone();
        let task_body = body.clone();
        // Construct the guard before spawning.  Aborting a task before its
        // first poll must still release both budgets and remove Pending.
        let request_guard = RequestGuard {
            channel: weak.clone(),
            request,
            _channel_permit: channel_permit,
            _lane_permit: lane_permit,
            _global_permit: global_permit,
        };
        let (start, started) = oneshot::channel();
        let task = tokio::spawn(async move {
            let _guard = request_guard;
            if started.await.is_err() {
                return;
            }
            let sent_channel = weak.clone();
            let headers_channel = weak.clone();
            let result = timeout(
                REQUEST_TIMEOUT,
                task_lane.post(
                    task_body,
                    move || {
                        if let Some(channel) = sent_channel.upgrade() {
                            channel.mark_sent(request);
                        }
                    },
                    move || {
                        if let Some(channel) = headers_channel.upgrade() {
                            channel.mark_receiving(request);
                        }
                    },
                ),
            )
            .await;
            let Some(channel) = weak.upgrade() else {
                return;
            };
            match result {
                Ok(Ok(Some(reply))) => channel.deliver(reply),
                Ok(Ok(None)) => channel.progress(),
                Ok(Err(PostError::Transport(code))) => {
                    channel.lane.stats.h2_error();
                    channel.fail(Terminal::Transport(code));
                }
                Ok(Err(PostError::Channel(error))) => {
                    channel.lane.stats.h2_error();
                    channel.fail(Terminal::Error(error.kind(), error.to_string()));
                }
                Ok(Err(PostError::Route(error))) => {
                    channel.lane.stats.h2_error();
                    channel.lane.cool_down();
                    channel.fail(Terminal::Error(error.kind(), error.to_string()));
                }
                Err(_) => {
                    channel.lane.stats.h2_error();
                    channel.lane.cool_down();
                    channel.fail(Terminal::Error(
                        io::ErrorKind::TimedOut,
                        "H2 request timed out".into(),
                    ));
                }
            }
        });
        let abort = task.abort_handle();
        lane.register_task(task_id, task);
        let entry = if replay {
            replay_sequence
        } else {
            self.remember(&mut state, &body, request, now)
        };
        if let Some(sequence) = replay_sequence {
            if let Some(entry) = state
                .history
                .iter_mut()
                .find(|entry| entry.sequence == sequence)
            {
                entry.attempts = entry.attempts.saturating_add(1);
                entry.last_attempt = Some(now);
                entry.pending = Some(request);
            }
        }
        state.pending.insert(
            request,
            Pending {
                abort,
                replay,
                entry,
                sent_at: None,
                receiving: false,
            },
        );
        drop(state);
        // Pending and both task handles are visible before the task can mutate
        // or finish that record, including on a multi-thread runtime.
        let _ = start.send(());
        Ok(())
    }

    fn mark_sent(&self, request: usize) {
        if let Some(pending) = self.state.lock().unwrap().pending.get_mut(&request) {
            pending.sent_at = Some(Instant::now());
        }
    }

    fn mark_receiving(&self, request: usize) {
        let mut state = self.state.lock().unwrap();
        if let Some(pending) = state.pending.get_mut(&request) {
            pending.receiving = true;
        }
        state.last_progress = Some(Instant::now());
    }

    fn progress(&self) {
        self.state.lock().unwrap().last_progress = Some(Instant::now());
        self.progress_changed.notify_waiters();
    }

    fn deliver(&self, mut reply: BufferedReply) {
        debug_assert!(!reply.is_empty());
        let length = reply.len();
        let mut state = self.state.lock().unwrap();
        if self.closed.load(Ordering::Acquire) || state.terminal.is_some() {
            return;
        }
        state.last_progress = Some(Instant::now());
        if state
            .reply_bytes
            .checked_add(length)
            .is_none_or(|bytes| bytes > MAX_CHANNEL_REPLY_BYTES)
        {
            drop(state);
            self.fail(Terminal::Error(
                io::ErrorKind::OutOfMemory,
                "H2 client response queue exceeded bound".into(),
            ));
            return;
        }
        state.reply_bytes += length;
        reply._channel_charge = Some(ChannelReplyCharge {
            channel: self.weak_self(),
            bytes: length,
        });
        drop(state);
        if let Err(error) = self.replies.try_send(reply) {
            drop(error.into_inner());
            self.fail(Terminal::Error(
                io::ErrorKind::OutOfMemory,
                "H2 client response queue is full".into(),
            ));
        }
    }

    fn finish_request(&self, request: usize) {
        let mut state = self.state.lock().unwrap();
        let Some(pending) = state.pending.remove(&request) else {
            return;
        };
        if let Some(sequence) = pending.entry {
            if let Some(entry) = state
                .history
                .iter_mut()
                .find(|entry| entry.sequence == sequence)
            {
                if pending.replay && entry.pending == Some(request) {
                    entry.pending = None;
                } else {
                    entry.originals.remove(&request);
                }
            }
        }
        drop(state);
        self.budget.changed.notify_waiters();
        self.lane.budget.changed.notify_waiters();
    }

    fn retire_and_abort(&self, request: usize) {
        let abort = {
            let mut state = self.state.lock().unwrap();
            let Some(pending) = state.pending.get(&request) else {
                return;
            };
            if !pending.replay {
                if let Some(sequence) = pending.entry {
                    if let Some(entry) = state
                        .history
                        .iter_mut()
                        .find(|entry| entry.sequence == sequence)
                    {
                        entry.retired = true;
                    }
                }
            }
            state
                .pending
                .get(&request)
                .map(|pending| pending.abort.clone())
        };
        if let Some(abort) = abort {
            abort.abort();
        }
    }

    fn replay_candidate(&self, now: Instant) -> Option<(usize, Bytes)> {
        let state = self.state.lock().unwrap();
        if state.terminal.is_some() || state.reply_bytes > 0 || state.delivering {
            return None;
        }
        let replay_count = state
            .pending
            .values()
            .filter(|pending| pending.replay)
            .count();
        if replay_count >= MAX_CHANNEL_REPLAYS {
            return None;
        }
        let newest = state.history.back().map(|entry| entry.sequence);
        let mut entries = state.history.iter().collect::<Vec<_>>();
        entries.sort_by_key(|entry| {
            let overdue = entry.retired
                || entry.originals.iter().any(|id| {
                    state.pending.get(id).is_some_and(|pending| {
                        !pending.receiving
                            && pending
                                .sent_at
                                .is_some_and(|sent| now.duration_since(sent) >= REPLAY_REQUEST)
                    })
                });
            (
                !overdue,
                if overdue {
                    entry.sequence
                } else {
                    usize::MAX - entry.sequence
                },
            )
        });
        for entry in entries {
            let age = now.saturating_duration_since(entry.sent_at);
            let limit =
                if !entry.originals.is_empty() || entry.retired || newest == Some(entry.sequence) {
                    REPLAY_MAX_ATTEMPTS
                } else {
                    0
                };
            if age > REPLAY_MAX_AGE || entry.attempts >= limit || entry.pending.is_some() {
                continue;
            }
            if entry
                .last_attempt
                .is_some_and(|last| now.duration_since(last) < REPLAY_RETRY)
            {
                continue;
            }
            let receiving_original = entry.originals.iter().any(|id| {
                state
                    .pending
                    .get(id)
                    .is_some_and(|pending| pending.receiving)
            });
            if receiving_original {
                continue;
            }
            let overdue = entry.retired
                || entry.originals.iter().any(|id| {
                    state.pending.get(id).is_some_and(|pending| {
                        pending
                            .sent_at
                            .is_some_and(|sent| now.duration_since(sent) >= REPLAY_REQUEST)
                    })
                });
            if !overdue
                && (newest != Some(entry.sequence)
                    || state.pending.values().any(|pending| !pending.replay)
                    || state
                        .last_progress
                        .is_some_and(|last| now.duration_since(last) < REPLAY_IDLE))
            {
                continue;
            }
            return Some((entry.sequence, entry.body.clone()));
        }
        None
    }

    fn rotate_stale_replay(&self, now: Instant) {
        let abort = {
            let state = self.state.lock().unwrap();
            state
                .pending
                .values()
                .filter(|pending| pending.replay && !pending.receiving)
                .filter_map(|pending| pending.sent_at.map(|sent| (sent, pending.abort.clone())))
                .filter(|(sent, _)| now.duration_since(*sent) >= REPLAY_SLOT)
                .min_by_key(|(sent, _)| *sent)
                .map(|(_, abort)| abort)
        };
        if let Some(abort) = abort {
            abort.abort();
        }
    }

    async fn recover(self: Arc<Self>) {
        loop {
            tokio::select! {
                _ = sleep(REPLAY_CHECK) => {}
                _ = self.progress_changed.notified() => {}
            }
            if self.closed.load(Ordering::Acquire) {
                // The bridge's download half owns terminal delivery.  In
                // particular, it may be blocked draining an encrypted -404 to
                // the native client.  Recovery must never win the bridge
                // select merely because the channel was marked closed.
                std::future::pending::<()>().await;
            }
            let now = Instant::now();
            {
                let mut state = self.state.lock().unwrap();
                state.history.retain(|entry| {
                    !entry.originals.is_empty()
                        || entry.pending.is_some()
                        || now.saturating_duration_since(entry.sent_at) <= REPLAY_MAX_AGE
                });
                if state.history.is_empty() {
                    state.replay_key = None;
                }
            }
            let waiting = self.state.lock().unwrap().waiting_upload;
            if let Some((started, bytes)) = waiting {
                if now.duration_since(started) >= REPLAY_REQUEST {
                    self.lane.make_room(&self, bytes);
                }
            }
            self.rotate_stale_replay(now);
            if let Some((sequence, body)) = self.replay_candidate(now) {
                self.try_replay(sequence, body);
            }
        }
    }
}

struct RequestGuard {
    channel: Weak<ChannelInner>,
    request: usize,
    _channel_permit: BudgetPermit,
    _lane_permit: BudgetPermit,
    _global_permit: BudgetPermit,
}

impl Drop for RequestGuard {
    fn drop(&mut self) {
        if let Some(channel) = self.channel.upgrade() {
            channel.finish_request(self.request);
        }
    }
}

/// A native MTProto client multiplexed over a shared origin lane.
pub struct H2Channel {
    inner: Arc<ChannelInner>,
}

impl H2Channel {
    pub fn id(&self) -> usize {
        self.inner.id
    }

    pub fn host(&self) -> &str {
        &self.inner.lane.host
    }

    pub async fn receive(&self) -> io::Result<H2Reply> {
        loop {
            let changed = self.inner.terminal_changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if let Some(terminal) = self.inner.terminal() {
                return match terminal {
                    Terminal::Transport(code) => Ok(H2Reply::TransportError(code)),
                    Terminal::Error(kind, message) => Err(io::Error::new(kind, message)),
                };
            }
            let mut receiver = self.inner.receiver.lock().await;
            tokio::select! {
                biased;
                _ = changed => continue,
                reply = receiver.recv() => {
                    let Some(reply) = reply else {
                        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "H2 response channel closed"));
                    };
                    let mut state = self.inner.state.lock().unwrap();
                    if let Some(terminal) = state.terminal.take() {
                        return match terminal {
                            Terminal::Transport(code) => Ok(H2Reply::TransportError(code)),
                            Terminal::Error(kind, message) => Err(io::Error::new(kind, message)),
                        };
                    }
                    drop(state);
                    return Ok(H2Reply::Packet(reply));
                }
            }
        }
    }

    pub fn set_native_write_pending(&self, pending: bool) {
        self.inner.state.lock().unwrap().delivering = pending;
    }

    pub fn close(&self) {
        self.inner.fail(Terminal::Error(
            io::ErrorKind::ConnectionAborted,
            "H2 channel closed".into(),
        ));
    }

    async fn recover(&self) {
        self.inner.clone().recover().await
    }
}

impl Drop for H2Channel {
    fn drop(&mut self) {
        // Request tasks are detached so their individual H2 streams can run in
        // parallel.  Always abort them when the owning bridge is cancelled or
        // its Route is dropped; otherwise they retain the lane and TLS socket
        // until REQUEST_TIMEOUT.
        self.close();
    }
}

/// Shared H2 lanes.  The supplied connector must advertise only `h2` through
/// ALPN; [`Lane::connect`] also verifies the negotiated protocol.
pub struct CfH2Pool {
    connector: TlsConnector,
    stats: Arc<Stats>,
    payload_budgets: PayloadBudgets,
    connect_timeout: Duration,
    buffer_size: usize,
    lanes: AsyncMutex<HashMap<String, Arc<Lane>>>,
    all_lanes: Mutex<Vec<Arc<Lane>>>,
    lane_slots: Arc<Semaphore>,
    setup_lock: AsyncMutex<()>,
    failed_until: Mutex<HashMap<String, Instant>>,
    closed: AtomicBool,
}

impl CfH2Pool {
    pub fn new(
        connector: TlsConnector,
        connect_timeout: Duration,
        buffer_size: usize,
        stats: Arc<Stats>,
    ) -> Arc<Self> {
        Arc::new(Self {
            connector,
            stats,
            payload_budgets: PayloadBudgets::process_defaults(),
            connect_timeout,
            buffer_size,
            lanes: AsyncMutex::new(HashMap::new()),
            all_lanes: Mutex::new(Vec::new()),
            lane_slots: Arc::new(Semaphore::new(MAX_LIVE_LANES)),
            setup_lock: AsyncMutex::new(()),
            failed_until: Mutex::new(HashMap::new()),
            closed: AtomicBool::new(false),
        })
    }

    async fn cache_lane(&self, host: String, lane: Arc<Lane>) {
        let evicted = {
            let mut lanes = self.lanes.lock().await;
            let evict = if lanes.len() >= MAX_CACHED_LANES {
                lanes
                    .iter()
                    .filter(|(_, candidate)| {
                        Arc::strong_count(candidate) <= 2 && !candidate.has_live_channels()
                    })
                    .min_by_key(|(_, candidate)| candidate.last_used())
                    .map(|(host, _)| host.clone())
            } else {
                None
            };
            let evicted = evict.and_then(|host| lanes.remove(&host));
            if lanes.len() < MAX_CACHED_LANES {
                lanes.insert(host, lane);
            }
            // If every cached lane is active, leave the new lane ephemeral.
            // Its H2Channel owns it and Drop closes it after this bridge.
            evicted
        };
        if let Some(evicted) = evicted {
            let mut tasks = evicted.start_close();
            tasks.extend(evicted.settle_close().await);
            for task in tasks {
                let _ = task.await;
            }
            self.prune_tracked_lanes();
        }
    }

    fn track_lane(&self, lane: &Arc<Lane>) {
        self.prune_tracked_lanes();
        let mut lanes = self.all_lanes.lock().unwrap();
        if !lanes.iter().any(|tracked| Arc::ptr_eq(tracked, lane)) {
            lanes.push(lane.clone());
        }
    }

    fn prune_tracked_lanes(&self) {
        self.all_lanes
            .lock()
            .unwrap()
            .retain(|lane| !lane.reap_if_quiescent());
    }

    async fn reserve_lane_slot(&self) -> Option<OwnedSemaphorePermit> {
        self.prune_tracked_lanes();
        if let Ok(slot) = self.lane_slots.clone().try_acquire_owned() {
            return Some(slot);
        }
        let evicted = {
            let mut lanes = self.lanes.lock().await;
            let host = lanes
                .iter()
                .filter(|(_, lane)| Arc::strong_count(lane) <= 2 && !lane.has_live_channels())
                .min_by_key(|(_, lane)| lane.last_used())
                .map(|(host, _)| host.clone())?;
            lanes.remove(&host)?
        };
        let mut tasks = evicted.start_close();
        tasks.extend(evicted.settle_close().await);
        for task in tasks {
            let _ = task.await;
        }
        self.prune_tracked_lanes();
        drop(evicted);
        self.lane_slots.clone().try_acquire_owned().ok()
    }

    /// Open a native channel on `host`.  `Ok(None)` means the host is cooling
    /// down and the caller should immediately try its next WS fallback.
    pub async fn open(self: &Arc<Self>, host: &str) -> io::Result<Option<H2Channel>> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "H2 pool closed",
            ));
        }
        {
            let now = Instant::now();
            let mut failed = self.failed_until.lock().unwrap();
            failed.retain(|_, until| *until > now);
            if failed.contains_key(host) {
                return Ok(None);
            }
        }
        {
            let lanes = self.lanes.lock().await;
            if self.closed.load(Ordering::Acquire) {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "H2 pool closed",
                ));
            }
            if let Some(lane) = lanes.get(host).cloned() {
                if !lane.available() {
                    return Ok(None);
                }
                lane.touch();
                return Ok(Some(H2Channel {
                    inner: ChannelInner::new(lane),
                }));
            }
        }

        // Serialize cold TLS/H2 handshakes.  This deliberately trades rare
        // multi-origin setup latency for a strict CPU/RAM spike bound on small
        // routers.
        let _setup = self.setup_lock.lock().await;
        if self.closed.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "H2 pool closed",
            ));
        }
        {
            let lanes = self.lanes.lock().await;
            if let Some(lane) = lanes.get(host).cloned() {
                if !lane.available() {
                    return Ok(None);
                }
                lane.touch();
                return Ok(Some(H2Channel {
                    inner: ChannelInner::new(lane),
                }));
            }
        }
        let slot = match self.reserve_lane_slot().await {
            Some(slot) => slot,
            None => return Ok(None),
        };
        if self.closed.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "H2 pool closed",
            ));
        }
        let lane = Lane::new(
            host.to_owned(),
            self.connector.clone(),
            self.connect_timeout,
            self.buffer_size,
            self.stats.clone(),
            self.payload_budgets.clone(),
            Some(slot),
        );
        self.track_lane(&lane);
        let mut setup_guard = LaneSetupGuard::new(lane.clone());
        match timeout(SETUP_TIMEOUT, lane.preflight()).await {
            Ok(Ok(())) => {
                if self.closed.load(Ordering::Acquire) {
                    lane.close();
                    return Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "H2 pool closed",
                    ));
                }
                self.failed_until.lock().unwrap().remove(host);
                let channel = H2Channel {
                    inner: ChannelInner::new(lane),
                };
                self.cache_lane(host.to_owned(), channel.inner.lane.clone())
                    .await;
                setup_guard.disarm();
                Ok(Some(channel))
            }
            Ok(Err(error)) => {
                self.stats.h2_error();
                lane.close();
                self.failed_until
                    .lock()
                    .unwrap()
                    .insert(host.to_owned(), Instant::now() + DOMAIN_COOLDOWN);
                Err(error)
            }
            Err(_) => {
                self.stats.h2_error();
                lane.close();
                self.failed_until
                    .lock()
                    .unwrap()
                    .insert(host.to_owned(), Instant::now() + DOMAIN_COOLDOWN);
                Err(timed_out("H2 lane setup timed out"))
            }
        }
    }

    /// Stop accepting channels, abort all cached H2 work, and wait until its
    /// connection drivers and request tasks have released their sockets.
    pub async fn close(&self) {
        self.closed.store(true, Ordering::Release);
        let _setup = self.setup_lock.lock().await;
        self.failed_until.lock().unwrap().clear();
        let mut lanes = std::mem::take(&mut *self.lanes.lock().await)
            .into_values()
            .collect::<Vec<_>>();
        for lane in std::mem::take(&mut *self.all_lanes.lock().unwrap()) {
            if !lanes.iter().any(|cached| Arc::ptr_eq(cached, &lane)) {
                lanes.push(lane);
            }
        }
        let mut tasks = Vec::new();
        for lane in &lanes {
            tasks.extend(lane.start_close());
        }
        for lane in &lanes {
            tasks.extend(lane.settle_close().await);
        }
        for task in tasks {
            let _ = task.await;
        }
    }
}

fn strip_padded_body(mut body: Vec<u8>) -> io::Result<Vec<u8>> {
    if body.len() < 24 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "padded MTProto packet is too short",
        ));
    }
    let packet_length = if body[..8] == [0; 8] {
        if body.len() < 20 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "plaintext MTProto packet is too short",
            ));
        }
        20usize
            .checked_add(u32::from_le_bytes(body[16..20].try_into().unwrap()) as usize)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid MTProto length"))?
    } else {
        24 + ((body.len() - 24) / 16) * 16
    };
    if packet_length < 24 || packet_length > body.len() || body.len() - packet_length > 15 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid padded MTProto packet",
        ));
    }
    body.truncate(packet_length);
    Ok(body)
}

async fn read_exact_active<R: AsyncRead + Unpin>(
    reader: &mut R,
    mut buffer: &mut [u8],
    activity: &Activity,
) -> io::Result<()> {
    while !buffer.is_empty() {
        let read = reader.read(buffer).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "native MTProto packet ended early",
            ));
        }
        activity.touch();
        buffer = &mut buffer[read..];
    }
    Ok(())
}

async fn read_packet<R: AsyncRead + Unpin>(
    reader: &mut R,
    decrypt: &mut AesCtr,
    protocol: Protocol,
    channel: &H2Channel,
    activity: &Activity,
) -> io::Result<(Bytes, RequestCapacity)> {
    let mut header = [0; 4];
    read_exact_active(reader, &mut header[..1], activity).await?;
    decrypt.apply_keystream(&mut header[..1]);
    let header_length = framing::header_len(header[0], protocol);
    if header_length > 1 {
        read_exact_active(reader, &mut header[1..header_length], activity).await?;
        decrypt.apply_keystream(&mut header[1..header_length]);
    }
    let (_, length) = framing::packet_length(&header[..header_length], protocol)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "partial MTProto header"))?;
    let maximum = if protocol == Protocol::PaddedIntermediate {
        MAX_PADDED_PACKET
    } else {
        MAX_PACKET
    };
    if !(24..=maximum).contains(&length) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "native MTProto packet length outside H2 bound",
        ));
    }
    // Reserve both channel and shared-lane memory before allocating or reading
    // the advertised body.  A slow client can therefore never add an
    // unaccounted 4 MiB packet on top of already-full request queues.
    let capacity = channel.inner.reserve(length).await?;
    let mut body = vec![0; length];
    read_exact_active(reader, &mut body, activity).await?;
    decrypt.apply_keystream(&mut body);
    if protocol == Protocol::PaddedIntermediate {
        body = strip_padded_body(body)?;
    }
    if body.len() > MAX_PACKET || body.len() % 4 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid MTProto H2 request body",
        ));
    }
    Ok((Bytes::from(body), capacity))
}

#[cfg(test)]
fn frame_reply(body: &[u8], protocol: Protocol) -> io::Result<Vec<u8>> {
    frame_reply_with_rng(body, protocol, &mut OsRng)
}

#[cfg(test)]
fn frame_reply_with_rng<R: RngCore + ?Sized>(
    body: &[u8],
    protocol: Protocol,
    rng: &mut R,
) -> io::Result<Vec<u8>> {
    if body.is_empty() || body.len() > MAX_PACKET || body.len() % 4 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid HTTP MTProto response length",
        ));
    }
    let mut output = Vec::with_capacity(body.len() + 7);
    match protocol {
        Protocol::Abridged => {
            let words = body.len() / 4;
            if words < 0x7f {
                output.push(words as u8);
            } else if words <= 0xff_ffff {
                output.push(0x7f);
                let words = (words as u32).to_le_bytes();
                output.extend_from_slice(&words[..3]);
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "abridged MTProto response is too large",
                ));
            }
        }
        Protocol::Intermediate => output.extend_from_slice(&(body.len() as u32).to_le_bytes()),
        Protocol::PaddedIntermediate => {
            let mut random = [0; 1];
            rng.fill_bytes(&mut random);
            let padding = usize::from(random[0] & 0x0f);
            output.extend_from_slice(&((body.len() + padding) as u32).to_le_bytes());
            output.extend_from_slice(body);
            let padding_start = output.len();
            output.resize(padding_start + padding, 0);
            rng.fill_bytes(&mut output[padding_start..]);
            return Ok(output);
        }
    }
    output.extend_from_slice(body);
    Ok(output)
}

struct NativeWriteGuard<'a> {
    channel: &'a H2Channel,
}

async fn write_all_active<W: AsyncWrite + Unpin>(
    writer: &mut W,
    mut buffer: &[u8],
    activity: &Activity,
) -> io::Result<()> {
    while !buffer.is_empty() {
        let written = writer.write(buffer).await?;
        if written == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "native MTProto write made no progress",
            ));
        }
        activity.touch();
        buffer = &buffer[written..];
    }
    Ok(())
}

async fn write_encrypted_reply<'a, W, I>(
    writer: &mut W,
    encrypt: &mut AesCtr,
    body_length: usize,
    parts: I,
    protocol: Protocol,
    buffer_size: usize,
    activity: &Activity,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
    I: IntoIterator<Item = &'a [u8]>,
{
    if body_length == 0 || body_length > MAX_PACKET || body_length % 4 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid HTTP MTProto response length",
        ));
    }

    let mut prefix = [0_u8; 4];
    let mut padding = [0_u8; 15];
    let (prefix_length, padding_length) = match protocol {
        Protocol::Abridged => {
            let words = body_length / 4;
            if words < 0x7f {
                prefix[0] = words as u8;
                (1, 0)
            } else if words <= 0xff_ffff {
                prefix[0] = 0x7f;
                prefix[1..].copy_from_slice(&(words as u32).to_le_bytes()[..3]);
                (4, 0)
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "abridged MTProto response is too large",
                ));
            }
        }
        Protocol::Intermediate => {
            prefix.copy_from_slice(&(body_length as u32).to_le_bytes());
            (4, 0)
        }
        Protocol::PaddedIntermediate => {
            let mut random = [0_u8; 1];
            OsRng.fill_bytes(&mut random);
            let padding_length = usize::from(random[0] & 0x0f);
            prefix.copy_from_slice(&((body_length + padding_length) as u32).to_le_bytes());
            OsRng.fill_bytes(&mut padding[..padding_length]);
            (4, padding_length)
        }
    };

    encrypt.apply_keystream(&mut prefix[..prefix_length]);
    write_all_active(writer, &prefix[..prefix_length], activity).await?;

    let chunk_size = buffer_size.max(1).min(body_length);
    let mut encrypted = vec![0_u8; chunk_size];
    for part in parts {
        for chunk in part.chunks(chunk_size) {
            encrypted[..chunk.len()].copy_from_slice(chunk);
            encrypt.apply_keystream(&mut encrypted[..chunk.len()]);
            write_all_active(writer, &encrypted[..chunk.len()], activity).await?;
        }
    }
    if padding_length > 0 {
        encrypt.apply_keystream(&mut padding[..padding_length]);
        write_all_active(writer, &padding[..padding_length], activity).await?;
    }
    writer.flush().await
}

impl Drop for NativeWriteGuard<'_> {
    fn drop(&mut self) {
        self.channel.set_native_write_pending(false);
    }
}

async fn upload<R: AsyncRead + Unpin>(
    reader: &mut R,
    channel: &H2Channel,
    mut decrypt: AesCtr,
    protocol: Protocol,
    stats: &Stats,
    activity: Arc<Activity>,
) -> io::Result<()> {
    loop {
        let (body, capacity) =
            read_packet(reader, &mut decrypt, protocol, channel, &activity).await?;
        stats.add_up(body.len());
        channel.inner.send_reserved(body, capacity)?;
    }
}

async fn download<W: AsyncWrite + Unpin>(
    writer: &mut W,
    channel: &H2Channel,
    mut encrypt: AesCtr,
    protocol: Protocol,
    stats: &Stats,
    activity: Arc<Activity>,
) -> io::Result<()> {
    loop {
        let reply = channel.receive().await?;
        activity.touch();
        channel.set_native_write_pending(true);
        let _guard = NativeWriteGuard { channel };
        let (length, terminal) = match &reply {
            H2Reply::Packet(reply) => {
                write_encrypted_reply(
                    writer,
                    &mut encrypt,
                    reply.len(),
                    reply.chunks(),
                    protocol,
                    channel.inner.lane.buffer_size,
                    &activity,
                )
                .await?;
                (reply.len(), false)
            }
            H2Reply::TransportError(code) => {
                let body = code.to_le_bytes();
                write_encrypted_reply(
                    writer,
                    &mut encrypt,
                    body.len(),
                    std::iter::once(body.as_slice()),
                    protocol,
                    channel.inner.lane.buffer_size,
                    &activity,
                )
                .await?;
                (body.len(), true)
            }
        };
        stats.add_down(length);
        channel.inner.progress();
        if terminal {
            return Ok(());
        }
    }
}

/// Bridge one already-authenticated native client through an H2 channel.
///
/// No relay handshake is sent: `/api` receives complete decrypted native
/// MTProto packet bodies, while replies are framed and encrypted directly for
/// the original client.
pub async fn bridge_h2<C: AsyncRead + AsyncWrite + Unpin>(
    client: &mut C,
    channel: H2Channel,
    context: CryptoContext,
    protocol: Protocol,
    stats: Arc<Stats>,
    idle_timeout: Duration,
) -> io::Result<()> {
    let (mut reader, mut writer) = tokio::io::split(client);
    let CryptoContext {
        client_decrypt,
        client_encrypt,
        upstream_encrypt: _,
        upstream_decrypt: _,
    } = context;
    let activity = Activity::new();
    let result = tokio::select! {
        // A transport terminal is an MTProto reply that must reach the native
        // client.  fail() can also wake a blocked upload, so always poll the
        // download owner first when both halves become ready together.
        biased;
        result = download(&mut writer, &channel, client_encrypt, protocol, &stats, activity.clone()) => result,
        result = async {
            let result = upload(
                &mut reader,
                &channel,
                client_decrypt,
                protocol,
                &stats,
                activity.clone(),
            )
            .await;
            if channel.inner.closed.load(Ordering::Acquire) {
                // fail() wakes capacity waiters and makes send_reserved fail.
                // Once a terminal exists, upload must not cancel a native
                // terminal write that is still blocked on backpressure.
                std::future::pending::<io::Result<()>>().await
            } else {
                result
            }
        } => result,
        _ = channel.recover() => unreachable!("H2 recovery is bridge-scoped"),
        _ = activity.expired(idle_timeout) => Err(timed_out("proxy idle timeout")),
    };
    channel.close();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use ctr::cipher::KeyIvInit;
    use h2::server::SendResponse;
    use http::Response;
    use rand::rngs::mock::StepRng;
    use tokio::{io::DuplexStream, task::JoinHandle};

    fn connector() -> TlsConnector {
        native_tls::TlsConnector::builder().build().unwrap().into()
    }

    fn lane_with_budgets(
        host: &str,
        request_budget: Arc<Budget>,
        reply_budget: Arc<Budget>,
        history_budget: Arc<Budget>,
    ) -> Arc<Lane> {
        Lane::new(
            host.into(),
            connector(),
            Duration::from_secs(1),
            16 * 1024,
            Arc::new(Stats::default()),
            PayloadBudgets {
                requests: request_budget,
                replies: reply_budget,
                history: history_budget,
            },
            None,
        )
    }

    fn bare_lane(host: &str) -> Arc<Lane> {
        lane_with_budgets(
            host,
            Budget::new(usize::MAX, MAX_GLOBAL_REQUEST_BYTES),
            Budget::new(usize::MAX, MAX_GLOBAL_REPLY_BYTES),
            Budget::new(usize::MAX, MAX_GLOBAL_HISTORY_BYTES),
        )
    }

    fn test_cipher() -> AesCtr {
        let key = [0_u8; 32];
        let iv = [0_u8; 16];
        AesCtr::new(&key.into(), &iv.into())
    }

    fn test_context() -> CryptoContext {
        CryptoContext {
            client_decrypt: test_cipher(),
            client_encrypt: test_cipher(),
            upstream_encrypt: test_cipher(),
            upstream_decrypt: test_cipher(),
        }
    }

    struct TestRequest {
        method: Method,
        body: Bytes,
        respond: SendResponse<Bytes>,
    }

    async fn test_lane_with_payload_budgets(
        payload_budgets: PayloadBudgets,
    ) -> (Arc<Lane>, mpsc::Receiver<TestRequest>, JoinHandle<()>) {
        let (client_io, server_io) = tokio::io::duplex(8 * 1024 * 1024);
        let mut builder = h2::client::Builder::new();
        builder
            .initial_window_size(STREAM_RECEIVE_WINDOW)
            .initial_connection_window_size(CONNECTION_RECEIVE_WINDOW)
            .max_header_list_size(MAX_HEADER_LIST_SIZE)
            .enable_push(false);
        let (sender, connection) = builder.handshake(client_io).await.unwrap();
        let driver = tokio::spawn(async move {
            connection.await.unwrap();
        });
        let lane = Lane::new(
            "kws2.example.test".into(),
            connector(),
            Duration::from_secs(1),
            16 * 1024,
            Arc::new(Stats::default()),
            payload_budgets,
            None,
        );
        {
            let mut state = lane.connection.lock().unwrap();
            state.generation = 1;
            state.sender = Some(sender);
            state.driver = Some(driver);
        }
        let (requests, receiver) = mpsc::channel(16);
        let server = tokio::spawn(run_test_server(server_io, requests));
        (lane, receiver, server)
    }

    async fn test_lane() -> (Arc<Lane>, mpsc::Receiver<TestRequest>, JoinHandle<()>) {
        test_lane_with_payload_budgets(PayloadBudgets {
            requests: Budget::new(usize::MAX, MAX_GLOBAL_REQUEST_BYTES),
            replies: Budget::new(usize::MAX, MAX_GLOBAL_REPLY_BYTES),
            history: Budget::new(usize::MAX, MAX_GLOBAL_HISTORY_BYTES),
        })
        .await
    }

    async fn run_test_server(io: DuplexStream, requests: mpsc::Sender<TestRequest>) {
        let mut connection = h2::server::handshake(io).await.unwrap();
        while let Some(request) = connection.accept().await {
            let (request, respond) = request.unwrap();
            let requests = requests.clone();
            tokio::spawn(async move {
                let (parts, mut stream) = request.into_parts();
                let mut body = BytesMut::new();
                while let Some(chunk) = stream.data().await {
                    let chunk = chunk.unwrap();
                    body.extend_from_slice(&chunk);
                    stream.flow_control().release_capacity(chunk.len()).unwrap();
                }
                requests
                    .send(TestRequest {
                        method: parts.method,
                        body: body.freeze(),
                        respond,
                    })
                    .await
                    .unwrap();
            });
        }
    }

    fn respond(mut request: TestRequest, status: u16, body: &'static [u8]) {
        let response = Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header(header::CONTENT_LENGTH, body.len())
            .body(())
            .unwrap();
        let mut stream = request
            .respond
            .send_response(response, body.is_empty())
            .unwrap();
        if !body.is_empty() {
            stream.send_data(Bytes::from_static(body), true).unwrap();
        }
    }

    async fn send(channel: &H2Channel, body: Bytes) {
        let capacity = channel.inner.reserve(body.len()).await.unwrap();
        channel.inner.send_reserved(body, capacity).unwrap();
    }

    #[test]
    fn reply_framing_preserves_transport_errors() {
        let error = (-404_i32).to_le_bytes();
        assert_eq!(
            frame_reply(&error, Protocol::Abridged).unwrap(),
            [vec![1], error.to_vec()].concat()
        );
        assert_eq!(
            frame_reply(&error, Protocol::Intermediate).unwrap(),
            [vec![4, 0, 0, 0], error.to_vec()].concat()
        );
        let padded = frame_reply(&error, Protocol::PaddedIntermediate).unwrap();
        let length = u32::from_le_bytes(padded[..4].try_into().unwrap()) as usize;
        assert_eq!(length, padded.len() - 4);
        assert_eq!(&padded[4..8], &error);
        assert!(length <= 19);

        let mut rng = StepRng::new(3, 0);
        let padded = frame_reply_with_rng(&error, Protocol::PaddedIntermediate, &mut rng).unwrap();
        assert_eq!(u32::from_le_bytes(padded[..4].try_into().unwrap()), 7);
        assert_eq!(&padded[8..], &[3, 0, 0]);
    }

    #[test]
    fn padded_packets_strip_zero_through_fifteen_bytes() {
        let plaintext = [
            vec![0; 8],
            vec![b'm'; 8],
            20_u32.to_le_bytes().to_vec(),
            vec![b'p'; 20],
        ]
        .concat();
        let ciphertext = [vec![b'k'; 8], vec![b'm'; 16], vec![b'c'; 32]].concat();
        for padding in 0..16 {
            let mut wire = plaintext.clone();
            wire.resize(wire.len() + padding, b'z');
            assert_eq!(strip_padded_body(wire).unwrap(), plaintext);
            let mut wire = ciphertext.clone();
            wire.resize(wire.len() + padding, b'z');
            assert_eq!(strip_padded_body(wire).unwrap(), ciphertext);
        }
    }

    #[tokio::test]
    async fn budget_waits_and_releases_both_limits() {
        let budget = Budget::new(1, 40);
        let permit = budget.try_acquire(40).unwrap();
        assert!(budget.try_acquire(1).is_none());
        let waiting = tokio::spawn({
            let budget = budget.clone();
            async move { budget.acquire(20, Duration::from_secs(1)).await.unwrap() }
        });
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        drop(permit);
        drop(waiting.await.unwrap());
        assert!(budget.has_capacity(40));
    }

    #[tokio::test]
    async fn activity_deadline_resets_without_lost_wakeup() {
        let activity = Activity::new();
        let expired = tokio::spawn({
            let activity = activity.clone();
            async move { activity.expired(Duration::from_millis(60)).await }
        });
        sleep(Duration::from_millis(40)).await;
        activity.touch();
        sleep(Duration::from_millis(40)).await;
        assert!(!expired.is_finished());
        timeout(Duration::from_millis(50), expired)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn partial_native_writes_refresh_the_shared_idle_clock() {
        let activity = Activity::new();
        let (writer, mut reader) = tokio::io::duplex(1);
        let write = tokio::spawn({
            let activity = activity.clone();
            async move {
                let mut writer = writer;
                let body = [b'x'; 24];
                write_encrypted_reply(
                    &mut writer,
                    &mut test_cipher(),
                    body.len(),
                    std::iter::once(body.as_slice()),
                    Protocol::Intermediate,
                    8,
                    &activity,
                )
                .await
            }
        });
        let expired = tokio::spawn({
            let activity = activity.clone();
            async move { activity.expired(Duration::from_millis(80)).await }
        });
        let mut wire = [0_u8; 28];
        for byte in &mut wire {
            sleep(Duration::from_millis(20)).await;
            reader.read_exact(std::slice::from_mut(byte)).await.unwrap();
            assert!(!expired.is_finished());
        }
        write.await.unwrap().unwrap();
        assert!(!expired.is_finished());
        expired.abort();
    }

    #[tokio::test]
    async fn process_budgets_allow_two_max_requests_and_two_max_replies() {
        let request_budget = Budget::new(usize::MAX, MAX_GLOBAL_REQUEST_BYTES);
        let reply_budget = Budget::new(usize::MAX, MAX_GLOBAL_REPLY_BYTES);
        let history_budget = Budget::new(usize::MAX, MAX_GLOBAL_HISTORY_BYTES);
        let first_lane = lane_with_budgets(
            "global-one.example.test",
            request_budget.clone(),
            reply_budget.clone(),
            history_budget.clone(),
        );
        let second_lane = lane_with_budgets(
            "global-two.example.test",
            request_budget.clone(),
            reply_budget.clone(),
            history_budget,
        );
        let first = H2Channel {
            inner: ChannelInner::new(first_lane.clone()),
        };
        let second = H2Channel {
            inner: ChannelInner::new(second_lane.clone()),
        };
        let first_request = first.inner.reserve(MAX_PADDED_PACKET).await.unwrap();
        let second_request = second.inner.reserve(MAX_PADDED_PACKET).await.unwrap();
        assert!(!request_budget.has_capacity(1));

        let first_reply = first_lane.charge_reply(MAX_PACKET).unwrap();
        let second_reply = second_lane.charge_reply(MAX_PACKET).unwrap();
        assert!(!reply_budget.has_capacity(1));
        assert!(first_lane.charge_reply(1).is_err());

        drop((first_reply, second_reply, first_request, second_request));
        assert!(request_budget.has_capacity(MAX_GLOBAL_REQUEST_BYTES));
        assert!(reply_budget.has_capacity(MAX_GLOBAL_REPLY_BYTES));
    }

    #[tokio::test]
    async fn process_request_count_blocks_the_sixty_fifth_small_request() {
        let budgets = PayloadBudgets::process_defaults();
        let mut channels = Vec::new();
        let mut permits = Vec::new();
        for index in 0..8 {
            let lane = Lane::new(
                format!("request-count-{index}.example.test"),
                connector(),
                Duration::from_secs(1),
                4096,
                Arc::new(Stats::default()),
                budgets.clone(),
                None,
            );
            let channel = H2Channel {
                inner: ChannelInner::new(lane),
            };
            for _ in 0..MAX_CHANNEL_REQUESTS {
                permits.push(channel.inner.reserve(1).await.unwrap());
            }
            channels.push(channel);
        }
        assert_eq!(budgets.requests.state.lock().unwrap().requests, 64);

        let extra_lane = Lane::new(
            "request-count-extra.example.test".into(),
            connector(),
            Duration::from_secs(1),
            4096,
            Arc::new(Stats::default()),
            budgets.clone(),
            None,
        );
        let extra = H2Channel {
            inner: ChannelInner::new(extra_lane),
        };
        assert!(timeout(Duration::from_millis(30), extra.inner.reserve(1))
            .await
            .is_err());

        drop(permits);
        let released = timeout(Duration::from_millis(100), extra.inner.reserve(1))
            .await
            .unwrap()
            .unwrap();
        drop((released, extra, channels));
        assert_eq!(budgets.requests.state.lock().unwrap().requests, 0);
    }

    #[tokio::test]
    async fn saturated_replay_history_does_not_block_new_requests() {
        let request_budget = Budget::new(usize::MAX, MAX_GLOBAL_REQUEST_BYTES);
        let history_budget = Budget::new(usize::MAX, MAX_GLOBAL_HISTORY_BYTES);
        let history = history_budget
            .try_acquire(MAX_GLOBAL_HISTORY_BYTES)
            .unwrap();
        let lane = lane_with_budgets(
            "history-full.example.test",
            request_budget.clone(),
            Budget::new(usize::MAX, MAX_GLOBAL_REPLY_BYTES),
            history_budget,
        );
        let channel = H2Channel {
            inner: ChannelInner::new(lane),
        };
        let request = timeout(Duration::from_millis(50), channel.inner.reserve(MAX_PACKET))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(request_budget.state.lock().unwrap().bytes, MAX_PACKET);
        drop((request, history));
        assert!(request_budget.has_capacity(MAX_GLOBAL_REQUEST_BYTES));
    }

    #[tokio::test]
    async fn close_between_reserve_and_launch_releases_capacity() {
        let lane = bare_lane("closed.example.test");
        let channel = H2Channel {
            inner: ChannelInner::new(lane.clone()),
        };
        let body = Bytes::from_static(b"closegapxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
        let capacity = channel.inner.reserve(body.len()).await.unwrap();
        channel.close();
        let error = channel.inner.send_reserved(body, capacity).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert!(channel.inner.state.lock().unwrap().pending.is_empty());
        assert!(channel.inner.budget.has_capacity(MAX_CHANNEL_BYTES));
        assert!(lane.budget.has_capacity(MAX_LANE_BYTES));
    }

    #[tokio::test]
    async fn stalled_packet_body_times_out_and_releases_capacity() {
        let lane = bare_lane("stalled.example.test");
        let channel = H2Channel {
            inner: ChannelInner::new(lane.clone()),
        };
        let inner = channel.inner.clone();
        let (proxy, mut peer) = tokio::io::duplex(64);
        let bridge = tokio::spawn(async move {
            let mut proxy = proxy;
            bridge_h2(
                &mut proxy,
                channel,
                test_context(),
                Protocol::Intermediate,
                Arc::new(Stats::default()),
                Duration::from_millis(40),
            )
            .await
        });

        let mut header = (40_u32).to_le_bytes();
        test_cipher().apply_keystream(&mut header);
        peer.write_all(&header).await.unwrap();
        timeout(Duration::from_secs(1), async {
            loop {
                if inner.budget.state.lock().unwrap().requests == 1 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let error = bridge.await.unwrap().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(inner.budget.has_capacity(MAX_CHANNEL_BYTES));
        assert!(lane.budget.has_capacity(MAX_LANE_BYTES));
    }

    #[tokio::test]
    async fn terminal_error_waits_for_backpressured_native_write() {
        let lane = bare_lane("backpressure.example.test");
        let channel = H2Channel {
            inner: ChannelInner::new(lane),
        };
        channel.inner.fail(Terminal::Transport(-404));
        let (proxy, peer) = tokio::io::duplex(1);
        let (mut peer_read, mut peer_write) = tokio::io::split(peer);
        let mut pipelined = (40_u32).to_le_bytes();
        test_cipher().apply_keystream(&mut pipelined);
        let pipelined_write = tokio::spawn(async move { peer_write.write_all(&pipelined).await });
        let bridge = tokio::spawn(async move {
            let mut proxy = proxy;
            bridge_h2(
                &mut proxy,
                channel,
                test_context(),
                Protocol::Intermediate,
                Arc::new(Stats::default()),
                Duration::from_secs(1),
            )
            .await
        });
        // Upload consumes the already-pipelined header and observes the closed
        // channel before allocating its body, while the one-byte native output
        // is still backpressured.
        // It must stay pending so download can finish the -404 reply.
        timeout(Duration::from_secs(1), pipelined_write)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(!bridge.is_finished());

        let mut wire = [0_u8; 8];
        timeout(Duration::from_secs(1), peer_read.read_exact(&mut wire))
            .await
            .unwrap()
            .unwrap();
        test_cipher().apply_keystream(&mut wire);
        assert_eq!(&wire[..4], &4_u32.to_le_bytes());
        assert_eq!(&wire[4..], &(-404_i32).to_le_bytes());
        bridge.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn transport_terminal_beats_ready_pipelined_upload() {
        let lane = bare_lane("terminal-priority.example.test");
        let channel = H2Channel {
            inner: ChannelInner::new(lane),
        };
        channel.inner.fail(Terminal::Transport(-404));
        let (proxy, mut peer) = tokio::io::duplex(128);

        // Make upload ready to fail at the same time as terminal download: a
        // full next native packet is already waiting, but the closed channel
        // will reject it after decryption.  The transport reply still wins.
        let mut pipelined = [(40_u32).to_le_bytes().as_slice(), &[b'x'; 40]].concat();
        test_cipher().apply_keystream(&mut pipelined);
        peer.write_all(&pipelined).await.unwrap();
        let bridge = tokio::spawn(async move {
            let mut proxy = proxy;
            bridge_h2(
                &mut proxy,
                channel,
                test_context(),
                Protocol::Intermediate,
                Arc::new(Stats::default()),
                Duration::from_secs(1),
            )
            .await
        });

        let mut wire = [0_u8; 8];
        timeout(Duration::from_secs(1), peer.read_exact(&mut wire))
            .await
            .unwrap()
            .unwrap();
        test_cipher().apply_keystream(&mut wire);
        assert_eq!(&wire[..4], &4_u32.to_le_bytes());
        assert_eq!(&wire[4..], &(-404_i32).to_le_bytes());
        bridge.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn global_reply_limit_survives_dequeue_across_channels() {
        let lane = bare_lane("reply-bound.example.test");
        let first = H2Channel {
            inner: ChannelInner::new(lane.clone()),
        };
        let second = H2Channel {
            inner: ChannelInner::new(lane.clone()),
        };
        for channel in [&first, &second] {
            let charge = lane.charge_reply(MAX_GLOBAL_REPLY_BYTES / 2).unwrap();
            channel.inner.deliver(BufferedReply {
                parts: vec![Bytes::from_static(b"body")],
                length: 4,
                _lane_charge: charge,
                _channel_charge: None,
            });
        }
        let received = first.receive().await.unwrap();
        assert!(lane.charge_reply(1).is_err());
        assert_eq!(first.inner.state.lock().unwrap().reply_bytes, 4);
        drop(received);
        assert_eq!(first.inner.state.lock().unwrap().reply_bytes, 0);
        assert!(lane.charge_reply(MAX_GLOBAL_REPLY_BYTES / 2).is_ok());
    }

    #[tokio::test]
    async fn chunked_reply_extends_one_global_count_slot() {
        let budgets = PayloadBudgets::process_defaults();
        let (lane, mut requests, server) = test_lane_with_payload_budgets(budgets.clone()).await;
        let held = (0..MAX_GLOBAL_REPLIES - 1)
            .map(|_| lane.charge_reply(1).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(budgets.replies.state.lock().unwrap().requests, 63);

        let channel = H2Channel {
            inner: ChannelInner::new(lane.clone()),
        };
        send(
            &channel,
            Bytes::from_static(b"chunked!xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
        )
        .await;
        let mut request = requests.recv().await.unwrap();
        let response = Response::builder()
            .status(200)
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .body(())
            .unwrap();
        let mut stream = request.respond.send_response(response, false).unwrap();
        stream
            .send_data(Bytes::from_static(b"aaaa"), false)
            .unwrap();
        stream.send_data(Bytes::from_static(b"bbbb"), true).unwrap();

        let reply = channel.receive().await.unwrap();
        let H2Reply::Packet(reply) = reply else {
            panic!("unexpected transport error");
        };
        assert_eq!(
            reply.chunks().flatten().copied().collect::<Vec<_>>(),
            b"aaaabbbb"
        );
        assert_eq!(budgets.replies.state.lock().unwrap().requests, 64);
        assert!(lane.charge_reply(1).is_err());

        drop(reply);
        let released = lane.charge_reply(1).unwrap();
        drop((released, held));
        assert_eq!(budgets.replies.state.lock().unwrap().requests, 0);
        channel.close();
        lane.close();
        server.abort();
    }

    #[tokio::test]
    async fn lane_cache_evicts_oldest_idle_but_keeps_active_lanes() {
        let pool = CfH2Pool::new(
            connector(),
            Duration::from_secs(1),
            4096,
            Arc::new(Stats::default()),
        );
        let base = Instant::now();
        let mut lanes = Vec::new();
        for index in 0..MAX_CACHED_LANES {
            let lane = bare_lane(&format!("cached-{index}.example.test"));
            lanes.push(Arc::downgrade(&lane));
            pool.lanes.lock().await.insert(lane.host.clone(), lane);
        }
        let oldest = lanes[0].upgrade().unwrap();
        let active_oldest = H2Channel {
            inner: ChannelInner::new(oldest.clone()),
        };
        for (index, lane) in lanes.iter().filter_map(Weak::upgrade).enumerate() {
            *lane.last_used.lock().unwrap() = base + Duration::from_secs(index as u64);
        }
        let replacement = bare_lane("replacement.example.test");
        pool.cache_lane(replacement.host.clone(), replacement.clone())
            .await;
        let cached = pool.lanes.lock().await;
        assert_eq!(cached.len(), MAX_CACHED_LANES);
        assert!(cached.contains_key(&oldest.host));
        assert!(!cached.contains_key("cached-1.example.test"));
        assert!(cached.contains_key(&replacement.host));
        drop(cached);
        assert!(lanes[1].upgrade().is_none());

        let mut active = vec![active_oldest];
        let cached_lanes = pool
            .lanes
            .lock()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for lane in cached_lanes {
            if !Arc::ptr_eq(&lane, &oldest) {
                active.push(H2Channel {
                    inner: ChannelInner::new(lane),
                });
            }
        }
        let ephemeral = bare_lane("ephemeral.example.test");
        let ephemeral_channel = H2Channel {
            inner: ChannelInner::new(ephemeral.clone()),
        };
        pool.cache_lane(ephemeral.host.clone(), ephemeral.clone())
            .await;
        assert_eq!(pool.lanes.lock().await.len(), MAX_CACHED_LANES);
        assert!(!pool.lanes.lock().await.contains_key(&ephemeral.host));
        assert!(!ephemeral.closed.load(Ordering::Acquire));
        drop(ephemeral_channel);
        drop(active);
    }

    #[tokio::test]
    async fn live_lane_admission_evicts_idle_and_rejects_when_all_active() {
        let pool = CfH2Pool::new(
            connector(),
            Duration::from_secs(1),
            4096,
            Arc::new(Stats::default()),
        );
        let mut channels = Vec::new();
        for index in 0..MAX_LIVE_LANES {
            let slot = pool.lane_slots.clone().try_acquire_owned().unwrap();
            let lane = Lane::new(
                format!("live-{index}.example.test"),
                connector(),
                Duration::from_secs(1),
                4096,
                pool.stats.clone(),
                pool.payload_budgets.clone(),
                Some(slot),
            );
            pool.track_lane(&lane);
            pool.lanes
                .lock()
                .await
                .insert(lane.host.clone(), lane.clone());
            channels.push(H2Channel {
                inner: ChannelInner::new(lane),
            });
        }
        assert_eq!(pool.lane_slots.available_permits(), 0);
        assert!(pool.reserve_lane_slot().await.is_none());

        let released = channels.pop().unwrap();
        let released_host = released.host().to_owned();
        drop(released);
        let slot = pool.reserve_lane_slot().await.unwrap();
        assert!(!pool.lanes.lock().await.contains_key(&released_host));
        assert_eq!(pool.lane_slots.available_permits(), 0);
        drop(slot);
        assert_eq!(pool.lane_slots.available_permits(), 1);
        drop(channels);
        pool.close().await;
    }

    #[tokio::test]
    async fn tracked_idle_cache_evicts_oldest_lane_and_admits_replacement() {
        let pool = CfH2Pool::new(
            connector(),
            Duration::from_secs(1),
            4096,
            Arc::new(Stats::default()),
        );
        let base = Instant::now();
        let mut old_lanes = Vec::new();
        for index in 0..MAX_LIVE_LANES {
            let slot = pool.lane_slots.clone().try_acquire_owned().unwrap();
            let lane = Lane::new(
                format!("tracked-idle-{index}.example.test"),
                connector(),
                Duration::from_secs(1),
                4096,
                pool.stats.clone(),
                pool.payload_budgets.clone(),
                Some(slot),
            );
            *lane.last_used.lock().unwrap() = base + Duration::from_secs(index as u64);
            old_lanes.push(Arc::downgrade(&lane));
            pool.track_lane(&lane);
            pool.lanes.lock().await.insert(lane.host.clone(), lane);
        }
        assert_eq!(pool.lane_slots.available_permits(), 0);

        let slot = pool.reserve_lane_slot().await.unwrap();
        assert!(old_lanes[0].upgrade().is_none());
        assert_eq!(pool.lanes.lock().await.len(), MAX_CACHED_LANES - 1);
        let replacement = Lane::new(
            "tracked-idle-replacement.example.test".into(),
            connector(),
            Duration::from_secs(1),
            4096,
            pool.stats.clone(),
            pool.payload_budgets.clone(),
            Some(slot),
        );
        pool.track_lane(&replacement);
        pool.cache_lane(replacement.host.clone(), replacement.clone())
            .await;
        drop(replacement);
        assert_eq!(pool.lanes.lock().await.len(), MAX_CACHED_LANES);
        assert!(pool
            .lanes
            .lock()
            .await
            .contains_key("tracked-idle-replacement.example.test"));
        pool.close().await;
    }

    #[tokio::test]
    async fn preflight_and_posts_share_one_lane_and_transport_error_is_local() {
        let (lane, mut requests, server) = test_lane().await;
        let preflight = tokio::spawn({
            let lane = lane.clone();
            async move { lane.preflight().await }
        });
        let request = requests.recv().await.unwrap();
        assert_eq!(request.method, Method::HEAD);
        assert!(request.body.is_empty());
        respond(request, 200, b"");
        preflight.await.unwrap().unwrap();

        let failed = H2Channel {
            inner: ChannelInner::new(lane.clone()),
        };
        let healthy = H2Channel {
            inner: ChannelInner::new(lane.clone()),
        };
        send(
            &failed,
            Bytes::from_static(b"deadbeefxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
        )
        .await;
        let request = requests.recv().await.unwrap();
        assert_eq!(request.method, Method::POST);
        assert_eq!(&request.body[..8], b"deadbeef");
        respond(request, 404, b"<html>ignored</html>");
        assert!(matches!(
            failed.receive().await.unwrap(),
            H2Reply::TransportError(-404)
        ));
        assert!(lane.available());

        send(
            &healthy,
            Bytes::from_static(b"livekey!yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy"),
        )
        .await;
        let request = requests.recv().await.unwrap();
        assert_eq!(&request.body[..8], b"livekey!");
        respond(request, 200, b"rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr");
        match healthy.receive().await.unwrap() {
            H2Reply::Packet(reply) => {
                let body = reply.chunks().flatten().copied().collect::<Vec<_>>();
                assert_eq!(body, b"rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr")
            }
            H2Reply::TransportError(code) => panic!("unexpected transport error {code}"),
        }
        let counters = lane.stats.snapshot();
        assert_eq!(counters["h2_requests"], 2);
        assert_eq!(counters["h2_errors"], 1);

        failed.close();
        healthy.close();
        lane.close();
        server.abort();
    }

    #[tokio::test]
    async fn encoded_response_is_rejected_without_buffering_its_body() {
        let (lane, mut requests, server) = test_lane().await;
        let channel = H2Channel {
            inner: ChannelInner::new(lane.clone()),
        };
        send(
            &channel,
            Bytes::from_static(b"encodingxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
        )
        .await;
        let mut request = requests.recv().await.unwrap();
        let response = Response::builder()
            .status(200)
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header(header::CONTENT_ENCODING, "gzip")
            .header(header::CONTENT_LENGTH, 40)
            .body(())
            .unwrap();
        request.respond.send_response(response, false).unwrap();
        let error = channel.receive().await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(!lane.available());
        channel.close();
        lane.close();
        server.abort();
    }

    #[tokio::test]
    async fn oversized_response_headers_fail_the_route() {
        let (lane, mut requests, server) = test_lane().await;
        let channel = H2Channel {
            inner: ChannelInner::new(lane.clone()),
        };
        send(
            &channel,
            Bytes::from_static(b"headers!xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
        )
        .await;
        let mut request = requests.recv().await.unwrap();
        let response = Response::builder()
            .status(200)
            .header(
                "x-oversized",
                "x".repeat(MAX_HEADER_LIST_SIZE as usize + 1024),
            )
            .body(())
            .unwrap();
        let _ = request.respond.send_response(response, true);
        let result = timeout(Duration::from_secs(1), channel.receive())
            .await
            .unwrap();
        assert!(result.is_err());
        assert!(!lane.available());
        channel.close();
        lane.close();
        server.abort();
    }

    #[tokio::test]
    async fn idle_recovery_replays_the_same_packet_on_the_shared_lane() {
        let (lane, mut requests, server) = test_lane().await;
        let channel = H2Channel {
            inner: ChannelInner::new(lane.clone()),
        };
        let recovery = tokio::spawn(channel.inner.clone().recover());
        let body = Bytes::from_static(b"replay01xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
        send(&channel, body.clone()).await;
        let original = requests.recv().await.unwrap();
        assert_eq!(original.body, body);
        respond(original, 200, b"");

        let replay = timeout(Duration::from_secs(2), requests.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(replay.body, body);
        respond(replay, 200, b"");
        timeout(Duration::from_secs(1), async {
            loop {
                if channel.inner.state.lock().unwrap().pending.is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(channel.inner.budget.has_capacity(MAX_CHANNEL_BYTES));
        assert!(lane.budget.has_capacity(MAX_LANE_BYTES));
        assert!(channel.inner.state.lock().unwrap().history.len() <= REPLAY_HISTORY_PACKETS);
        channel.close();
        recovery.abort();
        lane.close();
        server.abort();
    }

    #[tokio::test]
    async fn dropping_channel_cleans_pending_and_budgets() {
        let (lane, _requests, server) = test_lane().await;
        let channel = H2Channel {
            inner: ChannelInner::new(lane.clone()),
        };
        send(
            &channel,
            Bytes::from_static(b"cancelmezzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"),
        )
        .await;
        let inner = channel.inner.clone();
        drop(channel);
        for _ in 0..10 {
            if inner.state.lock().unwrap().pending.is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(inner.state.lock().unwrap().pending.is_empty());
        assert!(inner.budget.has_capacity(MAX_CHANNEL_BYTES));
        assert!(lane.budget.has_capacity(MAX_LANE_BYTES));
        lane.close();
        server.abort();
    }

    #[tokio::test]
    async fn pool_close_awaits_tasks_on_ninth_ephemeral_lane() {
        let (lane, mut requests, server) = test_lane().await;
        let pool = CfH2Pool::new(
            connector(),
            Duration::from_secs(1),
            4096,
            Arc::new(Stats::default()),
        );
        let mut pinned = Vec::new();
        for index in 0..MAX_CACHED_LANES {
            let cached = bare_lane(&format!("pinned-{index}.example.test"));
            pool.track_lane(&cached);
            pool.lanes
                .lock()
                .await
                .insert(cached.host.clone(), cached.clone());
            pinned.push(H2Channel {
                inner: ChannelInner::new(cached),
            });
        }
        pool.track_lane(&lane);
        let channel = H2Channel {
            inner: ChannelInner::new(lane.clone()),
        };
        pool.cache_lane(lane.host.clone(), lane.clone()).await;
        assert!(!pool.lanes.lock().await.contains_key(&lane.host));
        let inner = channel.inner.clone();
        send(
            &channel,
            Bytes::from_static(b"shutdownxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
        )
        .await;
        let unanswered = requests.recv().await.unwrap();
        assert_eq!(lane.request_tasks.lock().unwrap().len(), 1);
        drop(channel);

        timeout(Duration::from_secs(1), pool.close()).await.unwrap();
        assert!(pool.closed.load(Ordering::Acquire));
        assert!(pool.lanes.lock().await.is_empty());
        assert!(lane.request_tasks.lock().unwrap().is_empty());
        assert!(inner.state.lock().unwrap().pending.is_empty());
        assert!(inner.budget.has_capacity(MAX_CHANNEL_BYTES));
        assert!(lane.budget.has_capacity(MAX_LANE_BYTES));
        drop(unanswered);
        drop(pinned);
        server.abort();
    }

    #[tokio::test]
    async fn pool_close_waits_for_setup_and_lane_connect_locks() {
        let pool = CfH2Pool::new(
            connector(),
            Duration::from_secs(1),
            4096,
            Arc::new(Stats::default()),
        );
        let setup = pool.setup_lock.lock().await;
        let closing = tokio::spawn({
            let pool = pool.clone();
            async move { pool.close().await }
        });
        tokio::task::yield_now().await;
        assert!(!closing.is_finished());
        drop(setup);
        closing.await.unwrap();

        let lane = bare_lane("connect-lock.example.test");
        let connect = lane.connect_lock.lock().await;
        let settling = tokio::spawn({
            let lane = lane.clone();
            async move { lane.settle_close().await }
        });
        tokio::task::yield_now().await;
        assert!(!settling.is_finished());
        drop(connect);
        for task in settling.await.unwrap() {
            let _ = task.await;
        }
        assert!(lane.closed.load(Ordering::Acquire));
        assert!(lane.connection.lock().unwrap().sender.is_none());
    }

    #[tokio::test]
    async fn pool_close_awaits_cancelled_non_cached_lane_driver_cleanup() {
        struct DropSignal(Arc<AtomicBool>);

        impl Drop for DropSignal {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }

        let pool = CfH2Pool::new(
            connector(),
            Duration::from_secs(1),
            4096,
            Arc::new(Stats::default()),
        );
        let slot = pool.lane_slots.clone().try_acquire_owned().unwrap();
        let lane = Lane::new(
            "cancelled-setup.example.test".into(),
            connector(),
            Duration::from_secs(1),
            4096,
            pool.stats.clone(),
            pool.payload_budgets.clone(),
            Some(slot),
        );
        pool.track_lane(&lane);

        let dropped = Arc::new(AtomicBool::new(false));
        let (started, running) = oneshot::channel();
        let driver = tokio::spawn({
            let dropped = dropped.clone();
            async move {
                let _signal = DropSignal(dropped);
                let _ = started.send(());
                std::future::pending::<()>().await;
            }
        });
        lane.connection.lock().unwrap().driver = Some(driver);
        running.await.unwrap();

        // This is the LaneSetupGuard cancellation path: synchronous Drop may
        // only abort, while the pool-owned strong registry must retain the
        // JoinHandle until the asynchronous shutdown barrier awaits it.
        lane.close();
        drop(lane);
        assert!(!dropped.load(Ordering::Acquire));
        pool.close().await;
        assert!(dropped.load(Ordering::Acquire));
        assert_eq!(pool.lane_slots.available_permits(), MAX_LIVE_LANES);
    }

    #[tokio::test]
    async fn retired_driver_registry_prunes_completed_tasks() {
        let lane = bare_lane("retired.example.test");
        for generation in 1..=32 {
            let driver = tokio::spawn(async {});
            while !driver.is_finished() {
                tokio::task::yield_now().await;
            }
            let mut state = lane.connection.lock().unwrap();
            state.generation = generation;
            state.driver = Some(driver);
            drop(state);
            lane.invalidate_connection(generation);
            assert!(lane.retired_drivers.lock().unwrap().len() <= 1);
        }
        lane.close();
    }

    #[tokio::test]
    async fn dropping_lane_aborts_connection_driver() {
        let lane = bare_lane("drop.example.test");
        let driver = tokio::spawn(std::future::pending::<()>());
        let abort = driver.abort_handle();
        lane.connection.lock().unwrap().driver = Some(driver);
        drop(lane);
        for _ in 0..10 {
            if abort.is_finished() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(abort.is_finished());
    }
}
