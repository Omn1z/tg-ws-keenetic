//! Admission-limited listener and constant-space MTProto bridges.
use crate::{
    config::Config,
    crypto::{self, AesCtr, CryptoContext, Protocol},
    fake_tls::{self, FakeTlsStream},
    framing,
    stats::Stats,
    upstream::{Route, Upstream},
    websocket::{self, WsReader, WsWriter},
};
use ctr::cipher::StreamCipher;
use std::{
    collections::BTreeMap,
    io,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::{oneshot, Semaphore},
    task::{JoinHandle, JoinSet},
    time::timeout,
};

trait Duplex: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Duplex for T {}
type Client = Box<dyn Duplex>;
type ReplayCache = Arc<Mutex<BTreeMap<[u8; 32], Instant>>>;

pub struct Proxy {
    task: Option<JoinHandle<()>>,
    stop: Option<oneshot::Sender<()>>,
    address: SocketAddr,
}
impl Proxy {
    pub async fn start(config: Arc<Config>, stats: Arc<Stats>) -> io::Result<Self> {
        let secret = config.secret_bytes()?;
        let upstream = Upstream::new(config.clone(), stats.clone())?;
        let listener = TcpListener::bind((config.host.as_str(), config.port)).await?;
        let address = listener.local_addr()?;
        let (stop, mut stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut jobs = JoinSet::new();
            let background = upstream.clone();
            jobs.spawn(async move {
                background.maintain().await;
            });
            let background = upstream.clone();
            jobs.spawn(async move {
                background.refresh_domains().await;
            });
            let slots = Arc::new(Semaphore::new(config.max_connections));
            let replay: ReplayCache = Arc::new(Mutex::new(BTreeMap::new()));
            loop {
                tokio::select! {
                    _=&mut stopped=>break,
                    result=listener.accept()=> {
                        let (socket,_)=match result {Ok(pair)=>pair,Err(error)=> {eprintln!("tgws: listener error: {error}"); tokio::time::sleep(Duration::from_millis(100)).await;continue;}};
                        let permit=match slots.clone().try_acquire_owned() {Ok(p)=>p,Err(_)=>{stats.rejected();continue;}};
                        let config=config.clone();let stats=stats.clone();let upstream=upstream.clone();let replay=replay.clone();
                        let active=Active::new(stats.clone());
                        jobs.spawn(async move {
                            let _active=active;let _permit=permit;
                            if let Err(error)=serve(socket,&config,stats,&upstream,&secret,&replay).await {
                                if config.verbose && !matches!(error.kind(),io::ErrorKind::UnexpectedEof|io::ErrorKind::ConnectionReset|io::ErrorKind::BrokenPipe) {
                                    eprintln!("tgws: connection closed: {error}");
                                }
                            }
                        });
                    }
                    _=jobs.join_next(),if !jobs.is_empty()=>{}
                }
            }
            // A completed shutdown guarantees every socket, guard and background dial is gone.
            jobs.abort_all();
            while jobs.join_next().await.is_some() {}
        });
        Ok(Self {
            task: Some(task),
            stop: Some(stop),
            address,
        })
    }
    pub fn local_addr(&self) -> SocketAddr {
        self.address
    }
    pub async fn shutdown(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}
impl Drop for Proxy {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}
struct Active(Arc<Stats>);
impl Active {
    fn new(stats: Arc<Stats>) -> Self {
        stats.accepted();
        Self(stats)
    }
}
impl Drop for Active {
    fn drop(&mut self) {
        self.0.closed();
    }
}

/// One clock for both directions: a long download must keep the silent upload alive.
struct Activity {
    last: Mutex<Instant>,
}
impl Activity {
    fn new() -> Self {
        Self {
            last: Mutex::new(Instant::now()),
        }
    }
    fn touch(&self) {
        *self.last.lock().unwrap() = Instant::now();
    }
    async fn expired(&self, idle: Duration) -> io::Result<()> {
        loop {
            let elapsed = self.last.lock().unwrap().elapsed();
            if elapsed >= idle {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "connection idle timeout",
                ));
            }
            tokio::time::sleep(idle - elapsed).await;
        }
    }
}

async fn serve(
    socket: TcpStream,
    config: &Config,
    stats: Arc<Stats>,
    upstream: &Upstream,
    secret: &[u8; 16],
    replay: &ReplayCache,
) -> io::Result<()> {
    socket.set_nodelay(true)?;
    let sock = socket2::SockRef::from(&socket);
    let _ = sock.set_recv_buffer_size(config.buffer_size);
    let _ = sock.set_send_buffer_size(config.buffer_size);
    let Some((mut client, handshake)) = initial(socket, config, &stats, secret, replay).await?
    else {
        return Ok(());
    };
    let parsed = match crypto::parse_client_handshake(&handshake, secret) {
        Ok(p) => p,
        Err(e) => {
            stats.bad();
            return Err(e);
        }
    };
    let (dc, media, test) = normalize_dc(parsed.dc_index, config.force_test_dc)?;
    let mut relay = crypto::generate_relay_handshake(parsed.protocol, if media { -dc } else { dc });
    let context = crypto::build_context(&parsed, secret, &relay);
    let idle = Duration::from_secs(config.idle_timeout_secs);
    match upstream.connect(dc, media, test).await? {
        Route::WebSocket(ws, packetized) => {
            let (reader, writer) = ws.split();
            writer.lock().await.binary(&mut relay).await?;
            bridge_ws(
                &mut client,
                reader,
                writer,
                context,
                parsed.protocol,
                packetized,
                stats,
                config.buffer_size,
                idle,
            )
            .await
        }
        Route::Tcp(mut remote) => {
            timeout(idle, remote.write_all(&relay))
                .await
                .map_err(websocket::timed_out)??;
            bridge_tcp(
                &mut client,
                &mut remote,
                context,
                stats,
                config.buffer_size,
                idle,
            )
            .await
        }
    }
}

fn normalize_dc(index: i16, force_test: bool) -> io::Result<(i16, bool, bool)> {
    let media = index < 0;
    let unsigned = index
        .checked_abs()
        .ok_or_else(|| invalid("invalid Telegram DC"))?;
    let test = unsigned >= 10000 || force_test;
    let dc = if unsigned >= 10000 {
        unsigned - 10000
    } else {
        unsigned
    };
    if !matches!(dc, 1..=5 | 203) || (test && !matches!(dc, 1..=3)) {
        return Err(invalid("unsupported Telegram DC"));
    }
    Ok((dc, media, test))
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

async fn initial(
    socket: TcpStream,
    config: &Config,
    stats: &Stats,
    secret: &[u8; 16],
    replay: &ReplayCache,
) -> io::Result<Option<(Client, [u8; 64])>> {
    let mut stream = BufReader::with_capacity(1024, socket);
    let prefix = timeout(Duration::from_secs(10), async {
        if config.proxy_protocol {
            consume_proxy(&mut stream).await?;
        }
        let first = stream.read_u8().await?;
        if first == 0x16 && !config.fake_tls_domain.is_empty() {
            let mut header = [first, 0, 0, 0, 0];
            stream.read_exact(&mut header[1..]).await?;
            let length = u16::from_be_bytes([header[3], header[4]]) as usize;
            if !(38..=16384).contains(&length) {
                return Err(invalid("invalid ClientHello record length"));
            }
            let mut hello = Vec::with_capacity(length + 5);
            hello.extend_from_slice(&header);
            hello.resize(length + 5, 0);
            stream.read_exact(&mut hello[5..]).await?;
            Ok((first, Some(hello)))
        } else {
            Ok((first, None))
        }
    })
    .await
    .map_err(websocket::timed_out)??;
    let (first, hello) = prefix;
    if let Some(hello) = hello {
        let verified = fake_tls::verify_client_hello(&hello, secret).and_then(|hello| {
            let mut cache = replay.lock().unwrap();
            cache.retain(|_, when| when.elapsed() < Duration::from_secs(300));
            if cache.contains_key(&hello.client_random) {
                return Err(invalid("replayed ClientHello"));
            }
            if cache.len() >= 4096 {
                return Err(invalid("ClientHello replay cache full"));
            }
            cache.insert(hello.client_random, Instant::now());
            Ok(hello)
        });
        match verified {
            Ok(parsed) => {
                let response = fake_tls::build_server_hello(secret, &parsed);
                return timeout(Duration::from_secs(10), async {
                    stream.write_all(&response).await?;
                    stream.flush().await?;
                    let mut tls = FakeTlsStream::new(stream);
                    let mut handshake = [0; 64];
                    tls.read_exact(&mut handshake).await?;
                    Ok(Some((Box::new(tls) as Client, handshake)))
                })
                .await
                .map_err(websocket::timed_out)?;
            }
            Err(_) => {
                stats.masked();
                let idle = Duration::from_secs(config.idle_timeout_secs);
                let mut remote = timeout(
                    Duration::from_secs(config.connect_timeout_secs),
                    TcpStream::connect((config.fake_tls_domain.as_str(), 443)),
                )
                .await
                .map_err(websocket::timed_out)??;
                timeout(idle, remote.write_all(&hello))
                    .await
                    .map_err(websocket::timed_out)??;
                let (mut cr, mut cw) = tokio::io::split(stream);
                let (mut rr, mut rw) = remote.split();
                let activity = Activity::new();
                tokio::select! {
                    result=copy_plain(&mut cr,&mut rw,config.buffer_size,idle,&activity)=>{result?;},
                    result=copy_plain(&mut rr,&mut cw,config.buffer_size,idle,&activity)=>{result?;},
                    result=activity.expired(idle)=>{result?;}
                }
                return Ok(None);
            }
        }
    }
    if !config.fake_tls_domain.is_empty() {
        let response=format!("HTTP/1.1 301 Moved Permanently\r\nLocation: https://{}/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",config.fake_tls_domain);
        timeout(
            Duration::from_secs(10),
            stream.write_all(response.as_bytes()),
        )
        .await
        .map_err(websocket::timed_out)??;
        return Ok(None);
    }
    let mut handshake = [0; 64];
    handshake[0] = first;
    timeout(
        Duration::from_secs(10),
        stream.read_exact(&mut handshake[1..]),
    )
    .await
    .map_err(websocket::timed_out)??;
    Ok(Some((Box::new(stream), handshake)))
}

async fn consume_proxy<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<()> {
    let mut line = [0; 107];
    let mut length = 0;
    while length < line.len() {
        line[length] = reader.read_u8().await?;
        length += 1;
        if line[length - 1] == b'\n' {
            if !line[..length].ends_with(b"\r\n") {
                return Err(invalid("invalid PROXY v1 terminator"));
            }
            let text = std::str::from_utf8(&line[..length - 2])
                .map_err(|_| invalid("invalid PROXY v1 encoding"))?;
            let fields: Vec<_> = text.split(' ').collect();
            if fields.len() >= 2 && fields[0] == "PROXY" && fields[1] == "UNKNOWN" {
                return Ok(());
            }
            if fields.len() != 6 || fields[0] != "PROXY" || !matches!(fields[1], "TCP4" | "TCP6") {
                return Err(invalid("invalid PROXY v1 header"));
            }
            for host in &fields[2..4] {
                let ip = host
                    .parse::<std::net::IpAddr>()
                    .map_err(|_| invalid("invalid PROXY v1 address"))?;
                if ip.is_ipv4() != (fields[1] == "TCP4") {
                    return Err(invalid("PROXY address family mismatch"));
                }
            }
            for port in &fields[4..6] {
                port.parse::<u16>()
                    .map_err(|_| invalid("invalid PROXY v1 port"))?;
            }
            return Ok(());
        }
    }
    Err(invalid("PROXY v1 header exceeds 107 bytes"))
}

#[allow(clippy::too_many_arguments)]
async fn bridge_ws<C, R, W>(
    client: &mut C,
    mut reader: WsReader<R>,
    writer: Arc<tokio::sync::Mutex<WsWriter<W>>>,
    context: CryptoContext,
    protocol: Protocol,
    packetized: bool,
    stats: Arc<Stats>,
    buffer_size: usize,
    idle: Duration,
) -> io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let (mut cr, mut cw) = tokio::io::split(client);
    let CryptoContext {
        client_decrypt,
        client_encrypt,
        upstream_encrypt,
        upstream_decrypt,
    } = context;
    let activity = Activity::new();
    tokio::select! {
        result=upload_ws(&mut cr,&writer,client_decrypt,upstream_encrypt,protocol,packetized,&stats,buffer_size,&activity)=>result,
        result=download_ws(&mut reader,&writer,&mut cw,upstream_decrypt,client_encrypt,&stats,buffer_size,idle,&activity)=>result,
        result=activity.expired(idle)=>result,
    }
}

#[allow(clippy::too_many_arguments)]
async fn upload_ws<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &Arc<tokio::sync::Mutex<WsWriter<W>>>,
    mut decrypt: AesCtr,
    mut encrypt: AesCtr,
    protocol: Protocol,
    packetized: bool,
    stats: &Stats,
    buffer_size: usize,
    activity: &Activity,
) -> io::Result<()> {
    let mut buffer = vec![0; buffer_size];
    loop {
        if !packetized {
            let n = reader.read(&mut buffer).await?;
            if n == 0 {
                return Ok(());
            }
            activity.touch();
            decrypt.apply_keystream(&mut buffer[..n]);
            encrypt.apply_keystream(&mut buffer[..n]);
            stats.add_up(n);
            writer.lock().await.binary(&mut buffer[..n]).await?;
            continue;
        }
        // Read/decrypt only a transport header, then stream its body in fixed chunks.
        // Exactly one WS binary frame per MTProto packet, including quick-ack markers.
        let mut header = [0; 4];
        let n = reader.read(&mut header[..1]).await?;
        if n == 0 {
            return Ok(());
        }
        activity.touch();
        decrypt.apply_keystream(&mut header[..1]);
        let header_len = framing::header_len(header[0], protocol);
        if header_len > 1 {
            reader.read_exact(&mut header[1..header_len]).await?;
            activity.touch();
            decrypt.apply_keystream(&mut header[1..header_len]);
        }
        let (_, mut remaining) = framing::packet_length(&header[..header_len], protocol)?
            .ok_or_else(|| invalid("incomplete MTProto header"))?;
        let mut writer = writer.lock().await;
        writer.begin_binary(header_len + remaining).await?;
        encrypt.apply_keystream(&mut header[..header_len]);
        writer.payload(&mut header[..header_len]).await?;
        stats.add_up(header_len);
        while remaining > 0 {
            let take = remaining.min(buffer.len());
            let n = reader.read(&mut buffer[..take]).await?;
            if n == 0 {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
            }
            activity.touch();
            decrypt.apply_keystream(&mut buffer[..n]);
            encrypt.apply_keystream(&mut buffer[..n]);
            stats.add_up(n);
            writer.payload(&mut buffer[..n]).await?;
            remaining -= n;
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn download_ws<R: AsyncRead + Unpin, W: AsyncWrite + Unpin, C: AsyncWrite + Unpin>(
    reader: &mut WsReader<R>,
    writer: &Arc<tokio::sync::Mutex<WsWriter<W>>>,
    client: &mut C,
    mut decrypt: AesCtr,
    mut encrypt: AesCtr,
    stats: &Stats,
    buffer_size: usize,
    idle: Duration,
    activity: &Activity,
) -> io::Result<()> {
    let mut buffer = vec![0; buffer_size];
    loop {
        let n = reader.chunk(&mut buffer, writer).await?;
        if n == 0 {
            return Ok(());
        }
        activity.touch();
        decrypt.apply_keystream(&mut buffer[..n]);
        encrypt.apply_keystream(&mut buffer[..n]);
        stats.add_down(n);
        timeout(idle, async {
            client.write_all(&buffer[..n]).await?;
            client.flush().await
        })
        .await
        .map_err(websocket::timed_out)??;
    }
}

async fn bridge_tcp<C: AsyncRead + AsyncWrite + Unpin, T: AsyncRead + AsyncWrite + Unpin>(
    client: &mut C,
    remote: &mut T,
    context: CryptoContext,
    stats: Arc<Stats>,
    buffer_size: usize,
    idle: Duration,
) -> io::Result<()> {
    let (mut cr, mut cw) = tokio::io::split(client);
    let (mut rr, mut rw) = tokio::io::split(remote);
    let CryptoContext {
        client_decrypt,
        client_encrypt,
        upstream_encrypt,
        upstream_decrypt,
    } = context;
    let activity = Activity::new();
    tokio::select! {
        result=copy_crypto(&mut cr,&mut rw,client_decrypt,upstream_encrypt,&stats,true,buffer_size,idle,&activity)=>result,
        result=copy_crypto(&mut rr,&mut cw,upstream_decrypt,client_encrypt,&stats,false,buffer_size,idle,&activity)=>result,
        result=activity.expired(idle)=>result,
    }
}
#[allow(clippy::too_many_arguments)]
async fn copy_crypto<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    r: &mut R,
    w: &mut W,
    mut decrypt: AesCtr,
    mut encrypt: AesCtr,
    stats: &Stats,
    up: bool,
    buffer_size: usize,
    idle: Duration,
    activity: &Activity,
) -> io::Result<()> {
    let mut buffer = vec![0; buffer_size];
    loop {
        let n = r.read(&mut buffer).await?;
        if n == 0 {
            return Ok(());
        }
        activity.touch();
        decrypt.apply_keystream(&mut buffer[..n]);
        encrypt.apply_keystream(&mut buffer[..n]);
        if up {
            stats.add_up(n);
        } else {
            stats.add_down(n);
        }
        timeout(idle, async {
            w.write_all(&buffer[..n]).await?;
            w.flush().await
        })
        .await
        .map_err(websocket::timed_out)??;
    }
}
async fn copy_plain<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    r: &mut R,
    w: &mut W,
    buffer_size: usize,
    idle: Duration,
    activity: &Activity,
) -> io::Result<()> {
    let mut buffer = vec![0; buffer_size];
    loop {
        let n = r.read(&mut buffer).await?;
        if n == 0 {
            return Ok(());
        }
        activity.touch();
        timeout(idle, async {
            w.write_all(&buffer[..n]).await?;
            w.flush().await
        })
        .await
        .map_err(websocket::timed_out)??;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ctr::cipher::KeyIvInit;

    fn test_context() -> CryptoContext {
        let cipher = |key: u8| AesCtr::new((&[key; 32]).into(), (&[key + 10; 16]).into());
        CryptoContext {
            client_decrypt: cipher(1),
            client_encrypt: cipher(2),
            upstream_encrypt: cipher(3),
            upstream_decrypt: cipher(4),
        }
    }

    async fn client_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Vec<u8> {
        assert_eq!(reader.read_u8().await.unwrap(), 0x82);
        let short = reader.read_u8().await.unwrap();
        assert_ne!(short & 128, 0);
        let length = match short & 127 {
            126 => reader.read_u16().await.unwrap() as usize,
            127 => reader.read_u64().await.unwrap() as usize,
            n => n as usize,
        };
        let mut mask = [0; 4];
        reader.read_exact(&mut mask).await.unwrap();
        let mut data = vec![0; length];
        reader.read_exact(&mut data).await.unwrap();
        for (i, byte) in data.iter_mut().enumerate() {
            *byte ^= mask[i & 3];
        }
        data
    }

    #[tokio::test]
    async fn packetized_ws_streams_large_packets_and_preserves_frame_boundaries() {
        let first_payload: Vec<_> = (0..5001).map(|i| (i % 251) as u8).collect();
        let mut first = (first_payload.len() as u32 | 0x80000000)
            .to_le_bytes()
            .to_vec();
        first.extend_from_slice(&first_payload);
        let mut second = 7u32.to_le_bytes().to_vec();
        second.extend_from_slice(b"padding");
        let plain = [first.clone(), second.clone()].concat();
        let context = test_context();
        let mut client_cipher = context.client_decrypt.clone();
        let mut remote_cipher = context.upstream_encrypt.clone();
        let mut encrypted = plain.clone();
        client_cipher.apply_keystream(&mut encrypted);
        let mut expected_first = first;
        let mut expected_second = second;
        remote_cipher.apply_keystream(&mut expected_first);
        remote_cipher.apply_keystream(&mut expected_second);
        let (mut source, mut input) = tokio::io::duplex(13);
        let (output, mut sink) = tokio::io::duplex(11);
        let writer = Arc::new(tokio::sync::Mutex::new(WsWriter::new(
            output,
            Duration::from_secs(2),
        )));
        let stats = Stats::default();
        let activity = Activity::new();
        timeout(Duration::from_secs(5), async {
            let send = async {
                for part in encrypted.chunks(3) {
                    source.write_all(part).await.unwrap();
                }
                source.shutdown().await.unwrap();
            };
            let receive = async {
                assert_eq!(client_frame(&mut sink).await, expected_first);
                assert_eq!(client_frame(&mut sink).await, expected_second);
            };
            let pump = upload_ws(
                &mut input,
                &writer,
                context.client_decrypt,
                context.upstream_encrypt,
                Protocol::PaddedIntermediate,
                true,
                &stats,
                7,
                &activity,
            );
            let (_, _, result) = tokio::join!(send, receive, pump);
            result.unwrap();
        })
        .await
        .unwrap();
        assert_eq!(stats.snapshot()["bytes_up"], plain.len());
    }

    #[tokio::test]
    async fn worker_mode_forwards_partial_mtproto_packet_immediately() {
        let context = test_context();
        let mut encrypted = 42u32.to_le_bytes();
        context
            .client_decrypt
            .clone()
            .apply_keystream(&mut encrypted);
        let mut expected = 42u32.to_le_bytes();
        context
            .upstream_encrypt
            .clone()
            .apply_keystream(&mut expected);
        let (mut source, mut input) = tokio::io::duplex(32);
        let (output, mut sink) = tokio::io::duplex(32);
        let writer = Arc::new(tokio::sync::Mutex::new(WsWriter::new(
            output,
            Duration::from_secs(2),
        )));
        let stats = Stats::default();
        let activity = Activity::new();
        timeout(Duration::from_secs(2), async {
            let client = async {
                source.write_all(&encrypted).await.unwrap();
                // The rest of this packet never arrives: a raw Worker still gets these bytes.
                assert_eq!(client_frame(&mut sink).await, expected);
                source.shutdown().await.unwrap();
            };
            let pump = upload_ws(
                &mut input,
                &writer,
                context.client_decrypt,
                context.upstream_encrypt,
                Protocol::Intermediate,
                false,
                &stats,
                16,
                &activity,
            );
            let (_, result) = tokio::join!(client, pump);
            result.unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn tcp_bridge_reencrypts_both_directions_with_bounded_buffers() {
        let context = test_context();
        let mut upload = b"client payload across short reads".to_vec();
        let mut download = b"server payload across short reads".to_vec();
        let mut expected_up = upload.clone();
        let mut expected_down = download.clone();
        context.client_decrypt.clone().apply_keystream(&mut upload);
        context
            .upstream_encrypt
            .clone()
            .apply_keystream(&mut expected_up);
        context
            .upstream_decrypt
            .clone()
            .apply_keystream(&mut download);
        context
            .client_encrypt
            .clone()
            .apply_keystream(&mut expected_down);
        let (mut client, mut accepted) = tokio::io::duplex(64);
        let (mut remote, mut server) = tokio::io::duplex(64);
        let stats = Arc::new(Stats::default());
        let observe = stats.clone();
        timeout(Duration::from_secs(2), async {
            let exchange = async {
                client.write_all(&upload).await.unwrap();
                let mut got = vec![0; upload.len()];
                server.read_exact(&mut got).await.unwrap();
                assert_eq!(got, expected_up);
                server.write_all(&download).await.unwrap();
                let mut got = vec![0; download.len()];
                client.read_exact(&mut got).await.unwrap();
                assert_eq!(got, expected_down);
                client.shutdown().await.unwrap();
            };
            let pump = bridge_tcp(
                &mut accepted,
                &mut remote,
                context,
                stats,
                3,
                Duration::from_secs(1),
            );
            let (_, result) = tokio::join!(exchange, pump);
            result.unwrap();
        })
        .await
        .unwrap();
        assert_eq!(observe.snapshot()["bytes_up"], upload.len());
        assert_eq!(observe.snapshot()["bytes_down"], download.len());
    }

    #[tokio::test]
    async fn tcp_idle_timeout_tracks_activity_in_either_direction() {
        let (mut client, mut accepted) = tokio::io::duplex(64);
        let (mut remote, mut server) = tokio::io::duplex(64);
        let stats = Arc::new(Stats::default());
        let pump = bridge_tcp(
            &mut accepted,
            &mut remote,
            test_context(),
            stats,
            16,
            Duration::from_millis(120),
        );
        let exchange = async {
            // Upload remains completely silent for several idle periods.
            for _ in 0..8 {
                server.write_all(b"x").await.unwrap();
                client.read_exact(&mut [0]).await.unwrap();
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
            // Keeping both ends open must nevertheless expire once neither moves bytes.
        };
        timeout(Duration::from_secs(3), async {
            let (_, result) = tokio::join!(exchange, pump);
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn ws_download_streams_fragmented_ciphertext_without_reassembling_messages() {
        let context = test_context();
        let mut data = b"streamed fragmented ciphertext".to_vec();
        let mut expected = data.clone();
        context.upstream_decrypt.clone().apply_keystream(&mut data);
        context
            .client_encrypt
            .clone()
            .apply_keystream(&mut expected);
        let mut wire = vec![0x02, 5];
        wire.extend_from_slice(&data[..5]);
        wire.extend_from_slice(&[0x80, (data.len() - 5) as u8]);
        wire.extend_from_slice(&data[5..]);
        wire.extend_from_slice(&[0x88, 0]);
        let mut reader = WsReader::new(wire.as_slice());
        let writer = Arc::new(tokio::sync::Mutex::new(WsWriter::new(
            tokio::io::sink(),
            Duration::from_secs(1),
        )));
        let (mut output, mut sink) = tokio::io::duplex(64);
        let stats = Stats::default();
        let activity = Activity::new();
        download_ws(
            &mut reader,
            &writer,
            &mut output,
            context.upstream_decrypt,
            context.client_encrypt,
            &stats,
            3,
            Duration::from_secs(1),
            &activity,
        )
        .await
        .unwrap();
        let mut got = vec![0; data.len()];
        sink.read_exact(&mut got).await.unwrap();
        assert_eq!(got, expected);
        assert_eq!(stats.snapshot()["bytes_down"], data.len());
    }

    #[test]
    fn signed_test_dc_is_normalized_safely() {
        assert_eq!(normalize_dc(-10002, false).unwrap(), (2, true, true));
        assert_eq!(normalize_dc(-4, false).unwrap(), (4, true, false));
        assert!(normalize_dc(i16::MIN, false).is_err());
        assert!(normalize_dc(10004, false).is_err());
        assert!(normalize_dc(0, false).is_err());
    }
    #[tokio::test]
    async fn proxy_header_is_bounded_and_leaves_handshake_unread() {
        let mut input = &b"PROXY TCP4 192.0.2.1 192.0.2.2 4000 443\r\nx"[..];
        consume_proxy(&mut input).await.unwrap();
        assert_eq!(input, b"x");
        assert!(
            consume_proxy(&mut &b"PROXY TCP6 192.0.2.1 192.0.2.2 4000 443\r\n"[..])
                .await
                .is_err()
        );
        assert!(consume_proxy(&mut &[b'x'; 108][..]).await.is_err());
    }
    #[tokio::test]
    async fn shutdown_releases_listener_and_admission_slots() {
        let config = Config {
            host: "127.0.0.1".into(),
            port: 0,
            secret: "000102030405060708090a0b0c0d0e0f".into(),
            max_connections: 1,
            domain_refresh: false,
            ..Config::default()
        };
        let stats = Arc::new(Stats::default());
        let mut proxy = Proxy::start(Arc::new(config), stats.clone()).await.unwrap();
        let address = proxy.local_addr();
        let _client = TcpStream::connect(address).await.unwrap();
        tokio::task::yield_now().await;
        assert_eq!(stats.snapshot()["connections_active"], 1);
        let mut extra = TcpStream::connect(address).await.unwrap();
        let mut b = [0];
        assert_eq!(extra.read(&mut b).await.unwrap(), 0);
        assert_eq!(stats.snapshot()["rejected"], 1);
        proxy.shutdown().await;
        tokio::task::yield_now().await;
        assert_eq!(stats.snapshot()["connections_active"], 0);
        assert!(TcpListener::bind(address).await.is_ok());
    }
}
