//! Minimal RFC 6455 transport. Frame bodies are streamed into caller-owned buffers.
use base64::{engine::general_purpose::STANDARD, Engine};
use rand::RngCore;
use sha1::{Digest, Sha1};
use std::{collections::BTreeMap, io, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadHalf, WriteHalf},
    net::TcpStream,
    sync::Mutex,
    time::timeout,
};
use tokio_native_tls::{TlsConnector, TlsStream};

pub const MAX_MESSAGE: usize = 16 * 1024 * 1024 + 4;
const HEADER_LIMIT: usize = 16 * 1024;
pub type Wire = BufReader<TlsStream<TcpStream>>;
pub type SharedWriter = Arc<Mutex<WsWriter<WriteHalf<Wire>>>>;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
pub fn timed_out(_: tokio::time::error::Elapsed) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "transport timeout")
}

#[derive(Debug)]
pub struct HttpError(pub u16);
impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HTTP {}", self.0)
    }
}
impl std::error::Error for HttpError {}
pub fn status(error: &io::Error) -> Option<u16> {
    error.get_ref()?.downcast_ref::<HttpError>().map(|e| e.0)
}
pub fn is_redirect(error: &io::Error) -> bool {
    matches!(status(error), Some(301 | 302 | 303 | 307 | 308))
}

pub struct WebSocket {
    wire: Wire,
    idle: Duration,
}

impl WebSocket {
    #[allow(clippy::too_many_arguments)]
    pub async fn connect(
        connector: &TlsConnector,
        host: &str,
        domain: &str,
        sni: &str,
        path: &str,
        connect_limit: Duration,
        idle: Duration,
        buffer_size: usize,
    ) -> io::Result<Self> {
        if [host, domain, sni, path]
            .iter()
            .any(|s| s.bytes().any(|b| b <= 32 || b == 127))
        {
            return Err(invalid("invalid WebSocket request target"));
        }
        timeout(connect_limit, async {
            let tcp = TcpStream::connect((host, 443)).await?;
            tcp.set_nodelay(true)?;
            let socket = socket2::SockRef::from(&tcp);
            let _ = socket.set_recv_buffer_size(buffer_size);
            let _ = socket.set_send_buffer_size(buffer_size);
            let tls = connector.connect(sni, tcp).await.map_err(io::Error::other)?;
            let mut wire = BufReader::with_capacity(4096, tls);
            let mut random = [0; 16];
            rand::thread_rng().fill_bytes(&mut random);
            let key = STANDARD.encode(random);
            let request = format!("GET {path} HTTP/1.1\r\nHost: {domain}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: binary\r\n\r\n");
            wire.write_all(request.as_bytes()).await?;
            wire.flush().await?;
            let (code, headers) = read_http_headers(&mut wire).await?;
            validate_upgrade(code, &headers, &key)?;
            Ok(Self { wire, idle })
        }).await.map_err(timed_out)?
    }

    pub fn split(self) -> (WsReader<ReadHalf<Wire>>, SharedWriter) {
        let (r, w) = tokio::io::split(self.wire);
        (
            WsReader::new(r),
            Arc::new(Mutex::new(WsWriter::new(w, self.idle))),
        )
    }

    /// Probe with a cancellation-safe one-byte read into the buffered transport.
    /// It never removes a byte from the stream. Closed and close-frame sockets expire.
    pub async fn idle_healthy(&mut self) -> bool {
        use tokio::io::AsyncBufReadExt;
        match timeout(Duration::from_millis(2), self.wire.fill_buf()).await {
            Err(_) => true,
            Ok(Ok(bytes)) => !bytes.is_empty() && bytes[0] & 15 != 8,
            Ok(Err(_)) => false,
        }
    }
}

pub async fn read_http_headers<R: AsyncRead + Unpin>(
    r: &mut R,
) -> io::Result<(u16, BTreeMap<String, String>)> {
    let mut bytes = Vec::with_capacity(512);
    while !bytes.ends_with(b"\r\n\r\n") {
        if bytes.len() == HEADER_LIMIT {
            return Err(invalid("HTTP headers exceed 16 KiB"));
        }
        bytes.push(r.read_u8().await?);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| invalid("invalid HTTP headers"))?;
    let mut lines = text.split("\r\n");
    let status = lines.next().unwrap_or_default();
    let mut parts = status.splitn(3, ' ');
    if !matches!(parts.next(), Some("HTTP/1.1" | "HTTP/1.0")) {
        return Err(invalid("invalid HTTP version"));
    }
    let code = parts
        .next()
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| invalid("invalid HTTP status"))?;
    let mut headers = BTreeMap::<String, String>::new();
    for line in lines.filter(|s| !s.is_empty()) {
        let (key, value) = line
            .split_once(':')
            .ok_or_else(|| invalid("invalid HTTP header"))?;
        let key = key.trim().to_ascii_lowercase();
        headers
            .entry(key)
            .and_modify(|old| {
                old.push(',');
                old.push_str(value.trim());
            })
            .or_insert_with(|| value.trim().to_owned());
    }
    Ok((code, headers))
}

fn validate_upgrade(code: u16, headers: &BTreeMap<String, String>, key: &str) -> io::Result<()> {
    if code != 101 {
        return Err(io::Error::other(HttpError(code)));
    }
    let token = |name: &str, expected: &str| {
        headers.get(name).is_some_and(|v| {
            v.split(',')
                .any(|v| v.trim().eq_ignore_ascii_case(expected))
        })
    };
    let accept = STANDARD.encode(Sha1::digest(format!(
        "{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    )));
    if !token("upgrade", "websocket")
        || !token("connection", "upgrade")
        || headers.get("sec-websocket-accept") != Some(&accept)
    {
        return Err(invalid("invalid WebSocket upgrade proof"));
    }
    if headers.contains_key("sec-websocket-extensions") {
        return Err(invalid("unsolicited WebSocket extension"));
    }
    if headers
        .get("sec-websocket-protocol")
        .is_some_and(|s| s != "binary")
    {
        return Err(invalid("invalid WebSocket subprotocol"));
    }
    Ok(())
}

pub struct WsWriter<W> {
    wire: W,
    idle: Duration,
    remaining: usize,
    mask: [u8; 4],
    offset: usize,
}
impl<W: AsyncWrite + Unpin> WsWriter<W> {
    pub fn new(wire: W, idle: Duration) -> Self {
        Self {
            wire,
            idle,
            remaining: 0,
            mask: [0; 4],
            offset: 0,
        }
    }
    pub async fn begin_binary(&mut self, length: usize) -> io::Result<()> {
        self.begin(2, length).await
    }
    async fn begin(&mut self, opcode: u8, length: usize) -> io::Result<()> {
        if self.remaining != 0 || length > MAX_MESSAGE {
            return Err(invalid("invalid outgoing frame length"));
        }
        rand::thread_rng().fill_bytes(&mut self.mask);
        self.offset = 0;
        let mut header = [0u8; 14];
        header[0] = 0x80 | opcode;
        let n = if length < 126 {
            header[1] = 0x80 | length as u8;
            2
        } else if length <= 65535 {
            header[1] = 0x80 | 126;
            header[2..4].copy_from_slice(&(length as u16).to_be_bytes());
            4
        } else {
            header[1] = 0x80 | 127;
            header[2..10].copy_from_slice(&(length as u64).to_be_bytes());
            10
        };
        header[n..n + 4].copy_from_slice(&self.mask);
        timeout(self.idle, self.wire.write_all(&header[..n + 4]))
            .await
            .map_err(timed_out)??;
        self.remaining = length;
        Ok(())
    }
    /// Mutates a scratch buffer after encryption, avoiding a frame-sized allocation.
    pub async fn payload(&mut self, data: &mut [u8]) -> io::Result<()> {
        if data.len() > self.remaining {
            return Err(invalid("outgoing frame overflow"));
        }
        for (i, b) in data.iter_mut().enumerate() {
            *b ^= self.mask[(self.offset + i) & 3];
        }
        timeout(self.idle, self.wire.write_all(data))
            .await
            .map_err(timed_out)??;
        self.offset += data.len();
        self.remaining -= data.len();
        if self.remaining == 0 {
            timeout(self.idle, self.wire.flush())
                .await
                .map_err(timed_out)??;
        }
        Ok(())
    }
    pub async fn binary(&mut self, data: &mut [u8]) -> io::Result<()> {
        self.begin_binary(data.len()).await?;
        self.payload(data).await
    }
    pub async fn control(&mut self, opcode: u8, data: &mut [u8]) -> io::Result<()> {
        if data.len() > 125 {
            return Err(invalid("oversized control frame"));
        }
        self.begin(opcode, data.len()).await?;
        self.payload(data).await
    }
}

pub struct WsReader<R> {
    wire: R,
    remaining: usize,
    fragmented: bool,
    message_len: usize,
}
impl<R: AsyncRead + Unpin> WsReader<R> {
    pub fn new(wire: R) -> Self {
        Self {
            wire,
            remaining: 0,
            fragmented: false,
            message_len: 0,
        }
    }
    /// The owning bridge enforces a shared bidirectional inactivity deadline.
    /// Cancel the whole connection on timeout: retrying half-read frame headers is unsafe.
    pub async fn chunk<W: AsyncWrite + Unpin>(
        &mut self,
        data: &mut [u8],
        writer: &Arc<Mutex<WsWriter<W>>>,
    ) -> io::Result<usize> {
        if data.is_empty() {
            return Err(invalid("empty read buffer"));
        }
        loop {
            if self.remaining > 0 {
                let n = data.len().min(self.remaining);
                let n = self.wire.read(&mut data[..n]).await?;
                if n == 0 {
                    return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
                }
                self.remaining -= n;
                return Ok(n);
            }
            let a = self.wire.read_u8().await?;
            let b = self.wire.read_u8().await?;
            let opcode = a & 15;
            let fin = a & 128 != 0;
            if a & 0x70 != 0 || b & 128 != 0 {
                return Err(invalid("unsupported RSV or masked server frame"));
            }
            let short = b & 127;
            let length = match short {
                126 => {
                    let n = self.wire.read_u16().await? as u64;
                    if n < 126 {
                        return Err(invalid("noncanonical frame length"));
                    }
                    n
                }
                127 => {
                    let n = self.wire.read_u64().await?;
                    if n < 65536 {
                        return Err(invalid("noncanonical frame length"));
                    }
                    n
                }
                n => n as u64,
            };
            if length > MAX_MESSAGE as u64 {
                return Err(invalid("WebSocket frame exceeds limit"));
            }
            let length = length as usize;
            if opcode >= 8 {
                if !fin || length > 125 || !matches!(opcode, 8..=10) {
                    return Err(invalid("invalid WebSocket control frame"));
                }
                let mut control = [0; 125];
                self.wire.read_exact(&mut control[..length]).await?;
                if opcode == 8 {
                    if length == 1 {
                        return Err(invalid("invalid WebSocket close payload"));
                    }
                    if let Ok(mut w) = writer.try_lock() {
                        let _ = w.control(8, &mut control[..length.min(2)]).await;
                    }
                    return Ok(0);
                }
                if opcode == 9 {
                    writer
                        .lock()
                        .await
                        .control(10, &mut control[..length])
                        .await?;
                }
                continue;
            }
            match opcode {
                0 if self.fragmented => {}
                2 if !self.fragmented => {
                    self.message_len = 0;
                }
                _ => return Err(invalid("invalid WebSocket message opcode or continuation")),
            }
            self.message_len = self
                .message_len
                .checked_add(length)
                .ok_or_else(|| invalid("message length overflow"))?;
            if self.message_len > MAX_MESSAGE {
                return Err(invalid("WebSocket message exceeds limit"));
            }
            self.fragmented = !fin;
            self.remaining = length;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_rfc_upgrade_proof() {
        let h = BTreeMap::from([
            ("upgrade".into(), "websocket".into()),
            ("connection".into(), "keep-alive, Upgrade".into()),
            (
                "sec-websocket-accept".into(),
                "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=".into(),
            ),
        ]);
        assert!(validate_upgrade(101, &h, "dGhlIHNhbXBsZSBub25jZQ==").is_ok());
        assert!(validate_upgrade(101, &h, "wrong").is_err());
        assert_eq!(
            status(&validate_upgrade(429, &h, "wrong").unwrap_err()),
            Some(429)
        );
    }
    #[tokio::test]
    async fn streams_fragments_and_answers_ping() {
        let input = b"\x02\x03abc\x89\x01!\x80\x02de\x88\x00";
        let (wire, mut sink) = tokio::io::duplex(1024);
        let w = Arc::new(Mutex::new(WsWriter::new(wire, Duration::from_secs(1))));
        let mut r = WsReader::new(&input[..]);
        let mut buffer = [0; 2];
        let mut result = Vec::new();
        loop {
            let n = r.chunk(&mut buffer, &w).await.unwrap();
            if n == 0 {
                break;
            }
            result.extend_from_slice(&buffer[..n]);
        }
        assert_eq!(result, b"abcde");
        let mut pong = [0; 7];
        sink.read_exact(&mut pong).await.unwrap();
        assert_eq!(&pong[..2], &[0x8a, 0x81]);
        assert_eq!(pong[6] ^ pong[2], b'!');
    }
    #[tokio::test]
    async fn rejects_malformed_and_huge_frames_without_allocating() {
        for frame in [
            &b"\x82\xff\x00\x00\x00\x01\x00\x00\x00\x00"[..],
            &b"\x80\x01x"[..],
            &b"\x09\x00"[..],
            &b"\xc2\x00"[..],
        ] {
            let w = Arc::new(Mutex::new(WsWriter::new(
                tokio::io::sink(),
                Duration::from_secs(1),
            )));
            let mut r = WsReader::new(frame);
            assert!(r.chunk(&mut [0; 4], &w).await.is_err());
        }
    }
    #[tokio::test]
    async fn masks_streamed_payload_with_continuous_offset() {
        let (wire, mut sink) = tokio::io::duplex(1024);
        let mut w = WsWriter::new(wire, Duration::from_secs(1));
        let mut a = *b"abc";
        let mut b = *b"defg";
        w.begin_binary(7).await.unwrap();
        w.payload(&mut a).await.unwrap();
        w.payload(&mut b).await.unwrap();
        let mut frame = [0; 13];
        sink.read_exact(&mut frame).await.unwrap();
        assert_eq!(&frame[..2], &[0x82, 0x87]);
        let decoded: Vec<u8> = (0..7).map(|i| frame[6 + i] ^ frame[2 + (i & 3)]).collect();
        assert_eq!(decoded, b"abcdefg");
    }
}
