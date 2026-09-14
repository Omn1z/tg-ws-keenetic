//! Telegram Fake TLS authentication and bounded TLS-record streaming.

use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, Rng, RngCore};
use sha2::Sha256;
use std::{
    io,
    pin::Pin,
    task::{ready, Context, Poll},
    time::{SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

type HmacSha256 = Hmac<Sha256>;

pub const TLS_APP_DATA_MAX: usize = 16384;
pub const TIMESTAMP_TOLERANCE: u64 = 120;
const CCS_FRAME: &[u8] = &[0x14, 0x03, 0x03, 0, 1, 1];

#[derive(Clone)]
pub struct ClientHello {
    pub client_random: [u8; 32],
    pub session_id: [u8; 32],
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn authenticate(data: &[u8], secret: &[u8; 16], now: u64) -> io::Result<ClientHello> {
    if data.len() < 43 || data[0] != 0x16 || data[5] != 1 {
        return Err(invalid("invalid Fake TLS ClientHello"));
    }
    let mut random = [0; 32];
    random.copy_from_slice(&data[11..43]);
    // Hash the record with zeroed random without copying the ClientHello.
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key size");
    mac.update(&data[..11]);
    mac.update(&[0; 32]);
    mac.update(&data[43..]);
    let expected = mac.finalize().into_bytes();
    if !bool::from(expected[..28].ct_eq(&random[..28])) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid Fake TLS authentication",
        ));
    }
    let timestamp = u32::from_le_bytes(std::array::from_fn(|i| random[28 + i] ^ expected[28 + i]));
    if now.abs_diff(u64::from(timestamp)) > TIMESTAMP_TOLERANCE {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "expired Fake TLS ClientHello",
        ));
    }
    let mut session_id = [0; 32];
    if data.len() >= 76 && data[43] == 32 {
        session_id.copy_from_slice(&data[44..76]);
    }
    Ok(ClientHello {
        client_random: random,
        session_id,
    })
}

pub fn verify_client_hello(data: &[u8], secret: &[u8; 16]) -> io::Result<ClientHello> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| invalid("system clock is before Unix epoch"))?
        .as_secs();
    authenticate(data, secret, now)
}

pub fn build_server_hello(secret: &[u8; 16], client: &ClientHello) -> Vec<u8> {
    let app_size: usize = OsRng.gen_range(1900..=2100);
    let mut response = Vec::with_capacity(127 + CCS_FRAME.len() + 5 + app_size);
    response.extend_from_slice(&[0x16, 0x03, 0x03, 0, 0x7a, 2, 0, 0, 0x76, 0x03, 0x03]);
    response.extend_from_slice(&[0; 32]);
    response.push(32);
    response.extend_from_slice(&client.session_id);
    response.extend_from_slice(&[0x13, 1, 0, 0, 0x2e, 0, 0x33, 0, 0x24, 0, 0x1d, 0, 0x20]);
    response.extend_from_slice(&[0; 32]);
    OsRng.fill_bytes(&mut response[89..121]);
    response.extend_from_slice(&[0, 0x2b, 0, 2, 0x03, 0x04]);
    response.extend_from_slice(CCS_FRAME);
    response.extend_from_slice(&[0x17, 0x03, 0x03]);
    response.extend_from_slice(&(app_size as u16).to_be_bytes());
    let app_offset = response.len();
    response.resize(app_offset + app_size, 0);
    OsRng.fill_bytes(&mut response[app_offset..]);

    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key size");
    mac.update(&client.client_random);
    mac.update(&response);
    response[11..43].copy_from_slice(&mac.finalize().into_bytes());
    response
}

/// TLS record headers and empty records do not consume MTProto keystream.
/// Reads go directly into the caller's buffer. Writes retain at most one 16 KiB
/// record so partial writes and cancellation never discard a record suffix.
/// Call `flush()` after a write batch, as with other buffered AsyncWrite types.
pub struct FakeTlsStream<S> {
    inner: S,
    read_header: [u8; 5],
    read_header_len: usize,
    read_remaining: usize,
    read_ccs: bool,
    read_eof: bool,
    write_record: Vec<u8>,
    write_offset: usize,
}

impl<S> FakeTlsStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            read_header: [0; 5],
            read_header_len: 0,
            read_remaining: 0,
            read_ccs: false,
            read_eof: false,
            write_record: Vec::new(),
            write_offset: 0,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for FakeTlsStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 || this.read_eof {
            return Poll::Ready(Ok(()));
        }
        // Yield after many empty/CCS records so an always-ready peer cannot
        // monopolize the single-thread router runtime.
        for _ in 0..32 {
            if this.read_remaining != 0 {
                if this.read_ccs {
                    let mut ccs = [0];
                    let mut buf = ReadBuf::new(&mut ccs);
                    ready!(Pin::new(&mut this.inner).poll_read(cx, &mut buf))?;
                    if buf.filled().is_empty() {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "truncated TLS ChangeCipherSpec",
                        )));
                    }
                    if ccs[0] != 1 {
                        return Poll::Ready(Err(invalid("invalid TLS ChangeCipherSpec")));
                    }
                    this.read_remaining = 0;
                    this.read_ccs = false;
                    continue;
                }
                let n = output.remaining().min(this.read_remaining);
                let mut buf = ReadBuf::new(output.initialize_unfilled_to(n));
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut buf))?;
                let received = buf.filled().len();
                if received == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated TLS application record",
                    )));
                }
                this.read_remaining -= received;
                output.advance(received);
                return Poll::Ready(Ok(()));
            }

            let mut buf = ReadBuf::new(&mut this.read_header[this.read_header_len..]);
            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut buf))?;
            let received = buf.filled().len();
            if received == 0 {
                if this.read_header_len != 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated TLS record header",
                    )));
                }
                this.read_eof = true;
                return Poll::Ready(Ok(()));
            }
            this.read_header_len += received;
            if this.read_header_len != 5 {
                continue;
            }
            let header = this.read_header;
            this.read_header_len = 0;
            if header[1..3] != [0x03, 0x03] {
                return Poll::Ready(Err(invalid("invalid TLS record version")));
            }
            let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
            match header[0] {
                0x14 if length == 1 => this.read_ccs = true,
                // TLS 1.3 allows 256 bytes of record expansion.
                0x17 if length <= TLS_APP_DATA_MAX + 256 => {}
                0x15 => {
                    this.read_eof = true;
                    return Poll::Ready(Ok(()));
                }
                _ => return Poll::Ready(Err(invalid("unexpected TLS record"))),
            }
            this.read_remaining = length;
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl<S: AsyncWrite + Unpin> FakeTlsStream<S> {
    fn poll_drain_record(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        for _ in 0..64 {
            if self.write_offset == self.write_record.len() {
                self.write_record.clear();
                self.write_offset = 0;
                return Poll::Ready(Ok(()));
            }
            let n =
                ready!(Pin::new(&mut self.inner)
                    .poll_write(cx, &self.write_record[self.write_offset..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "TLS record write returned zero",
                )));
            }
            self.write_offset += n;
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for FakeTlsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_drain_record(cx))?;
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = data.len().min(TLS_APP_DATA_MAX);
        this.write_record.reserve_exact(5 + n);
        this.write_record.extend_from_slice(&[0x17, 0x03, 0x03]);
        this.write_record
            .extend_from_slice(&(n as u16).to_be_bytes());
        this.write_record.extend_from_slice(&data[..n]);
        if let Poll::Ready(Err(error)) = this.poll_drain_record(cx) {
            return Poll::Ready(Err(error));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain_record(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain_record(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn client_hello(secret: &[u8; 16], timestamp: u32) -> Vec<u8> {
        let mut hello = vec![0; 76];
        hello[..11].copy_from_slice(&[0x16, 0x03, 1, 0, 71, 1, 0, 0, 67, 0x03, 0x03]);
        hello[43] = 32;
        hello[44..].copy_from_slice(&[0xa5; 32]);
        let mut mac = HmacSha256::new_from_slice(secret).unwrap();
        mac.update(&hello);
        let expected = mac.finalize().into_bytes();
        hello[11..43].copy_from_slice(&expected);
        for (i, byte) in timestamp.to_le_bytes().into_iter().enumerate() {
            hello[39 + i] ^= byte;
        }
        hello
    }

    #[test]
    fn authenticates_hmac_and_timestamp_boundaries() {
        let secret = *b"0123456789abcdef";
        let now = 1_800_000_000;
        let hello = client_hello(&secret, now as u32);
        assert_eq!(
            authenticate(&hello, &secret, now).unwrap().client_random,
            hello[11..43]
        );
        assert!(authenticate(&hello, b"fedcba9876543210", now).is_err());
        for delta in [-120_i64, 120] {
            assert!(authenticate(
                &client_hello(&secret, (now as i64 + delta) as u32),
                &secret,
                now
            )
            .is_ok());
        }
        for delta in [-121_i64, 121] {
            assert!(authenticate(
                &client_hello(&secret, (now as i64 + delta) as u32),
                &secret,
                now
            )
            .is_err());
        }
        for position in [0, 5, 11, 38, 75] {
            let mut tampered = hello.clone();
            tampered[position] ^= 0x55;
            assert!(authenticate(&tampered, &secret, now).is_err());
        }
        for end in 0..43 {
            assert!(authenticate(&hello[..end], &secret, now).is_err());
        }
    }

    #[test]
    fn server_hello_matches_upstream_hmac_layout() {
        let secret = *b"0123456789abcdef";
        let hello = authenticate(
            &client_hello(&secret, 1_800_000_000),
            &secret,
            1_800_000_000,
        )
        .unwrap();
        let mut response = build_server_hello(&secret, &hello);
        assert_eq!(&response[44..76], &hello.session_id);
        assert_eq!(&response[127..133], CCS_FRAME);
        let app_size = usize::from(u16::from_be_bytes([response[136], response[137]]));
        assert!((1900..=2100).contains(&app_size));
        assert_eq!(response.len(), app_size + 138);
        let random = response[11..43].to_vec();
        response[11..43].fill(0);
        let mut mac = HmacSha256::new_from_slice(&secret).unwrap();
        mac.update(&hello.client_random);
        mac.update(&response);
        assert_eq!(&mac.finalize().into_bytes()[..], &random);
    }

    fn records(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for chunk in payload.chunks(TLS_APP_DATA_MAX) {
            out.extend_from_slice(&[0x17, 0x03, 0x03]);
            out.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
            out.extend_from_slice(chunk);
        }
        out
    }

    // Force record headers and payloads to be fragmented at arbitrary offsets.
    struct Fragmented<R>(R);
    impl<R: AsyncRead + Unpin> AsyncRead for Fragmented<R> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            output: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if output.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            let mut one = ReadBuf::new(output.initialize_unfilled_to(1));
            ready!(Pin::new(&mut self.get_mut().0).poll_read(cx, &mut one))?;
            let n = one.filled().len();
            output.advance(n);
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn reads_fragmented_empty_and_ccs_records() {
        let payload = vec![0x61; TLS_APP_DATA_MAX + 7];
        let mut input = CCS_FRAME.to_vec();
        // More empty records than the cooperative poll budget must still work.
        for _ in 0..40 {
            input.extend_from_slice(&[0x17, 0x03, 0x03, 0, 0]);
        }
        input.extend_from_slice(&records(&payload));
        let mut stream = FakeTlsStream::new(Fragmented(input.as_slice()));
        assert_eq!(stream.read(&mut []).await.unwrap(), 0);
        let mut actual = Vec::new();
        stream.read_to_end(&mut actual).await.unwrap();
        assert_eq!(actual, payload);
    }

    #[tokio::test]
    async fn detects_truncated_and_oversized_records() {
        for input in [
            vec![0x17, 0x03],
            vec![0x17, 0x03, 0x03, 0, 2, 0x11],
            vec![0x14, 0x03, 0x03, 0, 1],
            vec![0x17, 0x03, 0x03, 0xff, 0xff],
            vec![0x14, 0x03, 0x03, 0, 1, 0],
        ] {
            let mut stream = FakeTlsStream::new(input.as_slice());
            assert!(stream.read_to_end(&mut Vec::new()).await.is_err());
        }
    }

    #[tokio::test]
    async fn writes_large_payload_through_backpressure() {
        let (writer, mut reader) = tokio::io::duplex(7);
        let payload = vec![0x63; 2 * TLS_APP_DATA_MAX + 3];
        let expected = records(&payload);
        let send = async {
            let mut tls = FakeTlsStream::new(writer);
            tls.write_all(&payload).await.unwrap();
            tls.shutdown().await.unwrap();
        };
        let receive = async {
            let mut actual = Vec::new();
            reader.read_to_end(&mut actual).await.unwrap();
            actual
        };
        let ((), actual) = tokio::join!(send, receive);
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn cancelled_write_leaves_previous_accepted_record_intact() {
        let (writer, mut reader) = tokio::io::duplex(1);
        let mut tls = FakeTlsStream::new(writer);
        tls.write_all(b"first").await.unwrap();
        // A pending second write must not consume any of its input.
        let mut second = Box::pin(tls.write_all(b"discarded"));
        std::future::poll_fn(|cx| {
            assert!(second.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(second);
        let send = async {
            tls.write_all(b"next").await.unwrap();
            tls.shutdown().await.unwrap();
        };
        let receive = async {
            let mut actual = Vec::new();
            reader.read_to_end(&mut actual).await.unwrap();
            actual
        };
        let ((), actual) = tokio::join!(send, receive);
        let mut expected = records(b"first");
        expected.extend_from_slice(&records(b"next"));
        assert_eq!(actual, expected);
    }
}
