use crate::{
    config::{self, Config},
    stats::Stats,
    Change,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io,
    net::IpAddr,
    sync::{Arc, RwLock},
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot, Semaphore},
    task::{JoinHandle, JoinSet},
    time::timeout,
};

pub struct Web {
    task: JoinHandle<()>,
}
impl Drop for Web {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct State {
    config: Arc<RwLock<Config>>,
    stats: Arc<Stats>,
    changes: mpsc::Sender<Change>,
    csrf: String,
    mutation: tokio::sync::Mutex<()>,
    updater: Arc<crate::update::Updater>,
}

impl Web {
    pub async fn start(
        config: Arc<RwLock<Config>>,
        stats: Arc<Stats>,
        changes: mpsc::Sender<Change>,
        path: &std::path::Path,
    ) -> io::Result<Self> {
        let cfg = config.read().unwrap().clone();
        let listener = TcpListener::bind((cfg.web_host.as_str(), cfg.web_port)).await?;
        eprintln!("Panel http://{}:{}/", cfg.web_host, cfg.web_port);
        let state = Arc::new(State {
            config,
            stats,
            changes,
            csrf: config::random_hex(),
            mutation: tokio::sync::Mutex::new(()),
            updater: crate::update::Updater::new(path),
        });
        let task = tokio::spawn(async move {
            let slots = Arc::new(Semaphore::new(8));
            let mut clients = JoinSet::new();
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        match result {
                            Ok((stream, _)) => {
                                if let Ok(permit) = slots.clone().try_acquire_owned() {
                                    let state = state.clone();
                                    clients.spawn(async move {
                                        let _permit = permit;
                                        let _ = timeout(Duration::from_secs(15), handle(stream, state)).await;
                                    });
                                }
                            }
                            Err(_) => tokio::time::sleep(Duration::from_millis(200)).await,
                        }
                    }
                    _ = clients.join_next(), if !clients.is_empty() => {}
                }
            }
        });
        Ok(Self { task })
    }
}

struct Request {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

async fn read_request<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
) -> io::Result<Request> {
    let mut head = Vec::with_capacity(1024);
    loop {
        // Limit each append before reading; a peer cannot force an oversized allocation.
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Err(config::invalid("incomplete HTTP headers"));
        }
        let take = available
            .iter()
            .position(|b| *b == b'\n')
            .map_or(available.len(), |i| i + 1);
        if head.len() + take > 8192 {
            return Err(config::invalid("HTTP headers too large"));
        }
        head.extend_from_slice(&available[..take]);
        reader.consume(take);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let text = std::str::from_utf8(&head).map_err(|_| config::invalid("invalid HTTP headers"))?;
    let mut lines = text.split("\r\n");
    let first: Vec<_> = lines.next().unwrap_or_default().split(' ').collect();
    if first.len() != 3 || first[2] != "HTTP/1.1" {
        return Err(config::invalid("HTTP/1.1 required"));
    }
    let method = first[0].to_string();
    let path = first[1].to_string();
    let mut headers = BTreeMap::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (key, value) = line
            .split_once(':')
            .ok_or_else(|| config::invalid("bad header"))?;
        if key.is_empty() || !key.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-') {
            return Err(config::invalid("bad header name"));
        }
        if headers
            .insert(key.to_ascii_lowercase(), value.trim().to_string())
            .is_some()
        {
            return Err(config::invalid("duplicate header"));
        }
    }
    if headers.contains_key("transfer-encoding") {
        return Err(config::invalid("chunked requests are unsupported"));
    }
    let length = headers.get("content-length").map_or(Ok(0usize), |s| {
        s.parse().map_err(|_| config::invalid("bad content length"))
    })?;
    if length > 32768 {
        return Err(config::invalid("request body exceeds 32 KiB"));
    }
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body).await?;
    Ok(Request {
        method,
        path,
        headers,
        body,
    })
}

fn same_secret(a: &[u8], b: &[u8]) -> bool {
    Sha256::digest(a).ct_eq(&Sha256::digest(b)).into()
}

fn hostname(host: &str) -> Option<String> {
    if host.starts_with('[') {
        let close = host.find(']')?;
        let tail = &host[close + 1..];
        if !tail.is_empty() && (!tail.starts_with(':') || tail[1..].parse::<u16>().is_err()) {
            return None;
        }
        host[1..close].parse::<IpAddr>().ok()?;
        Some(host[1..close].into())
    } else {
        let (name, port) = host
            .split_once(':')
            .map_or((host, None), |(a, b)| (a, Some(b)));
        if port.is_some_and(|p| p.parse::<u16>().is_err()) {
            return None;
        }
        if name == "localhost" || name.parse::<IpAddr>().is_ok() || config::valid_domain(name) {
            Some(name.into())
        } else {
            None
        }
    }
}

async fn handle(stream: TcpStream, state: Arc<State>) -> io::Result<()> {
    let local_ip = stream.local_addr()?.ip();
    let mut reader = BufReader::with_capacity(4096, stream);
    let request = match read_request(&mut reader).await {
        Ok(req) => req,
        Err(_) => {
            return respond(
                reader.get_mut(),
                400,
                "text/plain",
                b"Invalid or oversized HTTP request",
                false,
            )
            .await
        }
    };
    // Snapshot and authenticate AFTER taking the mutation lock. Otherwise two
    // concurrent POSTs can overwrite a newly saved password with stale state.
    let _mutation = if request.method == "POST" {
        Some(state.mutation.lock().await)
    } else {
        None
    };
    let cfg = state.config.read().unwrap().clone();
    let Some(host) = request.headers.get("host").and_then(|s| hostname(s)) else {
        return respond(reader.get_mut(), 400, "text/plain", b"Invalid Host", false).await;
    };
    // Restrict Host to the destination IP or the explicitly configured name.
    // Together with CSRF this prevents a DNS-rebinding page from reading secrets.
    if host.parse::<IpAddr>().ok() != Some(local_ip)
        && host != cfg.link_host
        && !(host == "localhost" && local_ip.is_loopback())
    {
        return respond(
            reader.get_mut(),
            403,
            "text/plain",
            b"Use the router IP or configured link_host",
            false,
        )
        .await;
    }
    if !cfg.web_password.is_empty() {
        let expected = format!("{}:{}", cfg.web_user, cfg.web_password);
        let supplied = request
            .headers
            .get("authorization")
            .and_then(|h| h.strip_prefix("Basic "))
            .and_then(|value| STANDARD.decode(value).ok())
            .unwrap_or_default();
        if !same_secret(&supplied, expected.as_bytes()) {
            return respond(
                reader.get_mut(),
                401,
                "text/plain",
                b"Authentication required",
                true,
            )
            .await;
        }
    }
    if request.method == "POST" {
        let csrf = request
            .headers
            .get("x-csrf-token")
            .map_or("", String::as_str);
        if !same_secret(csrf.as_bytes(), state.csrf.as_bytes()) {
            return respond(
                reader.get_mut(),
                403,
                "text/plain",
                b"Reload the panel before making changes",
                false,
            )
            .await;
        }
    }
    let (code, content_type, body): (u16, &str, Vec<u8>) = match (
        request.method.as_str(),
        request.path.as_str(),
    ) {
        ("GET", "/") => (
            200,
            "text/html; charset=utf-8",
            include_bytes!("../webui/index.html").to_vec(),
        ),
        ("GET", "/style.css") => (
            200,
            "text/css; charset=utf-8",
            include_bytes!("../webui/style.css").to_vec(),
        ),
        ("GET", "/app.js") => (
            200,
            "application/javascript; charset=utf-8",
            include_bytes!("../webui/app.js").to_vec(),
        ),
        ("GET", "/api/state") => {
            let mut safe_config = serde_json::to_value(&cfg).map_err(io::Error::other)?;
            safe_config.as_object_mut().unwrap().remove("web_password");
            let value = serde_json::json!({"version": env!("CARGO_PKG_VERSION"), "upstream": config::UPSTREAM_VERSION,
                "upstream_commit": config::UPSTREAM_COMMIT, "config": safe_config, "stats": state.stats.snapshot(),
                "link": cfg.link(&host), "csrf": state.csrf, "password_set": !cfg.web_password.is_empty(), "update": state.updater.status()});
            (
                200,
                "application/json",
                serde_json::to_vec(&value).map_err(io::Error::other)?,
            )
        }
        ("GET", "/api/update/check") | ("POST", "/api/update/check") => {
            let info = state.updater.check(request.method == "POST");
            (
                200,
                "application/json",
                serde_json::to_vec(&info).map_err(io::Error::other)?,
            )
        }
        ("GET", "/api/update/status") => (
            200,
            "application/json",
            serde_json::to_vec(&state.updater.status()).map_err(io::Error::other)?,
        ),
        ("POST", "/api/update") => match state.updater.start() {
            Ok(info) => (
                202,
                "application/json",
                serde_json::to_vec(&info).map_err(io::Error::other)?,
            ),
            Err(error) => (
                400,
                "application/json",
                serde_json::to_vec(&serde_json::json!({"error":error.to_string()})).unwrap(),
            ),
        },
        ("POST", "/api/config" | "/api/restart" | "/api/secret") => {
            let next = if request.path == "/api/config" {
                if !request
                    .headers
                    .get("content-type")
                    .is_some_and(|v| v.split(';').next().unwrap_or("").trim() == "application/json")
                {
                    return respond(reader.get_mut(), 415, "text/plain", b"JSON required", false)
                        .await;
                }
                merge_config(&cfg, &request.body)
            } else {
                let mut next = cfg.clone();
                if request.path == "/api/secret" {
                    next.secret = config::random_hex();
                }
                Ok(next)
            };
            let result = match next {
                Ok(config) => {
                    let (reply, receive) = oneshot::channel();
                    match state.changes.try_send(Change { config, reply }) {
                        Ok(()) => receive
                            .await
                            .unwrap_or_else(|_| Err("Service is stopping".into())),
                        Err(_) => Err("Another configuration change is in progress".into()),
                    }
                }
                Err(error) => Err(error.to_string()),
            };
            match result {
                Ok(()) => (200, "application/json", b"{\"ok\":true}".to_vec()),
                Err(error) => (
                    400,
                    "application/json",
                    serde_json::to_vec(&serde_json::json!({"error": error})).unwrap(),
                ),
            }
        }
        _ => (404, "text/plain", b"Not found".to_vec()),
    };
    respond(reader.get_mut(), code, content_type, &body, false).await
}

fn merge_config(cfg: &Config, bytes: &[u8]) -> io::Result<Config> {
    let patch: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| config::invalid(e.to_string()))?;
    let patch = patch
        .as_object()
        .ok_or_else(|| config::invalid("config must be an object"))?;
    let mut value = serde_json::to_value(cfg).map_err(io::Error::other)?;
    for (key, val) in patch {
        value[key] = val.clone();
    }
    Config::from_value(value)
}

async fn respond(
    stream: &mut TcpStream,
    code: u16,
    content_type: &str,
    body: &[u8],
    auth: bool,
) -> io::Result<()> {
    let reason = match code {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        415 => "Unsupported Media Type",
        _ => "Error",
    };
    let auth = if auth {
        "WWW-Authenticate: Basic realm=\"tgwsproxy\"\r\n"
    } else {
        ""
    };
    let header = format!("HTTP/1.1 {code} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'\r\n{auth}\r\n", body.len());
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.shutdown().await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn rejects_smuggling_and_unbounded_lengths() {
        for bytes in [
            b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nContent-Length: 8\r\n\r\n"
                .as_slice(),
            b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 999999999\r\n\r\n".as_slice(),
            b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n".as_slice(),
        ] {
            assert!(read_request(&mut BufReader::new(bytes)).await.is_err());
        }
        let huge = vec![b'x'; 9000];
        assert!(read_request(&mut BufReader::new(huge.as_slice()))
            .await
            .is_err());
    }
    #[test]
    fn host_and_password_patch() {
        assert_eq!(hostname("[::1]:1434").unwrap(), "::1");
        assert!(hostname("example.org:bad").is_none());
        let cfg = Config {
            secret: config::random_hex(),
            web_password: "saved".into(),
            ..Config::default()
        };
        assert_eq!(
            merge_config(&cfg, br#"{"port":1443}"#)
                .unwrap()
                .web_password,
            "saved"
        );
        assert!(same_secret(b"same", b"same"));
        assert!(!same_secret(b"", b"secret"));
    }
}
