//! Exercise the shipped executable, its real config file, and its HTTP socket.
//! No Telegram/network service is involved in these control-plane regressions.

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicUsize, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

const BINARY: &str = env!("CARGO_BIN_EXE_tgwsproxy");
static NEXT_DIR: AtomicUsize = AtomicUsize::new(0);

struct TestDir {
    path: PathBuf,
    base: PathBuf,
}

impl TestDir {
    fn new() -> Self {
        let base = std::env::temp_dir().canonicalize().unwrap();
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = base.join(format!(
            "tgws-control-{}-{nonce}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&path).unwrap();
        Self { path, base }
    }

    fn config(&self) -> PathBuf {
        self.path.join("config.json")
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        // Delete only the unique directory this test actually created.
        if self.path.parent() == Some(self.base.as_path())
            && self
                .path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("tgws-control-")
        {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

fn cli(path: &Path, args: &[&str]) -> Output {
    Command::new(BINARY)
        .arg("--config")
        .arg(path)
        .args(args)
        .output()
        .unwrap()
}

fn assert_success(output: Output) {
    assert!(
        output.status.success(),
        "executable failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn init_preserves_existing_secret_and_rejects_invalid_config() {
    let dir = TestDir::new();
    let path = dir.config();
    assert_success(cli(&path, &["--init-config"]));
    let before = fs::read(&path).unwrap();
    let mut config: serde_json::Value = serde_json::from_slice(&before).unwrap();
    let secret = config["secret"].as_str().unwrap();
    assert_eq!(secret.len(), 32);
    assert!(secret.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_success(cli(&path, &["--init-config"]));
    assert_eq!(
        fs::read(&path).unwrap(),
        before,
        "init must preserve saved settings"
    );
    assert_success(cli(&path, &["--check-config"]));

    config["secret"] = "not-a-valid-secret".into();
    fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    let invalid = cli(&path, &["--check-config"]);
    assert!(!invalid.status.success());
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("secret"));
    assert!(
        !cli(&path, &[]).status.success(),
        "startup must reject bad config"
    );
}

#[test]
fn corrupted_config_is_not_overwritten_or_started() {
    let dir = TestDir::new();
    let path = dir.config();
    let corrupt = b"{\"secret\": broken JSON";
    fs::write(&path, corrupt).unwrap();
    for args in [&["--init-config"][..], &["--check-config"][..], &[][..]] {
        let output = cli(&path, args);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("invalid config JSON"));
        assert_eq!(fs::read(&path).unwrap(), corrupt);
    }
}

#[cfg(feature = "webui")]
mod http {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use std::{
        io::{self, Read, Write},
        net::{SocketAddr, TcpListener, TcpStream},
        process::{Child, Stdio},
        sync::{Arc, Barrier},
        thread,
        time::{Duration, Instant},
    };

    struct Server(Child);

    impl Server {
        fn spawn(path: &Path, web_port: u16) -> Self {
            let child = Command::new(BINARY)
                .arg("--config")
                .arg(path)
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let mut server = Self(child);
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                if TcpStream::connect(("127.0.0.1", web_port)).is_ok() {
                    return server;
                }
                if let Some(exit) = server.0.try_wait().unwrap() {
                    let mut error = String::new();
                    server
                        .0
                        .stderr
                        .take()
                        .unwrap()
                        .read_to_string(&mut error)
                        .unwrap();
                    panic!("server exited during startup ({exit}): {error}");
                }
                assert!(
                    Instant::now() < deadline,
                    "server did not open its panel port"
                );
                thread::sleep(Duration::from_millis(20));
            }
        }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    struct Response {
        status: u16,
        headers: String,
        body: Vec<u8>,
    }

    fn request(
        port: u16,
        method: &str,
        path: &str,
        host: &str,
        password: Option<&str>,
        csrf: Option<&str>,
        body: Option<&serde_json::Value>,
    ) -> io::Result<Response> {
        let address: SocketAddr = ([127, 0, 0, 1], port).into();
        let mut wire = TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
        wire.set_read_timeout(Some(Duration::from_secs(5)))?;
        wire.set_write_timeout(Some(Duration::from_secs(5)))?;
        let body = body
            .map(|v| serde_json::to_vec(v).unwrap())
            .unwrap_or_default();
        let mut head = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
        if let Some(password) = password {
            head.push_str(&format!(
                "Authorization: Basic {}\r\n",
                STANDARD.encode(format!("admin:{password}"))
            ));
        }
        if let Some(csrf) = csrf {
            head.push_str(&format!("X-CSRF-Token: {csrf}\r\n"));
        }
        head.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        ));
        wire.write_all(head.as_bytes())?;
        wire.write_all(&body)?;
        let mut reply = Vec::new();
        wire.read_to_end(&mut reply)?;
        let boundary = reply
            .windows(4)
            .position(|part| part == b"\r\n\r\n")
            .ok_or_else(|| io::Error::other("incomplete HTTP response"))?;
        let headers = String::from_utf8(reply[..boundary].to_vec()).unwrap();
        let status = headers.split_whitespace().nth(1).unwrap().parse().unwrap();
        let body = reply[boundary + 4..].to_vec();
        let length: usize = headers
            .lines()
            .find_map(|line| line.strip_prefix("Content-Length: "))
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(
            length,
            body.len(),
            "HTTP response length must match its body"
        );
        Ok(Response {
            status,
            headers,
            body,
        })
    }

    fn fixture(path: &Path) -> (u16, u16) {
        // Reserve both ephemeral ports simultaneously so they cannot coincide.
        let proxy = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let web = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let proxy_port = proxy.local_addr().unwrap().port();
        let web_port = web.local_addr().unwrap().port();
        assert_success(cli(path, &["--init-config"]));
        let mut config: serde_json::Value =
            serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        config["host"] = "0.0.0.0".into();
        config["port"] = proxy_port.into();
        config["web_host"] = "127.0.0.1".into();
        config["web_port"] = web_port.into();
        config["web_user"] = "admin".into();
        config["web_password"] = "testpassword".into();
        config["domain_refresh"] = false.into();
        config["cfproxy"] = false.into();
        config["pool_size"] = 0.into();
        config["dc_redirects"] = serde_json::json!({});
        // Exercise migration when a later panel save persists the configuration.
        config
            .as_object_mut()
            .unwrap()
            .remove("cfproxy_user_domains");
        config["cfproxy_user_domain"] = "FIRST.example, second.example".into();
        config["legacy_option"] = 7.into();
        fs::write(path, serde_json::to_vec(&config).unwrap()).unwrap();
        (proxy_port, web_port)
    }

    #[test]
    fn panel_auth_csrf_migration_and_listener_changes_work_end_to_end() {
        let dir = TestDir::new();
        let path = dir.config();
        let (proxy_port, web_port) = fixture(&path);
        let _server = Server::spawn(&path, web_port);
        let host = format!("127.0.0.1:{web_port}");

        let unauthenticated =
            request(web_port, "GET", "/api/state", &host, None, None, None).unwrap();
        assert_eq!(unauthenticated.status, 401);
        assert!(unauthenticated.headers.contains("WWW-Authenticate: Basic"));
        let forbidden = request(
            web_port,
            "GET",
            "/api/state",
            "rebinding.example",
            Some("testpassword"),
            None,
            None,
        )
        .unwrap();
        assert_eq!(forbidden.status, 403);
        let state = request(
            web_port,
            "GET",
            "/api/state",
            &host,
            Some("testpassword"),
            None,
            None,
        )
        .unwrap();
        assert_eq!(state.status, 200);
        let state: serde_json::Value = serde_json::from_slice(&state.body).unwrap();
        assert!(state["config"].get("web_password").is_none());
        assert_eq!(
            state["config"]["cfproxy_user_domains"],
            serde_json::json!(["first.example", "second.example"])
        );
        let original_secret = state["config"]["secret"].clone();
        let csrf = state["csrf"].as_str().unwrap();
        for token in [None, Some("invalid-token")] {
            let denied = request(
                web_port,
                "POST",
                "/api/restart",
                &host,
                Some("testpassword"),
                token,
                None,
            )
            .unwrap();
            assert_eq!(denied.status, 403);
        }

        // A wildcard listener must be replaceable by a specific IP on the same port.
        let narrowed = request(
            web_port,
            "POST",
            "/api/config",
            &host,
            Some("testpassword"),
            Some(csrf),
            Some(&serde_json::json!({"host":"127.0.0.1"})),
        )
        .unwrap();
        assert_eq!(
            narrowed.status,
            200,
            "{}",
            String::from_utf8_lossy(&narrowed.body)
        );
        assert!(TcpStream::connect(("127.0.0.1", proxy_port)).is_ok());

        let reservation = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let next_port = reservation.local_addr().unwrap().port();
        drop(reservation);
        let changed = request(
            web_port,
            "POST",
            "/api/config",
            &host,
            Some("testpassword"),
            Some(csrf),
            Some(&serde_json::json!({"port": next_port})),
        )
        .unwrap();
        assert_eq!(
            changed.status,
            200,
            "{}",
            String::from_utf8_lossy(&changed.body)
        );
        assert!(TcpStream::connect(("127.0.0.1", next_port)).is_ok());
        assert!(TcpStream::connect(("127.0.0.1", proxy_port)).is_err());

        let saved: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(saved["port"], next_port);
        assert_eq!(saved["secret"], original_secret);
        assert_eq!(saved["web_password"], "testpassword");
        assert_eq!(saved["legacy_option"], 7);
        assert_eq!(
            saved["cfproxy_user_domains"],
            serde_json::json!(["first.example", "second.example"])
        );
        assert!(saved.get("cfproxy_user_domain").is_none());

        let restarted = request(
            web_port,
            "POST",
            "/api/restart",
            &host,
            Some("testpassword"),
            Some(csrf),
            None,
        )
        .unwrap();
        assert_eq!(restarted.status, 200);
        assert!(TcpStream::connect(("127.0.0.1", next_port)).is_ok());
        assert_success(cli(&path, &["--check-config"]));
    }

    #[test]
    fn simultaneous_config_patches_preserve_both_changes() {
        let dir = TestDir::new();
        let path = dir.config();
        let (_, web_port) = fixture(&path);
        let _server = Server::spawn(&path, web_port);
        let host = format!("127.0.0.1:{web_port}");
        let response = request(
            web_port,
            "GET",
            "/api/state",
            &host,
            Some("testpassword"),
            None,
            None,
        )
        .unwrap();
        assert_eq!(response.status, 200);
        let state: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        let csrf = state["csrf"].as_str().unwrap().to_string();
        let barrier = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for patch in [
            serde_json::json!({"buffer_size":4096}),
            serde_json::json!({"max_connections":63}),
        ] {
            let barrier = barrier.clone();
            let host = host.clone();
            let csrf = csrf.clone();
            workers.push(thread::spawn(move || {
                barrier.wait();
                request(
                    web_port,
                    "POST",
                    "/api/config",
                    &host,
                    Some("testpassword"),
                    Some(&csrf),
                    Some(&patch),
                )
                .unwrap()
            }));
        }
        barrier.wait();
        for worker in workers {
            let reply = worker.join().unwrap();
            assert_eq!(
                reply.status,
                200,
                "{}",
                String::from_utf8_lossy(&reply.body)
            );
        }
        let saved: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert_eq!(saved["buffer_size"], 4096);
        assert_eq!(saved["max_connections"], 63);
        assert_eq!(saved["web_password"], "testpassword");
    }
}
