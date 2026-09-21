mod config;
mod crypto;
mod fake_tls;
mod framing;
mod proxy;
mod stats;
#[cfg(feature = "webui")]
mod update;
mod upstream;
#[cfg(feature = "webui")]
mod web;
mod websocket;

use config::Config;
use std::{
    collections::BTreeMap,
    io,
    net::IpAddr,
    path::PathBuf,
    sync::{Arc, RwLock},
};
use tokio::sync::{mpsc, oneshot};

pub struct Change {
    pub config: Config,
    pub reply: oneshot::Sender<Result<(), String>>,
}

fn default_path() -> PathBuf {
    if std::path::Path::new("/opt/etc").is_dir() {
        "/opt/etc/tgwsproxy/config.json".into()
    } else {
        "/etc/tgwsproxy/config.json".into()
    }
}

fn main() {
    if let Err(error) = entry() {
        eprintln!("tgwsproxy: {error}");
        std::process::exit(1);
    }
}

fn entry() -> io::Result<()> {
    let mut path = default_path();
    let mut action = "run";
    let mut no_webui = false;
    let mut no_secure = false;
    let mut dc_ips: Option<Vec<String>> = None;
    let mut args = std::env::args().skip(1).peekable();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => {
                path = args
                    .next()
                    .ok_or_else(|| config::invalid("--config needs a path"))?
                    .into()
            }
            "--init-config" => action = "init",
            "--check-config" => action = "check",
            "--print-link" => action = "link",
            "--no-webui" => no_webui = true,
            "--no-secure" => no_secure = true,
            "--dc-ip" => {
                // Keep the option optional without relying on Iterator::next_if,
                // which is newer than the Rust toolchains used by some targets.
                let value = match args.peek() {
                    Some(value) if !value.starts_with('-') => args.next(),
                    _ => None,
                };
                match value {
                    Some(value) => dc_ips.get_or_insert_with(Vec::new).push(value),
                    // A bare --dc-ip deliberately clears the built-in redirects,
                    // matching Flowseal v1.10.4's command-line behavior.
                    None => dc_ips = Some(Vec::new()),
                }
            }
            "--version" | "-V" => {
                println!(
                    "tgwsproxy {} (Rust; upstream {} {})",
                    env!("CARGO_PKG_VERSION"),
                    config::UPSTREAM_VERSION,
                    config::UPSTREAM_COMMIT
                );
                return Ok(());
            }
            "--help" | "-h" => {
                println!("tgwsproxy {}\n\nUsage: tgwsproxy [--config PATH] [--no-webui] [--no-secure] [--dc-ip [DC:IP]]...\n       tgwsproxy [--config PATH] --init-config|--check-config|--print-link\n\nOne process, foreground; OpenWrt procd / Entware init manages startup.\nSIGHUP reloads the saved configuration; SIGTERM shuts down.\nUpdates: run the release install.sh again.\nDefault config: {}", env!("CARGO_PKG_VERSION"), path.display());
                return Ok(());
            }
            _ => return Err(config::invalid(format!("unknown option {arg}; use --help"))),
        }
    }
    if action == "init" {
        if path.exists() {
            Config::load(&path)?;
            println!("Existing config preserved: {}", path.display());
        } else {
            let cfg = Config {
                secret: config::random_hex(),
                ..Config::default()
            };
            cfg.save(&path)?;
            println!("Created {}", path.display());
        }
        return Ok(());
    }
    let mut cfg = Config::load(&path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("{}: {e}; use --init-config for first setup", path.display()),
        )
    })?;
    if let Some(entries) = dc_ips {
        cfg.dc_redirects = parse_dc_redirects(&entries)?;
    }
    if no_secure {
        cfg.disable_secure = true;
    }
    cfg.validate()?;
    match action {
        "check" => {
            println!("Configuration OK");
            return Ok(());
        }
        "link" => {
            let host = if cfg.host == "0.0.0.0" || cfg.host == "::" {
                let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
                // UDP connect chooses a route without sending a packet.
                socket.connect("1.1.1.1:80")?;
                socket.local_addr()?.ip().to_string()
            } else {
                cfg.host.clone()
            };
            println!("{}", cfg.link(&host));
            return Ok(());
        }
        _ => {}
    }
    configure_ca_bundle(cfg.verbose);
    tokio::runtime::Builder::new_current_thread()
        .max_blocking_threads(2)
        .thread_stack_size(256 * 1024)
        .thread_keep_alive(std::time::Duration::from_secs(10))
        .enable_all()
        .build()?
        .block_on(serve(cfg, path, no_webui))
}

fn parse_dc_redirects(entries: &[String]) -> io::Result<BTreeMap<i16, String>> {
    let mut redirects = BTreeMap::new();
    for entry in entries {
        let (dc, ip) = entry
            .split_once(':')
            .ok_or_else(|| config::invalid(format!("invalid --dc-ip {entry:?}; expected DC:IP")))?;
        let dc = dc
            .parse::<i16>()
            .map_err(|_| config::invalid(format!("invalid --dc-ip {entry:?}")))?;
        ip.parse::<IpAddr>()
            .map_err(|_| config::invalid(format!("invalid --dc-ip {entry:?}")))?;
        redirects.insert(dc, ip.to_owned());
    }
    Ok(redirects)
}

fn configure_ca_bundle(verbose: bool) {
    let candidates = [
        (
            "/opt/etc/ssl/certs/ca-certificates.crt",
            "/opt/etc/ssl/certs",
        ),
        ("/etc/ssl/certs/ca-certificates.crt", "/etc/ssl/certs"),
        ("/etc/ssl/cert.pem", "/etc/ssl/certs"),
        ("/etc/ssl/certs/ca-bundle.crt", "/etc/ssl/certs"),
    ];
    let current_file = std::env::var_os("SSL_CERT_FILE");
    let current_dir = std::env::var_os("SSL_CERT_DIR");
    if current_file.is_none() {
        if let Some((file, dir)) = candidates
            .iter()
            .find(|(file, _)| std::fs::metadata(file).is_ok_and(|meta| meta.is_file()))
        {
            // Native TLS reads these variables when its connector is built.
            std::env::set_var("SSL_CERT_FILE", file);
            if current_dir.is_none() && std::fs::metadata(dir).is_ok_and(|meta| meta.is_dir()) {
                std::env::set_var("SSL_CERT_DIR", dir);
            }
            if verbose {
                eprintln!("tgws: verified TLS CA bundle: {file}");
            }
            return;
        }
    }
    if verbose {
        if let Some(file) = current_file {
            eprintln!("tgws: verified TLS CA bundle: {}", file.to_string_lossy());
        } else {
            eprintln!("tgws: verified TLS CA bundle was not found; install ca-bundle");
        }
    }
}

async fn serve(cfg: Config, path: PathBuf, no_webui: bool) -> io::Result<()> {
    let shared = Arc::new(RwLock::new(cfg.clone()));
    let stats = Arc::new(stats::Stats::default());
    let mut proxy = proxy::Proxy::start(Arc::new(cfg.clone()), stats.clone()).await?;
    let (_changes, mut receiver) = mpsc::channel::<Change>(4);
    #[cfg(feature = "webui")]
    let _web = if no_webui {
        None
    } else {
        Some(web::Web::start(shared.clone(), stats.clone(), _changes.clone(), &path).await?)
    };
    #[cfg(not(feature = "webui"))]
    let _ = no_webui;
    eprintln!(
        "tgwsproxy {} / upstream {} listening on {}; buffer={} pool={} max_clients={}",
        env!("CARGO_PKG_VERSION"),
        config::UPSTREAM_VERSION,
        proxy.local_addr(),
        cfg.buffer_size,
        cfg.pool_size,
        cfg.max_connections
    );
    let mut current = cfg;
    #[cfg(unix)]
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    #[cfg(unix)]
    let mut reload = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);
    loop {
        let change = tokio::select! {
            _ = &mut shutdown => break,
            _ = async {
                #[cfg(unix)] { terminate.recv().await; }
                #[cfg(not(unix))] { std::future::pending::<()>().await; }
            } => break,
            _ = async {
                #[cfg(unix)] { reload.recv().await; }
                #[cfg(not(unix))] { std::future::pending::<()>().await; }
            } => {
                match Config::load(&path) {
                    Ok(config) => { let (reply, _) = oneshot::channel(); Some(Change { config, reply }) }
                    Err(error) => { eprintln!("reload refused: {error}"); None }
                }
            },
            change = receiver.recv() => change,
        };
        let Some(change) = change else {
            continue;
        };
        let result = apply(&mut proxy, &current, &change.config, &path, stats.clone()).await;
        match result {
            Ok(()) => {
                current = change.config;
                *shared.write().unwrap() = current.clone();
                let _ = change.reply.send(Ok(()));
            }
            Err(error) => {
                eprintln!("config update refused: {error}");
                let _ = change.reply.send(Err(error.to_string()));
            }
        }
    }
    proxy.shutdown().await;
    Ok(())
}

async fn apply(
    proxy: &mut proxy::Proxy,
    old: &Config,
    new: &Config,
    path: &std::path::Path,
    stats: Arc<stats::Stats>,
) -> io::Result<()> {
    new.validate()?;
    if (old.web_host.as_str(), old.web_port) != (new.web_host.as_str(), new.web_port) {
        return Err(config::invalid(
            "To change the panel address, edit the config file and restart the service",
        ));
    }
    if old.port != new.port {
        // Reserve a new port before stopping the running listener.
        let mut replacement = proxy::Proxy::start(Arc::new(new.clone()), stats).await?;
        if let Err(error) = new.save(path) {
            replacement.shutdown().await;
            return Err(error);
        }
        proxy.shutdown().await;
        *proxy = replacement;
    } else {
        // Save first so I/O failure cannot disrupt existing connections.
        new.save(path)?;
        proxy.shutdown().await;
        match proxy::Proxy::start(Arc::new(new.clone()), stats.clone()).await {
            Ok(replacement) => *proxy = replacement,
            Err(error) => {
                let restore = old.save(path);
                *proxy = proxy::Proxy::start(Arc::new(old.clone()), stats)
                    .await
                    .map_err(|e| {
                        io::Error::other(format!("start failed: {error}; rollback failed: {e}"))
                    })?;
                restore?;
                return Err(error);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::parse_dc_redirects;

    #[test]
    fn parses_and_overwrites_dc_redirects() {
        let parsed = parse_dc_redirects(&[
            "2:149.154.167.220".into(),
            "4:149.154.167.220".into(),
            "2:149.154.167.221".into(),
        ])
        .unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[&2], "149.154.167.221");
    }

    #[test]
    fn rejects_malformed_dc_redirects() {
        assert!(parse_dc_redirects(&["2".into()]).is_err());
        assert!(parse_dc_redirects(&["2:not-an-ip".into()]).is_err());
    }
}
