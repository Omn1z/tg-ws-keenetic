mod cf_h2;
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

#[derive(Clone, Default)]
struct RuntimeOverrides {
    dc_redirects: Option<BTreeMap<i16, String>>,
    no_secure: bool,
    no_h2: bool,
}

impl RuntimeOverrides {
    fn apply(&self, config: &mut Config) {
        if let Some(redirects) = &self.dc_redirects {
            config.dc_redirects = redirects.clone();
        }
        if self.no_secure {
            config.disable_secure = true;
        }
        if self.no_h2 {
            config.cfproxy_h2_media = false;
        }
    }
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
    let mut no_h2 = false;
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
            "--no-h2" => no_h2 = true,
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
                    // matching Flowseal v1.11.1's command-line behavior.
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
                println!("tgwsproxy {}\n\nUsage: tgwsproxy [--config PATH] [--no-webui] [--no-secure] [--no-h2] [--dc-ip [DC:IP]]...\n       tgwsproxy [--config PATH] --init-config|--check-config|--print-link\n\nOne process, foreground; OpenWrt procd / Entware init manages startup.\nSIGHUP reloads the saved configuration; SIGTERM shuts down.\nUpdates: run the release install.sh again.\nDefault config: {}", env!("CARGO_PKG_VERSION"), path.display());
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
    let overrides = RuntimeOverrides {
        dc_redirects: dc_ips.as_deref().map(parse_dc_redirects).transpose()?,
        no_secure,
        no_h2,
    };
    let saved_cfg = cfg.clone();
    overrides.apply(&mut cfg);
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
        .block_on(serve(cfg, saved_cfg, path, no_webui, overrides))
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

async fn serve(
    cfg: Config,
    saved_cfg: Config,
    path: PathBuf,
    no_webui: bool,
    overrides: RuntimeOverrides,
) -> io::Result<()> {
    // The panel edits the file-backed values. CLI flags are applied only to
    // the effective runtime config and must never leak into config.json.
    let shared = Arc::new(RwLock::new(saved_cfg.clone()));
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
    let mut current_saved = saved_cfg;
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
                    Ok(config) => { let (reply, _) = oneshot::channel(); Some((Change { config, reply }, false)) }
                    Err(error) => { eprintln!("reload refused: {error}"); None }
                }
            },
            change = receiver.recv() => change.map(|change| (change, true)),
        };
        let Some((mut change, persist)) = change else {
            continue;
        };
        let saved = change.config.clone();
        overrides.apply(&mut change.config);
        let persistence = persist.then_some((&current_saved, &saved));
        let result = apply(
            &mut proxy,
            &current,
            &change.config,
            persistence,
            &path,
            stats.clone(),
        )
        .await;
        match result {
            Ok(()) => {
                current = change.config;
                current_saved = saved;
                *shared.write().unwrap() = current_saved.clone();
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
    persistence: Option<(&Config, &Config)>,
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
        if let Some((_, saved)) = persistence {
            if let Err(error) = saved.save(path) {
                replacement.shutdown().await;
                return Err(error);
            }
        }
        proxy.shutdown().await;
        *proxy = replacement;
    } else {
        // Save first so I/O failure cannot disrupt existing connections.
        if let Some((_, saved)) = persistence {
            saved.save(path)?;
        }
        proxy.shutdown().await;
        match proxy::Proxy::start(Arc::new(new.clone()), stats.clone()).await {
            Ok(replacement) => *proxy = replacement,
            Err(error) => {
                let restore = persistence
                    .map(|(previous, _)| previous.save(path))
                    .unwrap_or(Ok(()));
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
    use super::{apply, parse_dc_redirects, RuntimeOverrides};
    use crate::config::Config;
    use std::{collections::BTreeMap, sync::Arc};

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

    #[test]
    fn runtime_overrides_do_not_mutate_saved_config() {
        let overrides = RuntimeOverrides {
            dc_redirects: Some([(2, "149.154.167.221".into())].into()),
            no_secure: true,
            no_h2: true,
        };
        let saved = Config::default();
        let mut reloaded = saved.clone();
        overrides.apply(&mut reloaded);
        assert_eq!(reloaded.dc_redirects[&2], "149.154.167.221");
        assert_eq!(reloaded.dc_redirects.len(), 1);
        assert!(reloaded.disable_secure);
        assert!(!reloaded.cfproxy_h2_media);
        assert_ne!(saved.dc_redirects, reloaded.dc_redirects);
        assert!(!saved.disable_secure);
        assert!(saved.cfproxy_h2_media);
    }

    #[tokio::test]
    async fn reload_only_applies_cli_overrides_in_memory() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let path = std::env::temp_dir().join(format!(
            "tgwsproxy-reload-{}-{}.json",
            std::process::id(),
            rand::random::<u64>()
        ));
        let saved = Config {
            host: "127.0.0.1".into(),
            port,
            web_port: if port == u16::MAX { port - 1 } else { port + 1 },
            secret: "00".repeat(16),
            domain_refresh: false,
            ..Config::default()
        };
        saved.save(&path).unwrap();
        let overrides = RuntimeOverrides {
            dc_redirects: Some(BTreeMap::new()),
            no_secure: true,
            no_h2: true,
        };
        let mut effective = saved.clone();
        overrides.apply(&mut effective);
        let stats = Arc::new(crate::stats::Stats::default());
        let mut proxy = crate::proxy::Proxy::start(Arc::new(effective.clone()), stats.clone())
            .await
            .unwrap();

        apply(&mut proxy, &effective, &effective, None, &path, stats)
            .await
            .unwrap();
        proxy.shutdown().await;

        let reloaded = Config::load(&path).unwrap();
        assert_eq!(reloaded.dc_redirects, saved.dc_redirects);
        assert_eq!(reloaded.disable_secure, saved.disable_secure);
        assert_eq!(reloaded.cfproxy_h2_media, saved.cfproxy_h2_media);
        std::fs::remove_file(path).unwrap();
    }
}
