mod config;
mod crypto;
mod fake_tls;
mod framing;
mod proxy;
mod stats;
mod upstream;
#[cfg(feature = "webui")]
mod web;
mod websocket;

use config::Config;
use std::{
    io,
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
    let mut args = std::env::args().skip(1);
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
                println!("tgwsproxy {}\n\nUsage: tgwsproxy [--config PATH] [--no-webui]\n       tgwsproxy [--config PATH] --init-config|--check-config|--print-link\n\nOne process, foreground; OpenWrt procd / Entware init manages startup.\nSIGHUP reloads the saved configuration; SIGTERM shuts down.\nUpdates: run the release install.sh again.\nDefault config: {}", env!("CARGO_PKG_VERSION"), path.display());
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
    let cfg = Config::load(&path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("{}: {e}; use --init-config for first setup", path.display()),
        )
    })?;
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
    tokio::runtime::Builder::new_current_thread()
        .max_blocking_threads(2)
        .thread_stack_size(256 * 1024)
        .thread_keep_alive(std::time::Duration::from_secs(10))
        .enable_all()
        .build()?
        .block_on(serve(cfg, path, no_webui))
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
        Some(web::Web::start(shared.clone(), stats.clone(), _changes.clone()).await?)
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
