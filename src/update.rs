//! Release checks stay in memory. Only an explicit update writes staging files.
use crate::config::{hex, invalid, random_hex};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs, io,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
    time::timeout,
};

const REPO: &str = "Omn1z/tg-ws-keenetic";
const CURRENT: &str = env!("CARGO_PKG_VERSION");
const MAX_ARCHIVE: u64 = 32 * 1024 * 1024;

#[derive(Clone, Serialize)]
pub struct Info {
    current: String,
    latest: Option<String>,
    available: bool,
    supported: bool,
    checking: bool,
    running: bool,
    stage: String,
    error: Option<String>,
    checked_at: Option<u64>,
    url: Option<String>,
}

struct State {
    info: Info,
    handed_off: bool,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Clone)]
struct Installation {
    system: &'static str,
    bin_dir: PathBuf,
    state_dir: PathBuf,
    template: &'static str,
}

pub struct Updater {
    state: Mutex<State>,
    installation: Option<Installation>,
    arch: Option<&'static str>,
}

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    assets: Vec<Asset>,
}
#[derive(Deserialize)]
struct Asset {
    name: String,
    size: u64,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn release_version(tag: &str) -> io::Result<Version> {
    let value = Version::parse(tag.strip_prefix('v').unwrap_or(tag))
        .map_err(|_| invalid("Некорректная версия релиза"))?;
    if !value.pre.is_empty() || !value.build.is_empty() || tag.len() > 64 {
        return Err(invalid("Нужен стабильный релиз в формате vX.Y.Z"));
    }
    Ok(value)
}

fn release_available(release: &Release, arch: Option<&str>) -> io::Result<bool> {
    let latest = release_version(&release.tag_name)?;
    if !release.tag_name.starts_with('v') || release.draft || release.prerelease {
        return Err(invalid("Релиз ещё не опубликован как стабильный"));
    }
    if latest <= Version::parse(CURRENT).unwrap() {
        return Ok(false);
    }
    let Some(arch) = arch else { return Ok(false) };
    for name in [format!("tgwsproxy-{arch}.tar.gz"), "SHA256SUMS".into()] {
        let assets: Vec<_> = release.assets.iter().filter(|a| a.name == name).collect();
        if assets.len() != 1 || assets[0].size == 0 || assets[0].size > MAX_ARCHIVE {
            return Err(invalid(format!("В релизе нет готового пакета: {name}")));
        }
    }
    Ok(true)
}

fn architecture() -> Option<&'static str> {
    if let Some(arch @ ("mips" | "mipsel" | "arm" | "armv7" | "aarch64" | "x86_64")) =
        option_env!("TGWS_ARCH")
    {
        return Some(arch);
    }
    match std::env::consts::ARCH {
        "aarch64" => Some("aarch64"),
        "x86_64" => Some("x86_64"),
        "mips" if cfg!(target_endian = "little") => Some("mipsel"),
        "mips" => Some("mips"),
        // ARMv5TE soft-float runs on both ARMv5 and ARMv7 routers.
        "arm" => Some("arm"),
        _ => None,
    }
}

fn installation(config: &Path) -> Option<Installation> {
    #[cfg(target_os = "linux")]
    {
        // Self-update is limited to the two managed service layouts.
        if unsafe { libc::geteuid() } != 0 {
            return None;
        }
        let exe = fs::canonicalize(std::env::current_exe().ok()?).ok()?;
        let config = fs::canonicalize(config).ok()?;
        for (system, bin, cfg, run, template) in [
            (
                "entware",
                "/opt/bin/tgwsproxy",
                "/opt/etc/tgwsproxy/config.json",
                "/opt/var/run",
                "S99tgwsproxy",
            ),
            (
                "openwrt",
                "/usr/bin/tgwsproxy",
                "/etc/tgwsproxy/config.json",
                "/var/run",
                "tgwsproxy",
            ),
        ] {
            if fs::canonicalize(bin).ok().as_ref() == Some(&exe)
                && fs::canonicalize(cfg).ok().as_ref() == Some(&config)
                && Path::new(if system == "entware" {
                    "/opt/etc/init.d/S99tgwsproxy"
                } else {
                    "/etc/init.d/tgwsproxy"
                })
                .is_file()
            {
                return Some(Installation {
                    system,
                    bin_dir: Path::new(bin).parent()?.into(),
                    state_dir: Path::new(run).join("tgwsproxy-update"),
                    template,
                });
            }
        }
    }
    let _ = config;
    None
}

fn private_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
        match fs::DirBuilder::new().mode(0o700).create(path) {
            Ok(()) => (),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (),
            Err(e) => return Err(e),
        }
        let meta = fs::symlink_metadata(path)?;
        if !meta.is_dir()
            || meta.uid() != unsafe { libc::geteuid() }
            || meta.permissions().mode() & 0o077 != 0
        {
            return Err(invalid("Небезопасный каталог обновления"));
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        fs::create_dir(path)
    }
}

fn small_file(path: &Path, max: usize) -> Option<String> {
    let meta = fs::symlink_metadata(path).ok()?;
    if !meta.is_file() || meta.len() > max as u64 {
        return None;
    }
    Some(fs::read_to_string(path).ok()?.trim().into())
}

impl Updater {
    pub fn new(config: &Path) -> Arc<Self> {
        let installation = installation(config);
        let arch = architecture();
        let updater = Arc::new(Self {
            state: Mutex::new(State {
                info: Info {
                    current: CURRENT.into(),
                    latest: None,
                    available: false,
                    supported: installation.is_some() && arch.is_some(),
                    checking: false,
                    running: false,
                    stage: "idle".into(),
                    error: None,
                    checked_at: None,
                    url: None,
                },
                handed_off: installation.as_ref().is_some_and(|i| i.state_dir.exists()),
            }),
            installation,
            arch,
        });
        updater.status();
        updater
    }

    pub fn status(&self) -> Info {
        let mut state = self.state.lock().unwrap();
        if state.handed_off {
            if let Some(install) = &self.installation {
                let dir = &install.state_dir;
                if private_dir(dir).is_ok() {
                    let stage = small_file(&dir.join("stage"), 32).unwrap_or_default();
                    let target =
                        small_file(&dir.join("target"), 64).filter(|v| release_version(v).is_ok());
                    let live = worker_live(dir);
                    let grace = worker_starting(dir);
                    state.info.latest = target
                        .map(|v| v.trim_start_matches('v').to_string())
                        .or(state.info.latest.clone());
                    state.info.available = state
                        .info
                        .latest
                        .as_deref()
                        .and_then(|t| release_version(t).ok())
                        .is_some_and(|v| v > Version::parse(CURRENT).unwrap());
                    if ["complete", "error"].contains(&stage.as_str()) || (!live && !grace) {
                        state.handed_off = false;
                        state.info.running = false;
                        let done = stage == "complete";
                        state.info.stage = if done { "complete" } else { "error" }.into();
                        state.info.error = if done {
                            None
                        } else {
                            Some("Обновление не завершено. Журнал: tgwsproxy-update/log".into())
                        };
                    } else {
                        state.info.running = true;
                        state.info.stage = if stage == "installing" {
                            "installing"
                        } else {
                            "restarting"
                        }
                        .into();
                    }
                } else {
                    state.handed_off = false;
                    state.info.running = false;
                    state.info.stage = "error".into();
                    state.info.error = Some("Не удалось прочитать состояние обновления".into());
                }
            }
        }
        state.info.clone()
    }

    pub fn check(self: &Arc<Self>, force: bool) -> Info {
        self.status();
        let mut state = self.state.lock().unwrap();
        if state.info.checking
            || state.info.running
            || (!force
                && state
                    .info
                    .checked_at
                    .is_some_and(|t| now().saturating_sub(t) < 300))
        {
            return state.info.clone();
        }
        state.info.checking = true;
        state.info.stage = "checking".into();
        state.info.error = None;
        let result = state.info.clone();
        drop(state);
        let this = self.clone();
        tokio::spawn(async move {
            let result = this.release().await;
            let mut state = this.state.lock().unwrap();
            state.info.checking = false;
            state.info.checked_at = Some(now());
            state.info.stage = "idle".into();
            match result {
                Ok(release) => {
                    state.info.available = release_available(&release, this.arch).unwrap_or(false);
                    state.info.url = Some(format!(
                        "https://github.com/{REPO}/releases/tag/{}",
                        release.tag_name
                    ));
                    state.info.latest = Some(release.tag_name.trim_start_matches('v').into());
                }
                Err(error) => {
                    state.info.available = false;
                    state.info.error = Some(error.to_string());
                }
            }
        });
        result
    }

    async fn release(&self) -> io::Result<Release> {
        let bytes = fetch_bytes(
            &format!("https://api.github.com/repos/{REPO}/releases/latest"),
            1024 * 1024,
        )
        .await?;
        let release: Release = serde_json::from_slice(&bytes)
            .map_err(|_| invalid("Некорректный ответ GitHub Releases"))?;
        release_available(&release, self.arch)?;
        Ok(release)
    }

    pub fn start(self: &Arc<Self>) -> io::Result<Info> {
        self.status();
        let mut state = self.state.lock().unwrap();
        if state.info.running {
            return Ok(state.info.clone());
        }
        if !state.info.supported {
            return Err(invalid(
                "Обновление доступно для установленного сервиса OpenWrt/Entware",
            ));
        }
        if state.info.checking || !state.info.available {
            return Err(invalid("Сначала дождитесь проверки новой версии"));
        }
        let tag = format!("v{}", state.info.latest.as_deref().unwrap());
        release_version(&tag)?;
        state.info.running = true;
        state.info.error = None;
        state.info.stage = "downloading".into();
        let result = state.info.clone();
        drop(state);
        let this = self.clone();
        tokio::spawn(async move {
            if let Err(error) = this.prepare(&tag).await {
                let mut state = this.state.lock().unwrap();
                state.info.running = false;
                state.info.stage = "error".into();
                state.info.error = Some(error.to_string());
            }
        });
        Ok(result)
    }

    async fn prepare(&self, tag: &str) -> io::Result<()> {
        let install = self.installation.as_ref().unwrap();
        private_dir(&install.state_dir)?;
        recover_stale(&install.state_dir)?;
        if let Some(old) = small_file(&install.state_dir.join("payload"), 4096) {
            let old = PathBuf::from(old);
            if old.parent() == Some(install.bin_dir.as_path())
                && old
                    .file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with(".tgwsproxy-update."))
                && fs::symlink_metadata(&old).is_ok_and(|m| m.is_dir())
            {
                fs::remove_dir_all(old)?;
            }
        }
        let payload = install
            .bin_dir
            .join(format!(".tgwsproxy-update.{}", random_hex()));
        private_dir(&payload)?;
        let mut cleanup = Payload(Some(payload.clone()));
        fs::write(
            install.state_dir.join("payload"),
            payload.as_os_str().as_encoded_bytes(),
        )?;
        let asset = format!("tgwsproxy-{}.tar.gz", self.arch.unwrap());
        let base = format!("https://github.com/{REPO}/releases/download/{tag}");
        let sums = fetch_bytes(&format!("{base}/SHA256SUMS"), 65536).await?;
        let expected = checksum(&sums, &asset)?;
        let archive = payload.join("release.tar.gz");
        let actual = fetch_file(&format!("{base}/{asset}"), &archive, MAX_ARCHIVE).await?;
        if actual != expected {
            return Err(invalid("SHA-256 пакета не совпадает; обновление отменено"));
        }
        fs::create_dir_all(payload.join("etc/init.d"))?;
        extract(&archive, "tgwsproxy", &payload.join("tgwsproxy")).await?;
        let template = format!("etc/init.d/{}", install.template);
        extract(&archive, &template, &payload.join(&template)).await?;
        fs::write(
            payload.join("install.sh"),
            include_bytes!("../scripts/install.sh"),
        )?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(payload.join("tgwsproxy"), fs::Permissions::from_mode(0o755))?;
        }
        let mut candidate = Command::new(payload.join("tgwsproxy"));
        candidate.arg("--version");
        let version = capture(candidate, 4096, Duration::from_secs(10)).await?;
        if !String::from_utf8_lossy(&version)
            .starts_with(&format!("tgwsproxy {} ", tag.trim_start_matches('v')))
        {
            return Err(invalid(
                "Версия или архитектура скачанного бинарника не подходит",
            ));
        }
        fs::remove_file(&archive)?;
        launch_worker(install, tag, &payload)?;
        // The detached worker now owns payload cleanup and rollback supervision.
        cleanup.0 = None;
        let mut state = self.state.lock().unwrap();
        state.handed_off = true;
        state.info.stage = "installing".into();
        Ok(())
    }
}

struct Payload(Option<PathBuf>);
impl Drop for Payload {
    fn drop(&mut self) {
        if let Some(path) = &self.0 {
            let _ = fs::remove_dir_all(path);
        }
    }
}

fn checksum(bytes: &[u8], name: &str) -> io::Result<String> {
    let text = std::str::from_utf8(bytes).map_err(|_| invalid("Некорректный SHA256SUMS"))?;
    let matches: Vec<_> = text
        .lines()
        .filter_map(|l| {
            let mut p = l.split_whitespace();
            let hash = p.next()?;
            let file = p.next()?.trim_start_matches('*');
            (file == name && p.next().is_none()).then_some(hash)
        })
        .collect();
    if matches.len() != 1
        || matches[0].len() != 64
        || !matches[0].bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(invalid("Нет однозначной SHA-256 для пакета"));
    }
    Ok(matches[0].to_ascii_lowercase())
}

fn wget() -> io::Result<PathBuf> {
    let preferred = Path::new("/opt/bin/wget");
    if preferred.is_file() {
        return Ok(preferred.into());
    }
    std::env::var_os("PATH")
        .and_then(|p| {
            std::env::split_paths(&p)
                .map(|p| p.join(if cfg!(windows) { "wget.exe" } else { "wget" }))
                .find(|p| p.is_file())
        })
        .ok_or_else(|| invalid("Нужен wget с HTTPS и CA-сертификатами"))
}

async fn capture(mut command: Command, limit: u64, budget: Duration) -> io::Result<Vec<u8>> {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let mut stdout = child.stdout.take().unwrap().take(limit + 1);
    let result = timeout(budget, async {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).await?;
        if bytes.len() as u64 > limit { return Err(invalid("Ответ программы превышает лимит размера")); }
        if !child.wait().await?.success() { return Err(invalid("Не удалось получить релиз или проверить программу; проверьте HTTPS wget, сеть и сертификаты")); }
        Ok(bytes)
    }).await.unwrap_or_else(|_| Err(invalid("Истекло время ожидания ответа")));
    if result.is_err() {
        let _ = child.kill().await;
    }
    result
}

async fn fetch_bytes(url: &str, limit: u64) -> io::Result<Vec<u8>> {
    let mut command = Command::new(wget()?);
    command.args(["-q", "-O", "-", url]);
    capture(command, limit, Duration::from_secs(12)).await
}

async fn pipe_file(
    mut command: Command,
    path: &Path,
    limit: u64,
    budget: Duration,
) -> io::Result<String> {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let mut stdout = child.stdout.take().unwrap();
    let result = timeout(budget, async {
        let mut file = tokio::fs::File::create(path).await?;
        let mut digest = Sha256::new();
        let mut total = 0u64;
        let mut buf = [0; 16384];
        loop {
            let n = stdout.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            total += n as u64;
            if total > limit {
                return Err(invalid("Файл превышает лимит размера"));
            }
            digest.update(&buf[..n]);
            file.write_all(&buf[..n]).await?;
        }
        file.flush().await?;
        if total == 0 || !child.wait().await?.success() {
            return Err(invalid("Не удалось загрузить или распаковать пакет"));
        }
        Ok(hex(&digest.finalize()))
    })
    .await
    .unwrap_or_else(|_| Err(invalid("Истекло время загрузки или распаковки")));
    if result.is_err() {
        let _ = child.kill().await;
    }
    result
}

async fn fetch_file(url: &str, path: &Path, limit: u64) -> io::Result<String> {
    let mut command = Command::new(wget()?);
    command.args(["-q", "-O", "-", url]);
    pipe_file(command, path, limit, Duration::from_secs(180)).await
}

async fn extract(archive: &Path, member: &str, output: &Path) -> io::Result<()> {
    let mut command = Command::new("tar");
    command.arg("-xzOf").arg(archive).arg(member);
    let limit = if member == "tgwsproxy" {
        MAX_ARCHIVE
    } else {
        65536
    };
    pipe_file(command, output, limit, Duration::from_secs(30)).await?;
    Ok(())
}

fn worker_live(dir: &Path) -> bool {
    small_file(&dir.join("pid"), 20)
        .and_then(|s| s.parse::<u32>().ok())
        .filter(|p| *p > 1)
        .is_some_and(|pid| {
            let cmdline = fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
            cmdline
                .split(|b| *b == 0)
                .any(|arg| arg == dir.join("worker.sh").as_os_str().as_encoded_bytes())
        })
}

fn worker_starting(dir: &Path) -> bool {
    // A just-spawned process may still have the parent's cmdline before exec.
    small_file(&dir.join("stage"), 32).is_some_and(|s| s == "installing" || s == "restarting")
        && fs::metadata(dir.join("stage"))
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|d| d < Duration::from_secs(10))
}

fn recover_stale(dir: &Path) -> io::Result<()> {
    let lock = dir.join("worker.lock");
    if !lock.exists() {
        return Ok(());
    }
    if worker_live(dir) || worker_starting(dir) {
        return Err(invalid("Предыдущее обновление ещё выполняется"));
    }
    // Only remove the known PID file and an empty lock directory. Never recurse.
    match fs::remove_file(lock.join("pid")) {
        Ok(()) => (),
        Err(e) if e.kind() == io::ErrorKind::NotFound => (),
        Err(e) => return Err(e),
    }
    fs::remove_dir(lock)
}

fn launch_worker(install: &Installation, tag: &str, payload: &Path) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        let worker = install.state_dir.join("worker.sh");
        fs::write(&worker, include_bytes!("../scripts/update-worker.sh"))?;
        // Prepare observable state before spawn, then publish the PID before any
        // async yield. The worker waits briefly before stopping this service.
        fs::write(install.state_dir.join("stage"), "installing\n")?;
        fs::write(install.state_dir.join("target"), format!("{tag}\n"))?;
        let log = fs::File::create(install.state_dir.join("log"))?;
        let mut command = std::process::Command::new("/bin/sh");
        command
            .arg(&worker)
            .arg(&install.state_dir)
            .arg(install.system)
            .arg(tag)
            .arg(payload)
            .env("TGWS_REPO", REPO)
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log);
        // setsid is async-signal-safe and avoids being killed with the old
        // procd service process group. No allocation in the pre-exec callback.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() == -1 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
        let mut child = command.spawn()?;
        // After spawn, ownership belongs to the worker even if publishing its
        // PID fails. The worker also publishes its own PID atomically.
        let _ = fs::write(install.state_dir.join("pid"), format!("{}\n", child.id()));
        // Reap failures while this process survives; successful updates replace
        // this process and the worker is then adopted by the system supervisor.
        let _ = std::thread::Builder::new()
            .name("update-reaper".into())
            .stack_size(128 * 1024)
            .spawn(move || {
                let _ = child.wait();
            });
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (install, tag, payload);
        Err(invalid("Обновление поддерживается только на Linux"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    #[tokio::test]
    async fn child_output_and_downloads_are_bounded_and_timed_out() {
        let dir = std::env::temp_dir().join(format!("tgws-update-test-{}", random_hex()));
        private_dir(&dir).unwrap();
        let _cleanup = Payload(Some(dir.clone()));
        let mut oversized = Command::new("sh");
        oversized.args(["-c", "printf 123456789"]);
        assert!(capture(oversized, 4, Duration::from_secs(2)).await.is_err());
        let mut endless = Command::new("sh");
        endless.args(["-c", "exec sleep 2"]);
        let started = std::time::Instant::now();
        assert!(capture(endless, 4, Duration::from_millis(50))
            .await
            .is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
        let mut download = Command::new("sh");
        download.args(["-c", "printf 123456789"]);
        let output = dir.join("download");
        assert!(pipe_file(download, &output, 4, Duration::from_secs(2))
            .await
            .is_err());
        assert!(fs::metadata(&output).unwrap().len() <= 4);
        let mut valid = Command::new("sh");
        valid.args(["-c", "printf abc"]);
        assert_eq!(
            pipe_file(valid, &output, 4, Duration::from_secs(2))
                .await
                .unwrap(),
            hex(&Sha256::digest(b"abc"))
        );
    }
    #[cfg(unix)]
    #[test]
    fn failed_worker_state_normalizes_retry_version_and_reclaims_reused_pid_lock() {
        let dir = std::env::temp_dir().join(format!("tgws-update-test-{}", random_hex()));
        private_dir(&dir).unwrap();
        let _cleanup = Payload(Some(dir.clone()));
        fs::write(dir.join("target"), "v99.0.0\n").unwrap();
        fs::write(dir.join("stage"), "error\n").unwrap();
        // This is a live PID, but its argv is not our detached worker.
        fs::write(dir.join("pid"), std::process::id().to_string()).unwrap();
        fs::create_dir(dir.join("worker.lock")).unwrap();
        fs::write(dir.join("worker.lock/pid"), std::process::id().to_string()).unwrap();
        let source = Updater::new(Path::new("/nonexistent"));
        let updater = Updater {
            state: Mutex::new(State {
                info: source.status(),
                handed_off: true,
            }),
            installation: Some(Installation {
                system: "entware",
                bin_dir: dir.clone(),
                state_dir: dir.clone(),
                template: "S99tgwsproxy",
            }),
            arch: Some("aarch64"),
        };
        let info = updater.status();
        assert_eq!(info.latest.as_deref(), Some("99.0.0"));
        assert!(info.available);
        assert!(!info.running);
        assert_eq!(info.stage, "error");
        recover_stale(&dir).unwrap();
        assert!(!dir.join("worker.lock").exists());
        fs::create_dir(dir.join("worker.lock")).unwrap();
        fs::write(dir.join("stage"), "installing").unwrap();
        assert!(
            recover_stale(&dir).is_err(),
            "startup grace protects an about-to-exec worker"
        );
        assert!(dir.join("worker.lock").exists());
    }
    #[test]
    fn versions_never_downgrade_or_accept_unstable_or_injected_tags() {
        for tag in [
            "v2.1.0-rc.1",
            "v2.1.0+build",
            "v2.01.0",
            "../../x",
            "v2.1.0;id",
        ] {
            assert!(release_version(tag).is_err(), "{tag}");
        }
        let old = Release {
            tag_name: "v1.99.0".into(),
            draft: false,
            prerelease: false,
            assets: vec![],
        };
        assert!(!release_available(&old, Some("mipsel")).unwrap());
        assert!(release_version("v2.10.0").unwrap() > release_version("v2.9.9").unwrap());
    }
    #[test]
    fn newer_release_requires_exact_architecture_and_checksums() {
        let mut release = Release {
            tag_name: "v99.0.0".into(),
            draft: false,
            prerelease: false,
            assets: vec![],
        };
        assert!(release_available(&release, Some("mipsel")).is_err());
        release.assets = vec![
            Asset {
                name: "tgwsproxy-mipsel.tar.gz".into(),
                size: 100,
            },
            Asset {
                name: "SHA256SUMS".into(),
                size: 100,
            },
        ];
        assert!(release_available(&release, Some("mipsel")).unwrap());
        assert!(release_available(&release, Some("mips")).is_err());
        release.assets.push(Asset {
            name: "SHA256SUMS".into(),
            size: 100,
        });
        assert!(release_available(&release, Some("mipsel")).is_err());
    }
    #[test]
    fn checksums_reject_missing_malformed_and_duplicate_entries() {
        let good = format!("{}  tgwsproxy-mips.tar.gz\n", "A".repeat(64));
        assert_eq!(
            checksum(good.as_bytes(), "tgwsproxy-mips.tar.gz").unwrap(),
            "a".repeat(64)
        );
        assert!(checksum(good.as_bytes(), "tgwsproxy-mipsel.tar.gz").is_err());
        assert!(checksum(format!("{good}{good}").as_bytes(), "tgwsproxy-mips.tar.gz").is_err());
        assert!(checksum(b"abcd  tgwsproxy-mips.tar.gz", "tgwsproxy-mips.tar.gz").is_err());
    }
}
