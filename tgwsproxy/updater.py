"""Self-update over GitHub Releases.

We check `GET /repos/<owner>/<repo>/releases/latest` (or `/commits/<branch>`
for the rolling channel), download the corresponding tarball, extract it
into a staging dir, then hand off to a tiny shell script that:

    1. stops the running service,
    2. moves the current /opt/share/tgwsproxy/{tgwsproxy,webui} aside,
    3. moves the new code into place,
    4. starts the service back up,
    5. if the service refuses to come up, rolls back to the saved copy.

The python process exits as part of step 1, so the shell script must run
in its own session — `subprocess.Popen(..., start_new_session=True)`.

Configuration file at /opt/etc/tgwsproxy/config.json is never touched.
"""
from __future__ import annotations

import asyncio
import io
import json
import logging
import os
import re
import shutil
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from . import __version__

log = logging.getLogger("tgwsproxy.updater")

GITHUB_API_BASE = "https://api.github.com"
DEFAULT_REPO = "Omn1z/tg-ws-keenetic"
DEFAULT_INSTALL_ROOT = "/opt/share/tgwsproxy"
DEFAULT_INIT_SCRIPT = "/opt/etc/init.d/S99tgwsproxy"
USER_AGENT = f"tgwsproxy-updater/{__version__}"

# What we ship/replace in an update — code only, never config or logs.
PAYLOAD_DIRS = ("tgwsproxy", "webui")

# Where the unpacked staging copy lives. Outside install root so a failed
# install doesn't leave half-written files inside the real dir.
DEFAULT_STAGING_ROOT = "/opt/tmp"


@dataclass
class UpdateInfo:
    """Result of an update check."""

    current: str
    latest: str
    available: bool
    channel: str
    tarball_url: str
    published_at: str
    notes: str

    def as_dict(self) -> dict:
        return {
            "current": self.current,
            "latest": self.latest,
            "available": self.available,
            "channel": self.channel,
            "tarball_url": self.tarball_url,
            "published_at": self.published_at,
            "notes": self.notes,
        }


class UpdateError(Exception):
    """Anything user-facing that goes wrong during update."""


# --- HTTP helpers -----------------------------------------------------------


def _http_get(url: str, *, timeout: float = 15.0,
              accept: str = "application/json") -> bytes:
    """GET an HTTPS URL, following redirects, returning raw bytes."""
    req = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT, "Accept": accept}
    )
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.read()
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")[:200]
        raise UpdateError(
            f"GitHub returned HTTP {exc.code} for {url}: {body}"
        ) from exc
    except urllib.error.URLError as exc:
        raise UpdateError(f"network error fetching {url}: {exc.reason}") from exc


async def _http_get_async(url: str, **kw) -> bytes:
    return await asyncio.to_thread(_http_get, url, **kw)


# --- version checking ------------------------------------------------------


def _normalize_tag(tag: str) -> str:
    """`v1.2.3` → `1.2.3`. Leaves other strings alone."""
    return tag[1:] if tag.startswith(("v", "V")) else tag


def _is_newer(latest: str, current: str) -> bool:
    """Compare semver-like versions; safe on commit SHAs (returns True if differs)."""
    latest_n = _normalize_tag(latest)
    current_n = _normalize_tag(current)

    if latest_n == current_n:
        return False
    if re.fullmatch(r"\d+(?:\.\d+){0,2}", latest_n) and re.fullmatch(
        r"\d+(?:\.\d+){0,2}", current_n
    ):
        lt = tuple(int(p) for p in latest_n.split("."))
        ct = tuple(int(p) for p in current_n.split("."))
        # Pad to same length so 1.2 < 1.2.1.
        while len(lt) < len(ct):
            lt += (0,)
        while len(ct) < len(lt):
            ct += (0,)
        return lt > ct
    # Non-semver (commit SHAs etc.): anything different counts as "newer".
    return True


async def check_for_update(
    repo: str = DEFAULT_REPO, channel: str = "release"
) -> UpdateInfo:
    """Ask GitHub what the latest version is and whether we're behind."""
    log.info("checking for updates: repo=%s channel=%s", repo, channel)
    if channel == "release":
        return await _check_release(repo)
    if channel == "main":
        return await _check_branch(repo, "main")
    raise UpdateError(f"unknown channel {channel!r}; expected 'release' or 'main'")


async def _check_release(repo: str) -> UpdateInfo:
    url = f"{GITHUB_API_BASE}/repos/{repo}/releases/latest"
    raw = await _http_get_async(url)
    data = json.loads(raw)
    latest = data.get("tag_name") or ""
    return UpdateInfo(
        current=__version__,
        latest=_normalize_tag(latest),
        available=_is_newer(latest, __version__),
        channel="release",
        tarball_url=data.get("tarball_url", ""),
        published_at=data.get("published_at", ""),
        notes=(data.get("body") or "").strip(),
    )


async def _check_branch(repo: str, branch: str) -> UpdateInfo:
    url = f"{GITHUB_API_BASE}/repos/{repo}/commits/{branch}"
    raw = await _http_get_async(url)
    data = json.loads(raw)
    sha = (data.get("sha") or "")[:7]
    tarball_url = f"{GITHUB_API_BASE}/repos/{repo}/tarball/{branch}"
    commit_msg = (
        (data.get("commit") or {}).get("message", "").strip().split("\n", 1)[0]
    )
    return UpdateInfo(
        current=__version__,
        latest=sha,
        available=bool(sha) and sha != _current_sha_hint(),
        channel="main",
        tarball_url=tarball_url,
        published_at=(data.get("commit") or {})
        .get("committer", {})
        .get("date", ""),
        notes=commit_msg,
    )


def _current_sha_hint() -> str:
    """Best-effort current commit marker (for the 'main' channel).

    There is no real way for the installed copy to know its commit SHA — we
    don't ship a .git folder. So we always report "" and let `_is_newer`
    treat any non-empty `latest` as newer. That's fine: 'main' channel is
    explicitly opt-in, and "always offers an update" is acceptable there.
    """
    return ""


# --- download + apply -------------------------------------------------------


def _download_tarball(url: str, dest: Path) -> None:
    log.info("downloading update tarball: %s", url)
    data = _http_get(url, timeout=120, accept="application/gzip")
    dest.write_bytes(data)
    log.info("downloaded %d bytes -> %s", len(data), dest)


def _extract_tarball(tarball: Path, staging_dir: Path) -> Path:
    """Extract a GitHub tarball into staging_dir, return the inner root path."""
    log.info("extracting %s -> %s", tarball, staging_dir)
    staging_dir.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tarball, "r:gz") as tf:
        # GitHub tarballs always nest under <owner>-<repo>-<sha>/. Strip that.
        members = tf.getmembers()
        if not members:
            raise UpdateError("tarball is empty")
        top_levels = {m.name.split("/", 1)[0] for m in members if m.name}
        if len(top_levels) != 1:
            raise UpdateError(
                f"unexpected tarball layout, top-level entries: {top_levels}"
            )
        prefix = top_levels.pop() + "/"
        for member in members:
            if member.name == prefix.rstrip("/"):
                continue
            if not member.name.startswith(prefix):
                raise UpdateError(
                    f"tarball member outside expected prefix: {member.name}"
                )
            member.name = member.name[len(prefix):]
            tf.extract(member, staging_dir)
    inner = staging_dir
    for required in PAYLOAD_DIRS:
        if not (inner / required).is_dir():
            raise UpdateError(
                f"tarball missing required directory '{required}'"
            )
    return inner


def _generate_apply_script(
    *,
    staging_root: Path,
    install_root: Path,
    init_script: str,
    log_file: Path,
) -> Path:
    """Write the shell script that swaps in the new code and restarts service."""
    script = staging_root / "apply.sh"
    quoted_install = str(install_root)
    quoted_staging = str(staging_root)
    quoted_init = init_script
    quoted_log = str(log_file)
    payload_list = " ".join(PAYLOAD_DIRS)

    contents = f"""#!/bin/sh
# Auto-generated by tgwsproxy.updater. Do not edit.
set -e
LOG={quoted_log}
INSTALL={quoted_install}
STAGING={quoted_staging}
INIT={quoted_init}
PAYLOAD="{payload_list}"

log() {{ echo "[$(date '+%H:%M:%S')] $*" >> "$LOG"; }}

log "update apply: staging=$STAGING install=$INSTALL"

# Give the HTTP response a chance to reach the client.
sleep 2

if [ -x "$INIT" ]; then
    log "stopping service via $INIT"
    "$INIT" stop >> "$LOG" 2>&1 || log "stop returned non-zero (continuing)"
fi

# Backup current code.
TS=$(date +%Y%m%d-%H%M%S)
BACKUP="$INSTALL/.backup-$TS"
mkdir -p "$BACKUP"
for d in $PAYLOAD; do
    if [ -d "$INSTALL/$d" ]; then
        mv "$INSTALL/$d" "$BACKUP/$d"
    fi
done
log "backup created at $BACKUP"

# Move new code into place.
for d in $PAYLOAD; do
    if [ -d "$STAGING/$d" ]; then
        mv "$STAGING/$d" "$INSTALL/$d"
        log "installed new $d"
    else
        log "ERROR: staging missing $d, rolling back"
        for r in $PAYLOAD; do
            rm -rf "$INSTALL/$r"
            [ -d "$BACKUP/$r" ] && mv "$BACKUP/$r" "$INSTALL/$r"
        done
        "$INIT" start >> "$LOG" 2>&1 || true
        exit 1
    fi
done

# Start the new version.
if [ -x "$INIT" ]; then
    log "starting service"
    if "$INIT" start >> "$LOG" 2>&1; then
        log "service started OK, removing backup"
        rm -rf "$BACKUP"
    else
        log "service failed to start, rolling back"
        "$INIT" stop >> "$LOG" 2>&1 || true
        for d in $PAYLOAD; do
            rm -rf "$INSTALL/$d"
            [ -d "$BACKUP/$d" ] && mv "$BACKUP/$d" "$INSTALL/$d"
        done
        "$INIT" start >> "$LOG" 2>&1 || true
        log "rollback done"
        exit 1
    fi
fi

# Clean up staging.
rm -rf "$STAGING"
log "update complete"
"""
    script.write_text(contents, encoding="utf-8")
    script.chmod(0o755)
    return script


@dataclass
class PreparedUpdate:
    """An update that has been downloaded and extracted, ready to apply."""
    staging: Path
    info: UpdateInfo
    install_root: Path
    init_script: str
    log_file: Path


def prepare_update(
    info: UpdateInfo,
    *,
    install_root: str = DEFAULT_INSTALL_ROOT,
    init_script: str = DEFAULT_INIT_SCRIPT,
    staging_root: str = DEFAULT_STAGING_ROOT,
    log_file: Optional[str] = None,
) -> PreparedUpdate:
    """Download and extract the tarball; do NOT touch the live install yet.

    Splitting prepare from spawn lets the web handler return a successful
    response before the apply script stops the service.
    """
    if not info.tarball_url:
        raise UpdateError("no tarball_url in update info")

    staging = Path(staging_root) / f"tgwsproxy-update-{int(time.time())}"
    staging.mkdir(parents=True, exist_ok=True)

    tarball_path = staging / "release.tar.gz"
    try:
        _download_tarball(info.tarball_url, tarball_path)
        _extract_tarball(tarball_path, staging)
    except UpdateError:
        shutil.rmtree(staging, ignore_errors=True)
        raise

    tarball_path.unlink(missing_ok=True)

    log_path = Path(log_file) if log_file else (
        Path("/opt/var/log/tgwsproxy") / "update.log"
    )
    log_path.parent.mkdir(parents=True, exist_ok=True)

    return PreparedUpdate(
        staging=staging,
        info=info,
        install_root=Path(install_root),
        init_script=init_script,
        log_file=log_path,
    )


def spawn_apply(prepared: PreparedUpdate) -> Path:
    """Write the apply script and start it in a detached session."""
    script = _generate_apply_script(
        staging_root=prepared.staging,
        install_root=prepared.install_root,
        init_script=prepared.init_script,
        log_file=prepared.log_file,
    )
    log.info("spawning apply script: %s (log -> %s)",
             script, prepared.log_file)
    subprocess.Popen(
        ["/bin/sh", str(script)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        close_fds=True,
    )
    return script


def apply_update(info: UpdateInfo, **kwargs) -> Path:
    """Convenience: prepare + spawn in one call. Used by the CLI."""
    prepared = prepare_update(info, **kwargs)
    return spawn_apply(prepared)


async def prepare_update_async(info: UpdateInfo, **kwargs) -> PreparedUpdate:
    return await asyncio.to_thread(prepare_update, info, **kwargs)


async def apply_update_async(info: UpdateInfo, **kwargs) -> Path:
    return await asyncio.to_thread(apply_update, info, **kwargs)
