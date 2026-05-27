"""JSON-backed configuration for the router build.

Single source of truth: a JSON file at `/opt/etc/tgwsproxy/config.json`.
The web UI reads and writes this file; the server reads it on start /
restart. No state is kept anywhere else.

Designed for "the file might not exist yet" (first install) and for
"the file might have garbage in it" (failed manual edit) — both produce
sensible defaults rather than a crash.
"""
from __future__ import annotations

import copy
import json
import logging
import os
import secrets
import socket as _socket
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

log = logging.getLogger("tgwsproxy.config")

DEFAULT_CONFIG_PATH = "/opt/etc/tgwsproxy/config.json"
DEFAULT_LOG_PATH = "/opt/var/log/tgwsproxy/tgwsproxy.log"

# CF proxy fallback default pool (encoded). See balancer.py for the decoder
# applied at load time. Encoded so a casual scan of the binary doesn't list
# fallback infrastructure.
_CFPROXY_ENCODED_DEFAULTS: List[str] = [
    "virkgj.com",
    "vmmzovy.com",
    "mkuosckvso.com",
    "zaewayzmplad.com",
    "twdmbzcm.com",
    "awzwsldi.com",
    "clngqrflngqin.com",
    "tjacxbqtj.com",
    "bxaxtxmrw.com",
    "dmohrsgmohcrwb.com",
]
_TLD = "".join(chr(c) for c in (46, 99, 111, 46, 117, 107))


def _decode_cfproxy(label: str) -> str:
    if not label.endswith(".com"):
        return label
    body = label[:-4]
    n = sum(c.isalpha() for c in body)
    out = []
    for ch in body:
        if ch.isalpha():
            base = 97 if ch > "`" else 65
            out.append(chr((ord(ch) - base - n) % 26 + base))
        else:
            out.append(ch)
    return "".join(out) + _TLD


@dataclass
class Config:
    """All knobs the proxy understands. Defaults match Keenetic-LAN use case."""

    # Network
    host: str = "0.0.0.0"
    port: int = 1433
    web_host: str = "0.0.0.0"
    web_port: int = 1434

    # MTProto
    secret: str = ""  # 32 hex chars; auto-generated on first save if empty
    dc_redirects: Dict[int, str] = field(
        default_factory=lambda: {
            2: "149.154.167.220",
            4: "149.154.167.220",
        }
    )

    # Tuning
    buffer_size: int = 256 * 1024
    pool_size: int = 4
    proxy_protocol: bool = False

    # Cloudflare-based fallback
    cfproxy: bool = True
    cfproxy_user_domain: str = ""
    cfproxy_worker_domain: str = ""

    # Fake TLS masking
    fake_tls_domain: str = ""

    # Hostname / IP to embed in the tg:// link. Empty = best-effort guess
    # (falls back to the Host: header of the request that built the link, or
    # the IP the router would use for outbound traffic).
    link_host: str = ""

    # Logging
    log_file: str = DEFAULT_LOG_PATH
    log_max_mb: float = 5.0
    log_backups: int = 2
    verbose: bool = False

    # Web UI auth (Basic). Empty user/pass = no auth.
    web_user: str = "admin"
    web_password: str = ""

    # ---- helpers ---------------------------------------------------------

    def ensure_secret(self) -> None:
        if not self.secret:
            self.secret = secrets.token_hex(16)

    def cfproxy_default_pool(self) -> List[str]:
        return [_decode_cfproxy(d) for d in _CFPROXY_ENCODED_DEFAULTS]

    def validate(self) -> List[str]:
        """Return a list of human-readable errors. Empty list = OK."""
        errors: List[str] = []
        if not _valid_port(self.port):
            errors.append(f"port {self.port!r} is out of range")
        if not _valid_port(self.web_port):
            errors.append(f"web_port {self.web_port!r} is out of range")
        if self.port == self.web_port:
            errors.append("port and web_port must differ")
        if self.secret and len(self.secret) != 32:
            errors.append("secret must be exactly 32 hex chars")
        if self.secret:
            try:
                bytes.fromhex(self.secret)
            except ValueError:
                errors.append("secret is not valid hex")
        for dc, ip in self.dc_redirects.items():
            if not _valid_dc(dc):
                errors.append(f"unknown DC {dc!r}")
            try:
                _socket.inet_aton(ip)
            except OSError:
                errors.append(f"invalid IP for DC{dc}: {ip!r}")
        if self.buffer_size < 4096:
            errors.append("buffer_size must be >= 4096")
        if self.pool_size < 0:
            errors.append("pool_size must be >= 0")
        return errors

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # JSON requires string keys for dc_redirects.
        d["dc_redirects"] = {str(k): v for k, v in self.dc_redirects.items()}
        return d


def _valid_port(p: int) -> bool:
    return isinstance(p, int) and 1 <= p <= 65535


def _valid_dc(dc: int) -> bool:
    return isinstance(dc, int) and dc in (1, 2, 3, 4, 5, 203)


# --- IO ---------------------------------------------------------------------


def default_config() -> Config:
    cfg = Config()
    cfg.ensure_secret()
    return cfg


def load_config(path: str = DEFAULT_CONFIG_PATH) -> Config:
    if not os.path.exists(path):
        log.info("Config %s missing, using defaults", path)
        return default_config()

    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        log.error("Cannot read %s: %s — using defaults", path, exc)
        return default_config()

    return _from_dict(raw)


def save_config(cfg: Config, path: str = DEFAULT_CONFIG_PATH) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg.to_dict(), f, indent=2, ensure_ascii=False)
        f.write("\n")
    os.replace(tmp, path)


def _from_dict(raw: Dict[str, Any]) -> Config:
    """Build a Config out of an untrusted dict — tolerant of missing keys."""
    base = default_config()
    merged = copy.deepcopy(asdict(base))

    for key in merged:
        if key not in raw:
            continue
        if key == "dc_redirects":
            merged[key] = _coerce_dc_map(raw[key])
        else:
            merged[key] = raw[key]

    cfg = Config(
        host=str(merged["host"]),
        port=int(merged["port"]),
        web_host=str(merged["web_host"]),
        web_port=int(merged["web_port"]),
        secret=str(merged["secret"]),
        dc_redirects=merged["dc_redirects"],
        buffer_size=int(merged["buffer_size"]),
        pool_size=int(merged["pool_size"]),
        proxy_protocol=bool(merged["proxy_protocol"]),
        cfproxy=bool(merged["cfproxy"]),
        cfproxy_user_domain=str(merged["cfproxy_user_domain"]),
        cfproxy_worker_domain=str(merged["cfproxy_worker_domain"]),
        fake_tls_domain=str(merged["fake_tls_domain"]),
        link_host=str(merged["link_host"]),
        log_file=str(merged["log_file"]),
        log_max_mb=float(merged["log_max_mb"]),
        log_backups=int(merged["log_backups"]),
        verbose=bool(merged["verbose"]),
        web_user=str(merged["web_user"]),
        web_password=str(merged["web_password"]),
    )
    cfg.ensure_secret()
    return cfg


def _coerce_dc_map(raw: Any) -> Dict[int, str]:
    if isinstance(raw, list):
        out = {}
        for entry in raw:
            if isinstance(entry, str) and ":" in entry:
                k, v = entry.split(":", 1)
                try:
                    out[int(k)] = v
                except ValueError:
                    continue
        return out
    if isinstance(raw, dict):
        out = {}
        for k, v in raw.items():
            try:
                out[int(k)] = str(v)
            except (TypeError, ValueError):
                continue
        return out
    return {}


def proxy_tg_link(cfg: Config, host_override: Optional[str] = None) -> str:
    """Build a tg://proxy link. Priority for the host:
       1. `host_override` (caller-supplied, e.g. from a Host: header)
       2. `cfg.link_host` (explicit setting)
       3. outbound-IP guess via `_local_ip_for(cfg.host)`
    """
    host = host_override or cfg.link_host or _local_ip_for(cfg.host)
    if cfg.fake_tls_domain:
        domain_hex = cfg.fake_tls_domain.encode("ascii").hex()
        return (
            f"tg://proxy?server={host}&port={cfg.port}"
            f"&secret=ee{cfg.secret}{domain_hex}"
        )
    return (
        f"tg://proxy?server={host}&port={cfg.port}"
        f"&secret=dd{cfg.secret}"
    )


def _local_ip_for(host: str) -> str:
    if host not in ("0.0.0.0", "", "::"):
        return host
    try:
        with _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
