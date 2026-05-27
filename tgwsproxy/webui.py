"""Tiny HTTP server (asyncio + stdlib) for the configuration web UI.

We deliberately avoid aiohttp/fastapi: the Entware Python install is bare
and every extra package is another opkg dependency to maintain. The
protocol surface we need is small enough that handwriting it is cheaper.

Routes:
    GET  /              -> bundled index.html
    GET  /style.css     -> bundled stylesheet
    GET  /app.js        -> bundled script
    GET  /api/state     -> {config, stats, link}
    POST /api/config    -> save config (body: full Config JSON), then restart
    POST /api/restart   -> restart proxy with current saved config
    POST /api/secret    -> regenerate secret, save and restart
"""
from __future__ import annotations

import asyncio
import base64
import hmac
import json
import logging
import os
import secrets
from dataclasses import asdict
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, Optional, Tuple

from .config import (
    Config,
    DEFAULT_CONFIG_PATH,
    _from_dict,
    proxy_tg_link,
    save_config,
)
from .server import ProxyServer

log = logging.getLogger("tgwsproxy.webui")

WEBUI_DIR = Path(__file__).resolve().parent.parent / "webui"

_CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
}


class _HttpRequest:
    __slots__ = ("method", "path", "headers", "body")

    def __init__(self, method: str, path: str, headers: Dict[str, str], body: bytes):
        self.method = method
        self.path = path
        self.headers = headers
        self.body = body

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)


Handler = Callable[[_HttpRequest], Awaitable[Tuple[int, bytes, Dict[str, str]]]]


class WebUI:
    def __init__(
        self,
        server: ProxyServer,
        config_path: str = DEFAULT_CONFIG_PATH,
        webui_dir: Path = WEBUI_DIR,
    ):
        self._proxy = server
        self._config_path = config_path
        self._dir = webui_dir
        self._http_server: Optional[asyncio.AbstractServer] = None
        self._routes: Dict[Tuple[str, str], Handler] = {
            ("GET", "/api/state"): self._handle_state,
            ("POST", "/api/config"): self._handle_save_config,
            ("POST", "/api/restart"): self._handle_restart,
            ("POST", "/api/secret"): self._handle_new_secret,
        }

    async def start(self) -> None:
        cfg = self._proxy.config
        self._http_server = await asyncio.start_server(
            self._on_connection, cfg.web_host, cfg.web_port,
        )
        log.info("Web UI listening on %s:%d", cfg.web_host, cfg.web_port)

    async def stop(self) -> None:
        if self._http_server is None:
            return
        self._http_server.close()
        try:
            await self._http_server.wait_closed()
        except Exception:
            pass
        self._http_server = None

    # ---- connection loop -------------------------------------------------

    async def _on_connection(self, reader, writer) -> None:
        try:
            request = await _read_request(reader)
            if request is None:
                return

            if not self._authorize(request):
                await _respond(writer, 401, b"Unauthorized", {
                    "WWW-Authenticate": 'Basic realm="tgwsproxy"',
                })
                return

            status, body, headers = await self._route(request)
            await _respond(writer, status, body, headers)
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        except Exception:
            log.exception("WebUI request error")
            try:
                await _respond(writer, 500, b"Internal error", {})
            except Exception:
                pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    def _authorize(self, request: _HttpRequest) -> bool:
        cfg = self._proxy.config
        if not cfg.web_user or not cfg.web_password:
            return True
        header = request.header("authorization")
        if not header.lower().startswith("basic "):
            return False
        try:
            decoded = base64.b64decode(header[6:]).decode("utf-8", "replace")
        except Exception:
            return False
        if ":" not in decoded:
            return False
        user, pw = decoded.split(":", 1)
        return (
            hmac.compare_digest(user, cfg.web_user)
            and hmac.compare_digest(pw, cfg.web_password)
        )

    async def _route(self, request: _HttpRequest):
        handler = self._routes.get((request.method, request.path))
        if handler is not None:
            return await handler(request)
        if request.method == "GET":
            return self._serve_static(request.path)
        return 405, b"Method not allowed", {"Allow": "GET, POST"}

    # ---- static files ----------------------------------------------------

    def _serve_static(self, path: str):
        relative = "index.html" if path in ("", "/") else path.lstrip("/")
        if ".." in relative.split("/"):
            return 400, b"bad path", {}

        target = self._dir / relative
        if not target.is_file():
            return 404, b"not found", {}

        body = target.read_bytes()
        ctype = _CONTENT_TYPES.get(target.suffix, "application/octet-stream")
        return 200, body, {"Content-Type": ctype}

    # ---- API handlers ----------------------------------------------------

    async def _handle_state(self, request: _HttpRequest):
        cfg = self._proxy.config
        # Use the requester's Host header as a fallback so the link points
        # at whatever IP the client used to reach us — works on routers with
        # multiple LANs where outbound-IP guess is wrong.
        host_override = _host_from_header(request.header("host"))
        link = proxy_tg_link(
            cfg, host_override=cfg.link_host or host_override
        )
        body = json.dumps(
            {
                "config": cfg.to_dict(),
                "stats": self._proxy.stats.as_dict(),
                "listening": self._proxy.listening,
                "link": link,
                "version": _version(),
            },
            ensure_ascii=False,
            indent=2,
        ).encode("utf-8")
        return 200, body, {"Content-Type": "application/json; charset=utf-8"}

    async def _handle_save_config(self, request: _HttpRequest):
        try:
            raw = json.loads(request.body.decode("utf-8"))
        except Exception as exc:
            return _json_error(400, f"invalid JSON: {exc}")

        if not isinstance(raw, dict):
            return _json_error(400, "expected JSON object")

        # Preserve secret if client sent it empty (UI may hide it).
        if not raw.get("secret"):
            raw["secret"] = self._proxy.config.secret

        new_cfg = _from_dict(raw)
        errors = new_cfg.validate()
        if errors:
            return _json_error(400, "; ".join(errors))

        save_config(new_cfg, self._config_path)
        self._proxy.apply_config(new_cfg)
        asyncio.create_task(self._restart_proxy_quiet())
        return _json_ok({"saved": True})

    async def _handle_restart(self, request: _HttpRequest):
        asyncio.create_task(self._restart_proxy_quiet())
        return _json_ok({"restarting": True})

    async def _handle_new_secret(self, request: _HttpRequest):
        cfg = self._proxy.config
        cfg.secret = secrets.token_hex(16)
        save_config(cfg, self._config_path)
        asyncio.create_task(self._restart_proxy_quiet())
        return _json_ok({"secret": cfg.secret})

    async def _restart_proxy_quiet(self) -> None:
        try:
            await self._proxy.restart()
        except Exception:
            log.exception("proxy restart failed")


# --- low-level HTTP helpers -------------------------------------------------


async def _read_request(reader) -> Optional[_HttpRequest]:
    request_line = await reader.readline()
    if not request_line:
        return None
    try:
        method, raw_path, _ = request_line.decode("ascii").rstrip().split(" ", 2)
    except ValueError:
        return None

    headers: Dict[str, str] = {}
    while True:
        line = await reader.readline()
        if not line or line in (b"\r\n", b"\n"):
            break
        text = line.decode("latin-1").rstrip("\r\n")
        if ":" in text:
            k, v = text.split(":", 1)
            headers[k.strip().lower()] = v.strip()

    body = b""
    length = int(headers.get("content-length", "0") or "0")
    if length > 0:
        body = await reader.readexactly(min(length, 1 * 1024 * 1024))

    # Strip query string — we don't use it.
    path = raw_path.split("?", 1)[0] or "/"
    return _HttpRequest(method.upper(), path, headers, body)


async def _respond(
    writer, status: int, body: bytes, extra_headers: Dict[str, str]
) -> None:
    reason = _REASON_PHRASES.get(status, "OK")
    headers = {
        "Content-Length": str(len(body)),
        "Connection": "close",
        "Server": "tgwsproxy/webui",
    }
    headers.update(extra_headers or {})

    header_block = f"HTTP/1.1 {status} {reason}\r\n" + "".join(
        f"{k}: {v}\r\n" for k, v in headers.items()
    ) + "\r\n"
    writer.write(header_block.encode("latin-1"))
    if body:
        writer.write(body)
    try:
        await writer.drain()
    except ConnectionError:
        pass


_REASON_PHRASES = {
    200: "OK",
    204: "No Content",
    301: "Moved Permanently",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    500: "Internal Server Error",
}


def _json_ok(payload: Dict[str, Any]):
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    return 200, body, {"Content-Type": "application/json; charset=utf-8"}


def _json_error(status: int, message: str):
    body = json.dumps(
        {"error": message}, ensure_ascii=False
    ).encode("utf-8")
    return status, body, {"Content-Type": "application/json; charset=utf-8"}


def _version() -> str:
    from . import __version__
    return __version__


def _host_from_header(header: str) -> str:
    """Strip the port off a Host: header value."""
    if not header:
        return ""
    # IPv6 literal: "[::1]:1434"
    if header.startswith("["):
        end = header.find("]")
        if end > 0:
            return header[: end + 1]
        return header
    return header.split(":", 1)[0]
