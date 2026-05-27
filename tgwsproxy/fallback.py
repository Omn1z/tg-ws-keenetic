"""Fallback strategies when the primary WSS path to Telegram is down.

Order of attempts is decided here based on what is enabled in config:
  1. Cloudflare Worker (if `cfproxy_worker_domain` set)
  2. Cloudflare proxied domain pool (if `cfproxy` enabled)
  3. Direct TCP to the DC default IP on :443

The first method that returns True wins. If everything fails, the client
is dropped.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Optional
from urllib.parse import urlencode

from .balancer import balancer
from .bridge import MessageSplitter, bridge_tcp, bridge_ws
from .constants import DC_DEFAULT_IPS
from .crypto import ReencryptionContext
from .stats import Stats
from .websocket import RawWebSocket

log = logging.getLogger("tgwsproxy.fallback")


class FallbackConfig:
    """Bundles the few flags that influence fallback selection."""

    __slots__ = ("cfproxy_enabled", "cfproxy_worker_domain")

    def __init__(self, cfproxy_enabled: bool, cfproxy_worker_domain: str):
        self.cfproxy_enabled = cfproxy_enabled
        self.cfproxy_worker_domain = cfproxy_worker_domain


async def attempt_fallback(
    client_reader,
    client_writer,
    relay_init: bytes,
    label: str,
    dc: int,
    is_media: bool,
    ctx: ReencryptionContext,
    stats: Stats,
    cfg: FallbackConfig,
    splitter: Optional[MessageSplitter] = None,
) -> bool:
    """Try each enabled fallback in order. Returns True if one took over."""
    target_ip = DC_DEFAULT_IPS.get(dc)
    media_tag = " media" if is_media else ""

    if cfg.cfproxy_worker_domain and target_ip:
        if await _cfworker(
            client_reader,
            client_writer,
            relay_init,
            label,
            dc,
            is_media,
            target_ip,
            ctx,
            stats,
            cfg,
            splitter,
        ):
            return True

    if cfg.cfproxy_enabled:
        if await _cfproxy(
            client_reader,
            client_writer,
            relay_init,
            label,
            dc,
            is_media,
            ctx,
            stats,
            splitter,
        ):
            return True

    if target_ip:
        log.info("[%s] DC%d%s -> TCP fallback %s:443",
                 label, dc, media_tag, target_ip)
        if await _tcp(
            client_reader,
            client_writer,
            target_ip,
            relay_init,
            label,
            ctx,
            stats,
        ):
            return True

    return False


async def _cfworker(
    client_reader,
    client_writer,
    relay_init,
    label,
    dc,
    is_media,
    target_ip,
    ctx,
    stats,
    cfg,
    splitter,
) -> bool:
    media_tag = " media" if is_media else ""
    domain = cfg.cfproxy_worker_domain
    query = urlencode(
        {"dst": target_ip, "dc": str(dc), "media": "1" if is_media else "0"}
    )
    log.info("[%s] DC%d%s -> CF worker %s", label, dc, media_tag, domain)
    try:
        ws = await RawWebSocket.connect(
            domain, domain, timeout=10.0, path=f"/apiws?{query}"
        )
    except Exception as exc:
        log.warning("[%s] DC%d%s CF worker failed: %r",
                    label, dc, media_tag, exc)
        return False

    stats.connections_cfproxy += 1
    await ws.send(relay_init)
    await bridge_ws(
        client_reader, client_writer, ws, label, ctx, stats, dc, is_media,
        splitter=splitter,
    )
    return True


async def _cfproxy(
    client_reader,
    client_writer,
    relay_init,
    label,
    dc,
    is_media,
    ctx,
    stats,
    splitter,
) -> bool:
    media_tag = " media" if is_media else ""
    log.info("[%s] DC%d%s -> CF proxy pool", label, dc, media_tag)

    ws = None
    chosen = None
    for base in balancer.candidates_for(dc):
        domain = f"kws{dc}.{base}"
        try:
            ws = await RawWebSocket.connect(domain, domain, timeout=10.0)
            chosen = base
            break
        except Exception as exc:
            log.warning("[%s] DC%d%s CF %s failed: %r",
                        label, dc, media_tag, base, exc)

    if ws is None:
        return False

    if chosen and balancer.promote(dc, chosen):
        log.info("[%s] active CF domain for DC%d -> %s", label, dc, chosen)

    stats.connections_cfproxy += 1
    await ws.send(relay_init)
    await bridge_ws(
        client_reader, client_writer, ws, label, ctx, stats, dc, is_media,
        splitter=splitter,
    )
    return True


async def _tcp(
    client_reader,
    client_writer,
    dst,
    relay_init,
    label,
    ctx,
    stats,
) -> bool:
    try:
        remote_reader, remote_writer = await asyncio.wait_for(
            asyncio.open_connection(dst, 443), timeout=10
        )
    except Exception as exc:
        log.warning("[%s] TCP fallback %s:443 failed: %r", label, dst, exc)
        return False

    stats.connections_tcp_fallback += 1
    remote_writer.write(relay_init)
    await remote_writer.drain()
    await bridge_tcp(
        client_reader, client_writer, remote_reader, remote_writer,
        label, ctx, stats,
    )
    return True
