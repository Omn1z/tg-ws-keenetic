"""Hot WebSocket connection pool, keyed by (DC, is_media).

Telegram clients open lots of short-lived MTProto sessions; opening a WSS
connection for each one is the slowest part of the path. We pre-open a
small pool per (DC, is_media) bucket and lend connections out as needed.
"""
from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from typing import Deque, Dict, List, Optional, Set, Tuple

from .stats import Stats
from .websocket import RawWebSocket, WsHandshakeError

log = logging.getLogger("tgwsproxy.ws_pool")

PoolKey = Tuple[int, bool]


def ws_domains_for(dc: int, is_media: Optional[bool]) -> List[str]:
    """Native Telegram WS endpoints. Media variant is preferred for media DCs."""
    if dc == 203:
        dc = 2
    if is_media is None or is_media:
        return [
            f"kws{dc}-1.web.telegram.org",
            f"kws{dc}.web.telegram.org",
        ]
    return [
        f"kws{dc}.web.telegram.org",
        f"kws{dc}-1.web.telegram.org",
    ]


class WebSocketPool:
    """Idle-keep-alive pool with background refill."""

    MAX_AGE_SECONDS = 120.0

    def __init__(self, target_size: int, buffer_size: int, stats: Stats):
        self._target = max(0, target_size)
        self._buffer = buffer_size
        self._stats = stats
        self._idle: Dict[PoolKey, Deque[Tuple[RawWebSocket, float]]] = {}
        self._refilling: Set[PoolKey] = set()

    @property
    def target_size(self) -> int:
        return self._target

    def set_target(self, size: int) -> None:
        self._target = max(0, size)

    async def acquire(
        self, dc: int, is_media: bool, target_ip: str, domains: List[str]
    ) -> Optional[RawWebSocket]:
        key = (dc, is_media)
        bucket = self._idle.setdefault(key, deque())
        now = time.monotonic()

        while bucket:
            ws, created = bucket.popleft()
            if (
                now - created > self.MAX_AGE_SECONDS
                or ws.closed
            ):
                asyncio.create_task(self._quiet_close(ws))
                continue
            self._stats.pool_hits += 1
            self._schedule_refill(key, target_ip, domains)
            return ws

        self._stats.pool_misses += 1
        self._schedule_refill(key, target_ip, domains)
        return None

    async def warmup(self, dc_to_ip: Dict[int, str]) -> None:
        for dc, target_ip in dc_to_ip.items():
            if target_ip is None:
                continue
            for is_media in (False, True):
                self._schedule_refill(
                    (dc, is_media), target_ip, ws_domains_for(dc, is_media)
                )
        log.info("WS pool warmup started for %d DC(s)", len(dc_to_ip))

    def reset(self) -> None:
        for bucket in self._idle.values():
            for ws, _ in bucket:
                asyncio.create_task(self._quiet_close(ws))
        self._idle.clear()
        self._refilling.clear()

    def _schedule_refill(
        self, key: PoolKey, target_ip: str, domains: List[str]
    ) -> None:
        if key in self._refilling or self._target == 0:
            return
        self._refilling.add(key)
        asyncio.create_task(self._refill(key, target_ip, domains))

    async def _refill(
        self, key: PoolKey, target_ip: str, domains: List[str]
    ) -> None:
        dc, is_media = key
        try:
            bucket = self._idle.setdefault(key, deque())
            needed = self._target - len(bucket)
            if needed <= 0:
                return
            connectors = [
                asyncio.create_task(self._connect_one(target_ip, domains))
                for _ in range(needed)
            ]
            for task in connectors:
                try:
                    ws = await task
                except Exception:
                    continue
                if ws is not None:
                    bucket.append((ws, time.monotonic()))
            log.debug(
                "WS pool refilled DC%d%s -> %d ready",
                dc,
                "m" if is_media else "",
                len(bucket),
            )
        finally:
            self._refilling.discard(key)

    async def _connect_one(
        self, target_ip: str, domains: List[str]
    ) -> Optional[RawWebSocket]:
        for domain in domains:
            try:
                return await RawWebSocket.connect(
                    target_ip,
                    domain,
                    timeout=8,
                    buffer_size=self._buffer,
                )
            except WsHandshakeError as exc:
                if exc.is_redirect:
                    continue
                return None
            except Exception:
                return None
        return None

    @staticmethod
    async def _quiet_close(ws: RawWebSocket) -> None:
        try:
            await ws.close()
        except Exception:
            pass
