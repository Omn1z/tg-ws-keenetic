"""Top-level TCP server for the MTProto proxy.

Composes the handler, pool and stats objects, exposes a clean `start`/
`stop` interface that the entrypoint and the web UI both use.
"""
from __future__ import annotations

import asyncio
import logging
import socket as _socket
import time
from typing import Optional, Set

from .balancer import balancer
from .config import Config
from .fallback import FallbackConfig
from .handler import ClientHandler, HandlerSettings
from .stats import stats
from .ws_pool import WebSocketPool

log = logging.getLogger("tgwsproxy.server")


class ProxyServer:
    def __init__(self, config: Config):
        self._config = config
        self._server: Optional[asyncio.AbstractServer] = None
        self._stop_event: Optional[asyncio.Event] = None
        self._serve_task: Optional[asyncio.Task] = None
        self._stats_task: Optional[asyncio.Task] = None
        self._tasks: Set[asyncio.Task] = set()
        self._handler: Optional[ClientHandler] = None
        self._pool: Optional[WebSocketPool] = None

    @property
    def listening(self) -> bool:
        return self._server is not None and self._server.is_serving()

    @property
    def stats(self):
        return stats

    @property
    def pool(self) -> Optional[WebSocketPool]:
        return self._pool

    @property
    def config(self) -> Config:
        return self._config

    async def start(self) -> None:
        if self.listening:
            return
        self._stop_event = asyncio.Event()

        if self._config.cfproxy and not self._config.cfproxy_user_domain:
            balancer.update_pool(self._config.cfproxy_default_pool())
        elif self._config.cfproxy_user_domain:
            balancer.update_pool([self._config.cfproxy_user_domain])

        self._pool = WebSocketPool(
            target_size=self._config.pool_size,
            buffer_size=self._config.buffer_size,
            stats=stats,
        )
        self._handler = ClientHandler(
            settings=self._build_handler_settings(),
            pool=self._pool,
            stats=stats,
        )
        stats.started_at = time.time()

        self._server = await asyncio.start_server(
            self._on_client, self._config.host, self._config.port
        )
        self._set_nodelay()

        log.info("=" * 60)
        log.info("  TG WS Proxy listening on %s:%d",
                 self._config.host, self._config.port)
        log.info("  Secret: %s", self._config.secret)
        log.info("  DC routes:")
        for dc, ip in sorted(self._config.dc_redirects.items()):
            log.info("    DC%d -> %s", dc, ip)
        if self._config.fake_tls_domain:
            log.info("  Fake TLS: %s", self._config.fake_tls_domain)
        log.info("=" * 60)

        self._stats_task = asyncio.create_task(self._log_stats_loop())
        await self._pool.warmup(self._config.dc_redirects)

        self._serve_task = asyncio.create_task(self._serve_forever())

    async def stop(self) -> None:
        if not self.listening:
            return
        log.info("Stopping proxy server")
        if self._stop_event is not None:
            self._stop_event.set()

        if self._server is not None:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:
                pass

        if self._stats_task is not None:
            self._stats_task.cancel()
            try:
                await self._stats_task
            except (asyncio.CancelledError, Exception):
                pass
            self._stats_task = None

        if self._serve_task is not None:
            self._serve_task.cancel()
            try:
                await self._serve_task
            except (asyncio.CancelledError, Exception):
                pass
            self._serve_task = None

        for task in list(self._tasks):
            task.cancel()
        for task in list(self._tasks):
            try:
                await task
            except BaseException:
                pass
        self._tasks.clear()

        if self._pool is not None:
            self._pool.reset()

        self._server = None
        self._handler = None
        log.info("Proxy server stopped. Stats: %s", stats.summary())

    async def restart(self) -> None:
        await self.stop()
        await self.start()

    def apply_config(self, new_config: Config) -> None:
        """Replace the config snapshot. Caller must `restart()` to apply."""
        self._config = new_config

    async def serve_until_stop(self) -> None:
        """Block until stop() is called or the loop is cancelled."""
        if self._stop_event is None:
            return
        await self._stop_event.wait()

    # --- internals -------------------------------------------------------

    def _build_handler_settings(self) -> HandlerSettings:
        return HandlerSettings(
            secret=bytes.fromhex(self._config.secret),
            dc_redirects=dict(self._config.dc_redirects),
            buffer_size=self._config.buffer_size,
            fake_tls_domain=self._config.fake_tls_domain,
            proxy_protocol=self._config.proxy_protocol,
            fallback=FallbackConfig(
                cfproxy_enabled=self._config.cfproxy,
                cfproxy_worker_domain=self._config.cfproxy_worker_domain,
            ),
        )

    def _on_client(self, reader, writer) -> None:
        if self._handler is None:
            try:
                writer.close()
            except Exception:
                pass
            return
        task = asyncio.create_task(self._handler.handle(reader, writer))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def _set_nodelay(self) -> None:
        if self._server is None:
            return
        for sock in self._server.sockets or ():
            try:
                sock.setsockopt(_socket.IPPROTO_TCP, _socket.TCP_NODELAY, 1)
            except (OSError, AttributeError):
                pass

    async def _serve_forever(self) -> None:
        try:
            assert self._server is not None
            async with self._server:
                await self._server.serve_forever()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.error("Server crashed: %s", exc, exc_info=True)

    async def _log_stats_loop(self) -> None:
        try:
            while True:
                await asyncio.sleep(60)
                log.info("stats: %s", stats.summary())
        except asyncio.CancelledError:
            raise
