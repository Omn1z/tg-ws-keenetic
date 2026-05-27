"""TCP↔WebSocket re-encrypting bridge.

The bridge is the hot path: every byte goes through here. We decrypt with
the client key and immediately re-encrypt with the upstream key before
forwarding (and vice versa for the response direction).

`MessageSplitter` slices an MTProto byte stream into individual transport
packets so each becomes its own WS binary frame. This is what makes the
WS encapsulation efficient.
"""
from __future__ import annotations

import asyncio
import logging
import struct
from typing import List, Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .constants import (
    PROTO_INT_ABRIDGED,
    PROTO_INT_INTERMEDIATE,
    PROTO_INT_PADDED_INTERMEDIATE,
    ZERO_64,
)
from .crypto import ReencryptionContext
from .stats import Stats, human_bytes
from .websocket import RawWebSocket

log = logging.getLogger("tgwsproxy.bridge")
_UNPACK_LE_U32 = struct.Struct("<I")


class MessageSplitter:
    """Decrypts incoming chunks just enough to know packet boundaries."""

    __slots__ = ("_decryptor", "_proto", "_cipher_buf", "_plain_buf", "_off")

    def __init__(self, relay_handshake: bytes, proto_int: int) -> None:
        cipher = Cipher(
            algorithms.AES(relay_handshake[8:40]),
            modes.CTR(relay_handshake[40:56]),
        )
        self._decryptor = cipher.encryptor()
        self._decryptor.update(ZERO_64)
        self._proto = proto_int
        self._cipher_buf = bytearray()
        self._plain_buf = bytearray()
        self._off = False  # set to True if we hit an unknown packet shape

    def split(self, chunk: bytes) -> List[bytes]:
        if not chunk:
            return []
        if self._off:
            return [chunk]

        self._cipher_buf.extend(chunk)
        self._plain_buf.extend(self._decryptor.update(chunk))

        parts: List[bytes] = []
        while self._cipher_buf:
            length = self._next_packet_len()
            if length is None:
                break
            if length <= 0:
                # Unknown — flush remainder as one piece and stop splitting.
                parts.append(bytes(self._cipher_buf))
                self._cipher_buf.clear()
                self._plain_buf.clear()
                self._off = True
                break
            parts.append(bytes(self._cipher_buf[:length]))
            del self._cipher_buf[:length]
            del self._plain_buf[:length]
        return parts

    def flush(self) -> List[bytes]:
        if not self._cipher_buf:
            return []
        tail = bytes(self._cipher_buf)
        self._cipher_buf.clear()
        self._plain_buf.clear()
        return [tail]

    def _next_packet_len(self) -> Optional[int]:
        if not self._plain_buf:
            return None
        if self._proto == PROTO_INT_ABRIDGED:
            return self._abridged_len()
        if self._proto in (
            PROTO_INT_INTERMEDIATE,
            PROTO_INT_PADDED_INTERMEDIATE,
        ):
            return self._intermediate_len()
        return 0

    def _abridged_len(self) -> Optional[int]:
        first = self._plain_buf[0]
        if first in (0x7F, 0xFF):
            if len(self._plain_buf) < 4:
                return None
            payload_len = int.from_bytes(self._plain_buf[1:4], "little") * 4
            header_len = 4
        else:
            payload_len = (first & 0x7F) * 4
            header_len = 1
        if payload_len <= 0:
            return 0
        total = header_len + payload_len
        return total if len(self._plain_buf) >= total else None

    def _intermediate_len(self) -> Optional[int]:
        if len(self._plain_buf) < 4:
            return None
        payload_len = _UNPACK_LE_U32.unpack_from(self._plain_buf, 0)[0] & 0x7FFFFFFF
        if payload_len <= 0:
            return 0
        total = 4 + payload_len
        return total if len(self._plain_buf) >= total else None


async def bridge_ws(
    client_reader,
    client_writer,
    ws: RawWebSocket,
    label: str,
    ctx: ReencryptionContext,
    stats: Stats,
    dc: int,
    is_media: bool,
    splitter: Optional[MessageSplitter] = None,
) -> None:
    """TCP(client) ↔ WS(telegram) with re-encryption."""
    dc_tag = f"DC{dc}{'m' if is_media else ''}"
    start = asyncio.get_running_loop().time()
    up_bytes = down_bytes = up_packets = down_packets = 0

    async def client_to_upstream() -> None:
        nonlocal up_bytes, up_packets
        try:
            while True:
                chunk = await client_reader.read(65536)
                if not chunk:
                    if splitter:
                        tail = splitter.flush()
                        if tail:
                            await ws.send(tail[0])
                    break
                up_bytes += len(chunk)
                up_packets += 1
                stats.bytes_up += len(chunk)
                reencrypted = ctx.upstream_encrypt.update(
                    ctx.client_decrypt.update(chunk)
                )
                if splitter:
                    parts = splitter.split(reencrypted)
                    if not parts:
                        continue
                    if len(parts) > 1:
                        await ws.send_batch(parts)
                    else:
                        await ws.send(parts[0])
                else:
                    await ws.send(reencrypted)
        except (asyncio.CancelledError, ConnectionError, OSError):
            return
        except Exception as exc:
            log.debug("[%s] tcp->ws ended: %s", label, exc)

    async def upstream_to_client() -> None:
        nonlocal down_bytes, down_packets
        try:
            while True:
                data = await ws.recv()
                if data is None:
                    break
                down_bytes += len(data)
                down_packets += 1
                stats.bytes_down += len(data)
                reencrypted = ctx.client_encrypt.update(
                    ctx.upstream_decrypt.update(data)
                )
                client_writer.write(reencrypted)
                await client_writer.drain()
        except (asyncio.CancelledError, ConnectionError, OSError):
            return
        except Exception as exc:
            log.debug("[%s] ws->tcp ended: %s", label, exc)

    tasks = [
        asyncio.create_task(client_to_upstream()),
        asyncio.create_task(upstream_to_client()),
    ]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for t in tasks:
            t.cancel()
        for t in tasks:
            try:
                await t
            except BaseException:
                pass
        elapsed = asyncio.get_running_loop().time() - start
        log.info(
            "[%s] %s WS closed: ^%s (%d) v%s (%d) in %.1fs",
            label,
            dc_tag,
            human_bytes(up_bytes),
            up_packets,
            human_bytes(down_bytes),
            down_packets,
            elapsed,
        )
        try:
            await ws.close()
        except BaseException:
            pass
        try:
            client_writer.close()
            await client_writer.wait_closed()
        except BaseException:
            pass


async def bridge_tcp(
    client_reader,
    client_writer,
    remote_reader,
    remote_writer,
    label: str,
    ctx: ReencryptionContext,
    stats: Stats,
) -> None:
    """TCP(client) ↔ TCP(telegram) with re-encryption — used as TCP fallback."""

    async def forward(src, dst, is_up: bool) -> None:
        try:
            while True:
                chunk = await src.read(65536)
                if not chunk:
                    break
                if is_up:
                    stats.bytes_up += len(chunk)
                    reencrypted = ctx.upstream_encrypt.update(
                        ctx.client_decrypt.update(chunk)
                    )
                else:
                    stats.bytes_down += len(chunk)
                    reencrypted = ctx.client_encrypt.update(
                        ctx.upstream_decrypt.update(chunk)
                    )
                dst.write(reencrypted)
                await dst.drain()
        except (asyncio.CancelledError, ConnectionError, OSError):
            return
        except Exception as exc:
            log.debug("[%s] tcp-bridge ended: %s", label, exc)

    tasks = [
        asyncio.create_task(forward(client_reader, remote_writer, True)),
        asyncio.create_task(forward(remote_reader, client_writer, False)),
    ]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for t in tasks:
            t.cancel()
        for t in tasks:
            try:
                await t
            except BaseException:
                pass
        for w in (client_writer, remote_writer):
            try:
                w.close()
                await w.wait_closed()
            except BaseException:
                pass
