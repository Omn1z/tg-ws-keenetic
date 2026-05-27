"""Lightweight in-process counters for the proxy."""
from __future__ import annotations

from dataclasses import dataclass, field


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"


@dataclass
class Stats:
    connections_total: int = 0
    connections_active: int = 0
    connections_ws: int = 0
    connections_tcp_fallback: int = 0
    connections_cfproxy: int = 0
    connections_bad: int = 0
    connections_masked: int = 0
    ws_errors: int = 0
    bytes_up: int = 0
    bytes_down: int = 0
    pool_hits: int = 0
    pool_misses: int = 0
    started_at: float = field(default=0.0)

    def summary(self) -> str:
        pool = self.pool_hits + self.pool_misses
        pool_s = f"{self.pool_hits}/{pool}" if pool else "n/a"
        return (
            f"total={self.connections_total} "
            f"active={self.connections_active} "
            f"ws={self.connections_ws} "
            f"tcp_fb={self.connections_tcp_fallback} "
            f"cf={self.connections_cfproxy} "
            f"bad={self.connections_bad} "
            f"masked={self.connections_masked} "
            f"err={self.ws_errors} "
            f"pool={pool_s} "
            f"up={human_bytes(self.bytes_up)} "
            f"down={human_bytes(self.bytes_down)}"
        )

    def as_dict(self) -> dict:
        return {
            "connections": {
                "total": self.connections_total,
                "active": self.connections_active,
                "ws": self.connections_ws,
                "tcp_fallback": self.connections_tcp_fallback,
                "cfproxy": self.connections_cfproxy,
                "bad": self.connections_bad,
                "masked": self.connections_masked,
            },
            "traffic": {
                "bytes_up": self.bytes_up,
                "bytes_down": self.bytes_down,
                "human_up": human_bytes(self.bytes_up),
                "human_down": human_bytes(self.bytes_down),
            },
            "ws": {
                "errors": self.ws_errors,
                "pool_hits": self.pool_hits,
                "pool_misses": self.pool_misses,
            },
            "started_at": self.started_at,
        }


stats = Stats()
