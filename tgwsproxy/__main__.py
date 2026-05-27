"""CLI entrypoint.

Usage:
    python3 -m tgwsproxy            # default config path
    python3 -m tgwsproxy --config /some/path.json
    python3 -m tgwsproxy --no-webui   # just the proxy, no /api server
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import sys
from typing import Optional

from . import __version__
from .config import (
    DEFAULT_CONFIG_PATH,
    Config,
    default_config,
    load_config,
    proxy_tg_link,
    save_config,
)
from .logging_setup import configure_logging
from .server import ProxyServer
from .updater import (
    UpdateError,
    apply_update,
    check_for_update,
)
from .webui import WebUI

log = logging.getLogger("tgwsproxy")


def _parse_args(argv: Optional[list] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        prog="tgwsproxy",
        description="Telegram MTProto-over-WebSocket proxy for Keenetic Entware",
    )
    ap.add_argument(
        "--config", "-c",
        default=DEFAULT_CONFIG_PATH,
        help=f"Path to JSON config (default: {DEFAULT_CONFIG_PATH})",
    )
    ap.add_argument(
        "--no-webui", action="store_true",
        help="Do not start the web configuration UI",
    )
    ap.add_argument(
        "--init-config", action="store_true",
        help="Write a default config file if it doesn't exist and exit",
    )
    ap.add_argument(
        "--print-link", action="store_true",
        help="Print the tg:// proxy link and exit",
    )
    ap.add_argument(
        "--check-update", action="store_true",
        help="Check GitHub for a newer version and exit",
    )
    ap.add_argument(
        "--update", action="store_true",
        help="Download and install the latest release, then exit",
    )
    ap.add_argument(
        "--update-channel", default=None, choices=("release", "main"),
        help="Override config update_channel for this run",
    )
    ap.add_argument(
        "--version", action="version", version=f"tgwsproxy {__version__}",
    )
    return ap.parse_args(argv)


def _bootstrap_config(path: str) -> Config:
    cfg = load_config(path)
    # Newly-defaulted configs need their secret persisted on first run.
    try:
        save_config(cfg, path)
    except OSError as exc:
        log.warning("Cannot persist config to %s: %s", path, exc)
    errors = cfg.validate()
    if errors:
        log.warning("Config has %d issue(s): %s", len(errors), "; ".join(errors))
    return cfg


async def _run(cfg: Config, start_webui: bool) -> None:
    proxy = ProxyServer(cfg)
    webui = WebUI(proxy) if start_webui else None

    loop = asyncio.get_running_loop()
    stop = asyncio.Event()

    def request_stop(*_):
        log.info("Signal received, shutting down")
        stop.set()

    for signame in ("SIGINT", "SIGTERM"):
        try:
            loop.add_signal_handler(getattr(signal, signame), request_stop)
        except (NotImplementedError, AttributeError, ValueError):
            # Windows during dev; ignore.
            pass

    await proxy.start()
    if webui is not None:
        await webui.start()

    try:
        await stop.wait()
    finally:
        if webui is not None:
            await webui.stop()
        await proxy.stop()


def main(argv: Optional[list] = None) -> int:
    args = _parse_args(argv)

    if args.init_config:
        cfg = default_config()
        save_config(cfg, args.config)
        print(f"Default config written to {args.config}")
        print(f"Secret: {cfg.secret}")
        return 0

    cfg = _bootstrap_config(args.config)
    configure_logging(
        cfg.log_file, cfg.log_max_mb, cfg.log_backups, cfg.verbose
    )

    if args.print_link:
        print(proxy_tg_link(cfg))
        return 0

    channel = args.update_channel or cfg.update_channel
    if args.check_update:
        return _cmd_check_update(cfg.update_repo, channel)
    if args.update:
        return _cmd_apply_update(cfg.update_repo, channel)

    log.info("tgwsproxy %s starting (config: %s)", __version__, args.config)
    try:
        asyncio.run(_run(cfg, start_webui=not args.no_webui))
    except KeyboardInterrupt:
        log.info("Interrupted by user")
    return 0


def _cmd_check_update(repo: str, channel: str) -> int:
    try:
        info = asyncio.run(check_for_update(repo, channel))
    except UpdateError as exc:
        print(f"update check failed: {exc}", file=sys.stderr)
        return 2
    print(f"current: {info.current}")
    print(f"latest:  {info.latest}  ({info.channel})")
    print(f"update available: {'yes' if info.available else 'no'}")
    if info.published_at:
        print(f"published: {info.published_at}")
    if info.notes:
        print("\nnotes:")
        for line in info.notes.splitlines()[:20]:
            print(f"  {line}")
    return 0


def _cmd_apply_update(repo: str, channel: str) -> int:
    try:
        info = asyncio.run(check_for_update(repo, channel))
    except UpdateError as exc:
        print(f"update check failed: {exc}", file=sys.stderr)
        return 2
    if not info.available:
        print(f"already at latest ({info.current}); nothing to do")
        return 0
    print(f"updating: {info.current} -> {info.latest}")
    try:
        script = apply_update(info)
    except UpdateError as exc:
        print(f"update failed: {exc}", file=sys.stderr)
        return 2
    print(f"apply script spawned: {script}")
    print("Service will restart in a few seconds; tail /opt/var/log/tgwsproxy/update.log")
    return 0


if __name__ == "__main__":
    sys.exit(main())
