"""Logging configuration for both daemon and CLI invocations."""
from __future__ import annotations

import logging
import logging.handlers
import os
from typing import Optional


def configure_logging(
    log_file: Optional[str],
    max_mb: float,
    backups: int,
    verbose: bool,
) -> None:
    """Reset root logging to one console + optional rotating file handler."""
    level = logging.DEBUG if verbose else logging.INFO
    fmt = logging.Formatter(
        "%(asctime)s  %(levelname)-5s  %(name)s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
    root.setLevel(level)

    console = logging.StreamHandler()
    console.setFormatter(fmt)
    root.addHandler(console)

    if log_file:
        try:
            os.makedirs(os.path.dirname(log_file) or ".", exist_ok=True)
            file_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=max(32 * 1024, int(max_mb * 1024 * 1024)),
                backupCount=max(0, backups),
                encoding="utf-8",
            )
            file_handler.setFormatter(fmt)
            root.addHandler(file_handler)
        except OSError as exc:
            root.warning("Cannot open log file %s: %s", log_file, exc)

    # Quiet down chatty asyncio.
    logging.getLogger("asyncio").setLevel(logging.WARNING)
