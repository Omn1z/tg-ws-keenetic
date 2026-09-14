"""Logging configuration for both daemon and CLI invocations."""
from __future__ import annotations

import logging
import logging.handlers
import os
import re
from typing import Optional


class DomainCensorFilter(logging.Filter):
    """Mask CF fallback domains in logs while leaving telegram.org intact."""

    _domain_pattern = re.compile(
        r"(?<![\w-])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,}(?![\w-])"
    )

    def _censor_match(self, match: "re.Match") -> str:
        domain = match.group()
        normalized = domain.casefold().rstrip(".")
        if (
            normalized == "telegram.org"
            or normalized.endswith(".telegram.org")
            or normalized.endswith(".log")
        ):
            return domain
        parts = domain.split(".")
        if len(parts) < 2:
            return domain
        return ".".join(
            part if i == len(parts) - 1 else
            part[: len(part) // 2] + "*" * (len(part) - len(part) // 2)
            for i, part in enumerate(parts)
        )

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = self._domain_pattern.sub(
            self._censor_match, record.getMessage()
        )
        record.args = ()
        return True


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

    censor = DomainCensorFilter()

    console = logging.StreamHandler()
    console.setFormatter(fmt)
    console.addFilter(censor)
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
            file_handler.addFilter(censor)
            root.addHandler(file_handler)
        except OSError as exc:
            root.warning("Cannot open log file %s: %s", log_file, exc)

    # Quiet down chatty asyncio.
    logging.getLogger("asyncio").setLevel(logging.WARNING)
