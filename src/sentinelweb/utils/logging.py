"""Structured logging for SentinelWeb runs."""

from __future__ import annotations

import logging
import sys
from logging import Logger

from rich.logging import RichHandler

_CONFIGURED = False


def configure(level: str = "INFO") -> None:
    """Configure the root logger once. Idempotent."""
    global _CONFIGURED
    if _CONFIGURED:
        return
    handler = RichHandler(
        rich_tracebacks=True,
        show_path=False,
        markup=True,
        show_time=True,
    )
    logging.basicConfig(
        level=level.upper(),
        format="%(message)s",
        datefmt="[%X]",
        handlers=[handler],
        force=True,
    )
    # Quiet noisy libraries.
    for name in ("httpx", "httpcore", "urllib3", "asyncio"):
        logging.getLogger(name).setLevel(logging.WARNING)
    _CONFIGURED = True


def get_logger(name: str) -> Logger:
    if not _CONFIGURED:
        configure()
    return logging.getLogger(name)


def fatal(message: str, code: int = 2) -> None:
    """Print a hard error and exit non-zero."""
    print(f"sentinelweb: error: {message}", file=sys.stderr)
    raise SystemExit(code)
