"""Shared helpers for running external CLI tools."""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass


class IntegrationError(RuntimeError):
    pass


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


def require(binary: str) -> str:
    path = shutil.which(binary)
    if not path:
        raise IntegrationError(
            f"required tool not found in PATH: {binary!r}. "
            "Install it before invoking this integration."
        )
    return path


def run(cmd: list[str], *, timeout: int = 600, input_data: str | None = None) -> CommandResult:
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_data,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise IntegrationError(f"{cmd[0]} timed out after {timeout}s") from exc
    return CommandResult(
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )
