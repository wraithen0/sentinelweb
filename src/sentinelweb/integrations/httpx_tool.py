"""ProjectDiscovery `httpx` CLI integration (URL liveness/probe)."""

from __future__ import annotations

import json
from dataclasses import dataclass

from ..scope.policy import ScopePolicy
from ._subprocess import IntegrationError, require, run


@dataclass(frozen=True)
class HttpxResult:
    url: str
    status_code: int
    title: str = ""
    tech: tuple[str, ...] = ()
    server: str = ""


def probe(targets: list[str], scope: ScopePolicy, *, timeout: int = 600) -> list[HttpxResult]:
    if not targets:
        return []
    for t in targets:
        scope.assert_in_scope(t)
    binary = require("httpx")
    cmd = [
        binary,
        "-silent",
        "-json",
        "-status-code",
        "-title",
        "-tech-detect",
        "-server",
        "-no-color",
    ]
    res = run(cmd, timeout=timeout, input_data="\n".join(targets) + "\n")
    if res.returncode != 0 and not res.stdout.strip():
        raise IntegrationError(f"httpx failed: {res.stderr.strip()[:300]}")

    out: list[HttpxResult] = []
    for line in res.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        out.append(
            HttpxResult(
                url=row.get("url", ""),
                status_code=int(row.get("status_code") or row.get("status-code") or 0),
                title=str(row.get("title", "")),
                tech=tuple(row.get("tech", []) or []),
                server=str(row.get("webserver") or row.get("server") or ""),
            )
        )
    return out
