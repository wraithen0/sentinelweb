"""sqlmap integration in **detection-only** mode.

We pass ``--batch --random-agent --level=1 --risk=1`` and never request
data dumping or shell. The wrapper verifies in-scope before invocation
and returns a list of detected injection points (not extracted data).
"""

from __future__ import annotations

import json
import re
import tempfile
from dataclasses import dataclass

from ..scope.policy import ScopePolicy
from ._subprocess import IntegrationError, require, run


@dataclass(frozen=True)
class SqlmapHit:
    url: str
    parameter: str
    type: str
    title: str


def detect(url: str, scope: ScopePolicy, *, timeout: int = 1200) -> list[SqlmapHit]:
    scope.assert_in_scope(url)
    binary = require("sqlmap")
    with tempfile.TemporaryDirectory() as out_dir:
        cmd = [
            binary,
            "-u",
            url,
            "--batch",
            "--random-agent",
            "--level=1",
            "--risk=1",
            "--output-dir",
            out_dir,
            "--flush-session",
            "--disable-coloring",
        ]
        res = run(cmd, timeout=timeout)
        # sqlmap exits 0 even when it finds nothing; surface stderr if non-zero.
        if res.returncode not in (0,):
            raise IntegrationError(f"sqlmap failed: {res.stderr.strip()[:300]}")
        return _parse_stdout(res.stdout, default_url=url) + _parse_target_log(out_dir, url)


_PARAM_RE = re.compile(
    r"Parameter:\s*(?P<param>[^\s(]+)\s*\((?P<where>[^)]+)\)\s*"
    r"(?:.*?Type:\s*(?P<type>[^\n]+))?\s*"
    r"(?:.*?Title:\s*(?P<title>[^\n]+))?",
    re.S,
)


def _parse_stdout(stdout: str, *, default_url: str) -> list[SqlmapHit]:
    hits: list[SqlmapHit] = []
    for m in _PARAM_RE.finditer(stdout):
        hits.append(
            SqlmapHit(
                url=default_url,
                parameter=m.group("param") or "",
                type=(m.group("type") or "").strip(),
                title=(m.group("title") or "").strip(),
            )
        )
    return hits


def _parse_target_log(out_dir: str, default_url: str) -> list[SqlmapHit]:
    """sqlmap also writes per-target JSON sometimes — best-effort parse."""
    import os

    hits: list[SqlmapHit] = []
    for root, _dirs, files in os.walk(out_dir):
        for name in files:
            if not name.endswith(".json"):
                continue
            try:
                with open(os.path.join(root, name)) as fh:
                    data = json.load(fh)
            except (OSError, json.JSONDecodeError):
                continue
            for row in data.get("data", []) or []:
                hits.append(
                    SqlmapHit(
                        url=row.get("url", default_url),
                        parameter=row.get("parameter", ""),
                        type=row.get("type", ""),
                        title=row.get("title", ""),
                    )
                )
    return hits
