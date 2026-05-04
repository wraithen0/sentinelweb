"""ffuf integration — content/path discovery wrapper."""

from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass

from ..scope.policy import ScopePolicy
from ._subprocess import IntegrationError, require, run


@dataclass(frozen=True)
class FfufHit:
    url: str
    status: int
    length: int
    words: int


def fuzz(
    url_template: str,
    wordlist: str,
    scope: ScopePolicy,
    *,
    threads: int | None = None,
    timeout: int = 1200,
    extra_args: tuple[str, ...] = (),
) -> list[FfufHit]:
    """Run ffuf against ``url_template`` (must contain ``FUZZ``)."""
    if "FUZZ" not in url_template:
        raise ValueError("url_template must contain the keyword FUZZ")
    scope.assert_in_scope(url_template.replace("FUZZ", ""))
    binary = require("ffuf")

    threads = threads or scope.max_concurrency
    with tempfile.NamedTemporaryFile("w+", suffix=".json", delete=True) as tmp:
        cmd = [
            binary,
            "-u",
            url_template,
            "-w",
            wordlist,
            "-t",
            str(threads),
            "-mc",
            "200,204,301,302,307,401,403",
            "-of",
            "json",
            "-o",
            tmp.name,
            "-s",
        ]
        cmd += list(extra_args)
        res = run(cmd, timeout=timeout)
        if res.returncode != 0:
            raise IntegrationError(f"ffuf failed: {res.stderr.strip()[:300]}")
        try:
            with open(tmp.name) as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            raise IntegrationError(f"could not parse ffuf output: {exc}") from exc

    out: list[FfufHit] = []
    for row in data.get("results", []):
        out.append(
            FfufHit(
                url=row.get("url", ""),
                status=int(row.get("status", 0)),
                length=int(row.get("length", 0)),
                words=int(row.get("words", 0)),
            )
        )
    return out
