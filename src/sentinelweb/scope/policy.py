"""Scope policy: load and enforce ``scope.yaml``.

Every operation in SentinelWeb is gated on a :class:`ScopePolicy`. The
policy declares which hosts are in scope, which are explicitly
out-of-scope, and the rate limits / engagement metadata for the run.

The framework refuses to send traffic to any host that is not in scope,
and refuses to run at all if the scope file is missing or malformed.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ..utils.urls import host_matches, normalize_host


class ScopeError(Exception):
    """Raised when a scope file is invalid or a target violates scope."""


class OutOfScopeError(ScopeError):
    """Raised when a host is not allowed by the loaded policy."""


@dataclass(frozen=True)
class Engagement:
    program: str
    authorization: str
    contact: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Engagement:
        program = str(data.get("program", "")).strip()
        authorization = str(data.get("authorization", "")).strip()
        contact = str(data.get("contact", "")).strip()
        if not program:
            raise ScopeError("engagement.program is required")
        if not authorization:
            raise ScopeError(
                "engagement.authorization is required (e.g. bug-bounty URL or written ROE id)"
            )
        return cls(program=program, authorization=authorization, contact=contact)


@dataclass(frozen=True)
class ScopePolicy:
    in_scope: tuple[str, ...]
    out_of_scope: tuple[str, ...]
    rate_per_sec: float
    max_concurrency: int
    engagement: Engagement
    notes: str = ""
    raw_path: Path | None = None

    @classmethod
    def load(cls, path: str | Path) -> ScopePolicy:
        p = Path(path)
        if not p.exists():
            raise ScopeError(f"scope file not found: {p}")
        with p.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        return cls.from_dict(data, raw_path=p)

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, raw_path: Path | None = None) -> ScopePolicy:
        if not isinstance(data, dict):
            raise ScopeError("scope file must be a YAML mapping")

        in_scope = _as_tuple_of_str(data.get("in_scope") or [], field_name="in_scope")
        out_of_scope = _as_tuple_of_str(
            data.get("out_of_scope") or [], field_name="out_of_scope"
        )
        if not in_scope:
            raise ScopeError("in_scope must contain at least one host or pattern")

        rate = float(data.get("rate_per_sec", 2.0))
        if rate <= 0 or rate > 50:
            raise ScopeError("rate_per_sec must be in (0, 50]; default conservative is 2")

        concurrency = int(data.get("max_concurrency", 4))
        if concurrency < 1 or concurrency > 32:
            raise ScopeError("max_concurrency must be in [1, 32]")

        engagement_data = data.get("engagement") or {}
        if not isinstance(engagement_data, dict):
            raise ScopeError("engagement must be a mapping")
        engagement = Engagement.from_dict(engagement_data)

        notes = str(data.get("notes", "")).strip()

        return cls(
            in_scope=in_scope,
            out_of_scope=out_of_scope,
            rate_per_sec=rate,
            max_concurrency=concurrency,
            engagement=engagement,
            notes=notes,
            raw_path=raw_path,
        )

    # -- enforcement ------------------------------------------------------

    def is_in_scope(self, host_or_url: str) -> bool:
        host = normalize_host(host_or_url)
        if not host:
            return False
        if any(host_matches(host, p) for p in self.out_of_scope):
            return False
        return any(host_matches(host, p) for p in self.in_scope)

    def assert_in_scope(self, host_or_url: str) -> None:
        if not self.is_in_scope(host_or_url):
            raise OutOfScopeError(
                f"target {host_or_url!r} is not allowed by scope "
                f"({self.raw_path or '<inline>'})"
            )

    def filter_in_scope(self, candidates: Sequence[str]) -> list[str]:
        return [c for c in candidates if self.is_in_scope(c)]


def _as_tuple_of_str(value: Any, *, field_name: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ScopeError(f"{field_name} must be a list of hosts/patterns")
    out: list[str] = []
    for v in value:
        if not isinstance(v, str) or not v.strip():
            raise ScopeError(f"{field_name} entries must be non-empty strings")
        out.append(v.strip().lower())
    return tuple(out)


def example_yaml() -> str:
    """Return the canonical example scope.yaml as a string."""
    return _EXAMPLE_TEMPLATE


_EXAMPLE_TEMPLATE = """\
# scope.yaml — engagement scope for SentinelWeb
#
# REQUIRED: do not run SentinelWeb without an accurate scope file.
#
# Patterns:
#   example.com         -> exact host match
#   *.example.com       -> any subdomain (does NOT include apex)

engagement:
  program: "Acme Bug Bounty"
  authorization: "https://hackerone.com/acme"   # required: program URL or written ROE
  contact: "security@acme.example"

in_scope:
  - "*.acme.example"
  - "api.acme.example"

out_of_scope:
  - "billing.acme.example"
  - "*.staff.acme.example"

rate_per_sec: 2          # per-host request rate (conservative default)
max_concurrency: 4
notes: |
  This file is required by SentinelWeb. Keep it under version control or
  attach it to the engagement record. Update it when scope changes.
"""


