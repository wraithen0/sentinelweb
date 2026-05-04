"""Authenticated-session bundle for in-scope scanning.

A :class:`Session` carries cookies and HTTP headers that should be
attached to outbound requests during an authorized engagement (e.g. a
logged-in test account on the in-scope target). Sessions are loaded
from disk separately from ``scope.yaml`` so credentials never end up in
the committed scope file, and they are **strictly host-scoped** — a
session is only attached to requests destined for hosts that are
allowed by the active :class:`ScopePolicy`. Out-of-scope hosts (e.g.
upstream APIs the target embeds) never see the session, even if a
cookie domain or header would otherwise apply.

YAML/JSON shape::

    cookies:
      - name: token
        value: "..."
        domain: "127.0.0.1"   # optional; defaults to all in-scope hosts
        path: "/"             # optional; default "/"
    headers:
      Authorization: "Bearer ..."
    host_headers:
      api.example.com:
        X-Internal-Token: "..."
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..utils.urls import host_matches, normalize_host
from .policy import ScopeError, ScopePolicy


class SessionError(ScopeError):
    """Raised when a session file is invalid."""


@dataclass(frozen=True)
class SessionCookie:
    """A single cookie carried in an authenticated session."""

    name: str
    value: str
    domain: str = "*"
    path: str = "/"

    def matches(self, host: str) -> bool:
        """Return True if this cookie should be sent to ``host``.

        ``domain="*"`` matches every host. Otherwise the same host
        pattern semantics as :class:`ScopePolicy` apply (exact host
        or ``*.example.com`` wildcard).
        """
        if self.domain == "*":
            return True
        return host_matches(host, self.domain)


@dataclass(frozen=True)
class Session:
    """An authenticated session for an in-scope target.

    A session binds cookies and headers to a :class:`ScopePolicy`. At
    bind time, every cookie domain pattern is checked against the
    policy's ``in_scope`` list — if no in-scope host could match the
    cookie, a :class:`SessionError` is raised so credentials cannot be
    silently leaked to out-of-scope infrastructure.
    """

    cookies: tuple[SessionCookie, ...] = ()
    headers: Mapping[str, str] = field(default_factory=dict)
    host_headers: Mapping[str, Mapping[str, str]] = field(default_factory=dict)
    raw_path: Path | None = None

    @classmethod
    def load(cls, path: str | Path) -> Session:
        p = Path(path)
        if not p.exists():
            raise SessionError(f"session file not found: {p}")
        text = p.read_text(encoding="utf-8")
        try:
            data = (
                json.loads(text)
                if p.suffix.lower() == ".json"
                else (yaml.safe_load(text) or {})
            )
        except (yaml.YAMLError, json.JSONDecodeError) as exc:
            raise SessionError(f"could not parse session file {p}: {exc}") from exc
        return cls.from_dict(data, raw_path=p)

    @classmethod
    def from_dict(
        cls, data: dict[str, Any], *, raw_path: Path | None = None
    ) -> Session:
        if not isinstance(data, dict):
            raise SessionError("session file must be a YAML/JSON mapping")

        cookies = _parse_cookies(data.get("cookies") or [])
        headers = _parse_headers(data.get("headers") or {}, field_name="headers")
        host_headers_raw = data.get("host_headers") or {}
        if not isinstance(host_headers_raw, dict):
            raise SessionError("host_headers must be a mapping of host -> headers")
        host_headers: dict[str, dict[str, str]] = {}
        for host, hh in host_headers_raw.items():
            if not isinstance(host, str) or not host.strip():
                raise SessionError("host_headers keys must be non-empty strings")
            host_headers[host.strip().lower()] = _parse_headers(
                hh, field_name=f"host_headers.{host}"
            )

        return cls(
            cookies=cookies,
            headers=headers,
            host_headers=host_headers,
            raw_path=raw_path,
        )

    # -- scope binding ---------------------------------------------------

    def bind(self, policy: ScopePolicy) -> Session:
        """Validate that this session's cookies cannot leak out of scope.

        Returns ``self`` (sessions are frozen, no mutation). Raises
        :class:`SessionError` if any cookie domain pattern would match
        a host that is not in the policy's ``in_scope`` list.
        """
        for cookie in self.cookies:
            if cookie.domain == "*":
                continue
            if not _domain_is_in_scope(cookie.domain, policy):
                raise SessionError(
                    f"session cookie {cookie.name!r} has domain "
                    f"{cookie.domain!r} which is not covered by any in-scope "
                    "pattern; refusing to bind to avoid credential leakage"
                )
        return self

    # -- per-host accessors ----------------------------------------------

    def cookies_for(self, host_or_url: str, policy: ScopePolicy) -> list[SessionCookie]:
        """Return cookies that should be sent to ``host``.

        Always returns ``[]`` when the host is not in the active
        :class:`ScopePolicy`, even if a cookie domain pattern would
        otherwise apply. This is the primary scope-safety guard.
        """
        host = normalize_host(host_or_url)
        if not host or not policy.is_in_scope(host):
            return []
        return [c for c in self.cookies if c.matches(host)]

    def headers_for(self, host_or_url: str, policy: ScopePolicy) -> dict[str, str]:
        """Return headers (global + host-specific) for ``host``.

        Always returns ``{}`` when the host is not in the active
        :class:`ScopePolicy`.
        """
        host = normalize_host(host_or_url)
        if not host or not policy.is_in_scope(host):
            return {}
        merged: dict[str, str] = dict(self.headers)
        for pattern, hh in self.host_headers.items():
            if host_matches(host, pattern):
                merged.update(hh)
        return merged


def _parse_cookies(raw: Any) -> tuple[SessionCookie, ...]:
    if not isinstance(raw, list):
        raise SessionError("cookies must be a list of mappings")
    out: list[SessionCookie] = []
    for entry in raw:
        if not isinstance(entry, dict):
            raise SessionError("each cookie entry must be a mapping")
        name = str(entry.get("name", "")).strip()
        value = str(entry.get("value", "")).strip()
        domain = str(entry.get("domain", "*")).strip().lower() or "*"
        path = str(entry.get("path", "/")).strip() or "/"
        if not name:
            raise SessionError("cookie.name is required")
        out.append(SessionCookie(name=name, value=value, domain=domain, path=path))
    return tuple(out)


def _parse_headers(raw: Any, *, field_name: str) -> dict[str, str]:
    if not isinstance(raw, dict):
        raise SessionError(f"{field_name} must be a mapping of name -> value")
    out: dict[str, str] = {}
    for k, v in raw.items():
        if not isinstance(k, str) or not k.strip():
            raise SessionError(f"{field_name} keys must be non-empty strings")
        if not isinstance(v, (str, int, float)):
            raise SessionError(
                f"{field_name}[{k}] must be a string, int, or float"
            )
        out[k.strip()] = str(v)
    return out


def _domain_is_in_scope(domain: str, policy: ScopePolicy) -> bool:
    """Return True if ``domain`` (a cookie pattern) overlaps with policy.in_scope.

    A wildcard pattern like ``*.example.com`` overlaps if any in-scope
    pattern targets ``example.com`` or a subdomain of it.
    """
    bare = domain[2:] if domain.startswith("*.") else domain
    for pat in policy.in_scope:
        if pat.startswith("*."):
            if bare == pat[2:] or bare.endswith("." + pat[2:]):
                return True
        else:
            if bare == pat or bare.endswith("." + pat):
                return True
    return False
