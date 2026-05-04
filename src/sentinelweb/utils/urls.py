"""URL utilities."""

from __future__ import annotations

from urllib.parse import urlparse

import tldextract

_extract = tldextract.TLDExtract(suffix_list_urls=())


def normalize_host(value: str) -> str:
    """Return the bare hostname for a value that may be a URL or host."""
    host = urlparse(value).hostname or "" if "://" in value else value
    return host.strip().lower().rstrip("/")


def registered_domain(host: str) -> str:
    """Return registrable domain for a host (e.g. ``a.b.example.co.uk`` -> ``example.co.uk``).

    Uses the bundled public suffix list with no network fetch.
    """
    parsed = _extract(host)
    if parsed.suffix and parsed.domain:
        return f"{parsed.domain}.{parsed.suffix}"
    return host


def host_matches(host: str, pattern: str) -> bool:
    """Return True if ``host`` matches ``pattern``.

    Patterns:
        - ``example.com``  exact match
        - ``*.example.com`` matches any single-or-multi-label subdomain
          but NOT the apex ``example.com``
    """
    host = host.lower().strip()
    pattern = pattern.lower().strip()
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return host.endswith("." + suffix) and host != suffix
    return host == pattern
