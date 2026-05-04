"""Passive subdomain enumeration via crt.sh + optional brute force.

Passive sources only by default — no aggressive scanning unless the
operator explicitly opts in with a wordlist.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterable

import dns.asyncresolver
import dns.resolver

from ..scope.policy import ScopePolicy
from ..utils.http import Client
from ..utils.logging import get_logger
from ..utils.urls import host_matches, normalize_host

log = get_logger(__name__)

CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"


async def from_crtsh(domain: str, client: Client) -> list[str]:
    """Query crt.sh for certificate-transparency-derived subdomains."""
    url = CRTSH_URL.format(domain=domain)
    try:
        resp = await client.get(url)
    except Exception as exc:
        log.warning("crt.sh request failed: %s", exc)
        return []
    if resp.status_code != 200:
        log.warning("crt.sh returned %s", resp.status_code)
        return []
    try:
        data = resp.json()
    except json.JSONDecodeError:
        return []

    out: set[str] = set()
    for row in data:
        name = row.get("name_value", "")
        for line in str(name).split("\n"):
            line = line.strip().lower().lstrip("*.")
            if line and "." in line:
                out.add(line)
    return sorted(out)


async def resolve(host: str) -> bool:
    """Return True if ``host`` resolves to anything."""
    try:
        await dns.asyncresolver.resolve(host, "A")
        return True
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
    ):
        return False


async def brute_force(
    domain: str,
    wordlist: Iterable[str],
    *,
    concurrency: int = 16,
) -> list[str]:
    """Resolve ``<word>.<domain>`` for each word in the list."""
    sem = asyncio.Semaphore(concurrency)
    results: list[str] = []

    async def check(word: str) -> None:
        host = f"{word.strip()}.{domain}".lower()
        async with sem:
            if await resolve(host):
                results.append(host)

    await asyncio.gather(*(check(w) for w in wordlist if w.strip()))
    return sorted(set(results))


async def enumerate(
    domain: str,
    scope: ScopePolicy,
    client: Client,
    *,
    wordlist: Iterable[str] | None = None,
) -> list[str]:
    """Return all in-scope subdomains discovered for ``domain``."""
    domain = normalize_host(domain)
    candidates: set[str] = set()
    candidates.update(await from_crtsh(domain, client))
    if wordlist is not None:
        candidates.update(await brute_force(domain, wordlist))
    in_scope: list[str] = []
    for c in sorted(candidates):
        if any(host_matches(c, p) for p in scope.in_scope) and not any(
            host_matches(c, p) for p in scope.out_of_scope
        ):
            in_scope.append(c)
    return in_scope
