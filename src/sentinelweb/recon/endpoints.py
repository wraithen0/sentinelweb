"""Endpoint and parameter discovery from HTML / JS.

Extracts:
  - ``href`` / ``src`` URLs from HTML
  - ``<form action=...>`` targets and their input names
  - URL strings from inline / external JS files (heuristic regex)
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from ..scope.policy import ScopePolicy
from ..utils.http import Client

URL_REGEX = re.compile(
    r"""(?P<url>(?:https?:)?//[^\s"'`<>]+|/[A-Za-z0-9_\-./?=&%]+)""",
    re.VERBOSE,
)


async def discover(url: str, scope: ScopePolicy, client: Client) -> dict[str, list[str]]:
    """Return a mapping with keys ``urls``, ``forms``, ``params``."""
    scope.assert_in_scope(url)
    resp = await client.get(url)
    body = resp.text or ""
    soup = BeautifulSoup(body, "html.parser")

    urls: set[str] = set()
    for tag, attr in (
        ("a", "href"),
        ("link", "href"),
        ("script", "src"),
        ("img", "src"),
        ("iframe", "src"),
        ("form", "action"),
    ):
        for el in soup.find_all(tag):
            v = el.get(attr)
            if isinstance(v, str) and v.strip():
                urls.add(urljoin(url, v.strip()))

    forms: list[str] = []
    params: set[str] = set()
    for form in soup.find_all("form"):
        action = form.get("action") or ""
        if isinstance(action, str):
            forms.append(urljoin(url, action))
        for inp in form.find_all(("input", "textarea", "select")):
            name = inp.get("name")
            if isinstance(name, str) and name.strip():
                params.add(name.strip())

    # heuristic: URLs in inline scripts
    for script in soup.find_all("script"):
        if not script.string:
            continue
        for m in URL_REGEX.finditer(str(script.string)):
            cand = m.group("url")
            urls.add(urljoin(url, cand))

    base_host = urlparse(url).hostname or ""
    in_scope_urls = []
    for u in sorted(urls):
        host = urlparse(u).hostname or base_host
        if scope.is_in_scope(host):
            in_scope_urls.append(u)

    in_scope_forms = [f for f in forms if scope.is_in_scope(urlparse(f).hostname or base_host)]

    return {
        "urls": in_scope_urls,
        "forms": in_scope_forms,
        "params": sorted(params),
    }
