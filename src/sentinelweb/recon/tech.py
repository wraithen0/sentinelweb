"""Tech-stack fingerprint via response headers + body signatures.

Lightweight pattern-matching only — no Wappalyzer-style enormous DB.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..scope.policy import ScopePolicy
from ..utils.http import Client


@dataclass(frozen=True)
class Tech:
    name: str
    where: str  # 'header' | 'body' | 'cookie'
    detail: str = ""


HEADER_SIGS: tuple[tuple[str, str, str], ...] = (
    ("server", r"nginx", "nginx"),
    ("server", r"apache", "Apache HTTPD"),
    ("server", r"iis", "Microsoft IIS"),
    ("server", r"cloudflare", "Cloudflare"),
    ("x-powered-by", r"php", "PHP"),
    ("x-powered-by", r"express", "Express.js"),
    ("x-powered-by", r"asp\.net", "ASP.NET"),
    ("x-aspnet-version", r".+", "ASP.NET (version exposed)"),
    ("x-amz-cf-id", r".+", "Amazon CloudFront"),
    ("via", r"varnish", "Varnish"),
)

BODY_SIGS: tuple[tuple[str, str], ...] = (
    (r"<meta name=\"generator\" content=\"WordPress", "WordPress"),
    (r"window\.__NUXT__", "Nuxt.js"),
    (r"__NEXT_DATA__", "Next.js"),
    (r"data-reactroot", "React"),
    (r"ng-app=\"|ng-controller=\"", "AngularJS"),
    (r"<svelte", "Svelte"),
    (r"static/runtime/", "webpack"),
    (r"jquery-\d", "jQuery"),
)

COOKIE_SIGS: tuple[tuple[str, str], ...] = (
    (r"PHPSESSID", "PHP"),
    (r"JSESSIONID", "Java servlet container"),
    (r"ASP\.NET_SessionId", "ASP.NET"),
    (r"laravel_session", "Laravel"),
    (r"connect\.sid", "Express.js (express-session)"),
)


async def fingerprint(url: str, scope: ScopePolicy, client: Client) -> list[Tech]:
    scope.assert_in_scope(url)
    resp = await client.get(url)
    out: list[Tech] = []

    headers_lc = {k.lower(): v for k, v in resp.headers.items()}
    for hdr, pattern, name in HEADER_SIGS:
        v = headers_lc.get(hdr, "")
        if v and re.search(pattern, v, re.I):
            out.append(Tech(name=name, where="header", detail=f"{hdr}: {v}"))

    body = resp.text or ""
    for pattern, name in BODY_SIGS:
        if re.search(pattern, body, re.I):
            out.append(Tech(name=name, where="body"))

    cookies = headers_lc.get("set-cookie", "")
    for pattern, name in COOKIE_SIGS:
        if re.search(pattern, cookies, re.I):
            out.append(Tech(name=name, where="cookie"))

    # de-dupe by (name, where)
    seen: set[tuple[str, str]] = set()
    deduped: list[Tech] = []
    for t in out:
        key = (t.name, t.where)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(t)
    return deduped
