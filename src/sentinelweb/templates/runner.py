"""Async template runner.

Given a list of :class:`Template` and a list of target URLs, runs each
template's HTTP requests through the rate-limited, scope-enforcing
:class:`~sentinelweb.utils.http.Client` and emits :class:`Finding`
objects for every matched template.

Safety properties:

* Every request goes through :class:`Client`, which calls
  ``policy.is_in_scope(host)`` before any traffic. Templates cannot
  bypass the scope check.
* Requests use paths relative to the target URL — there is no way for a
  template to redirect traffic to another host.
* Methods are restricted by the schema to ``GET / HEAD / POST /
  OPTIONS``, so templates cannot trigger destructive verbs.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from urllib.parse import urljoin, urlparse

from ..reporting.findings import Confidence, Evidence, Finding
from ..scope.policy import OutOfScopeError, ScopePolicy
from ..utils.http import Client
from .schema import (
    HttpRequest,
    Matcher,
    RegexMatcher,
    StatusMatcher,
    Template,
    WordMatcher,
)

_EXCERPT_LIMIT = 800


def _build_target_url(target: str, path: str) -> str:
    """Join ``target`` with ``path``.

    Behaves like :func:`urllib.parse.urljoin` with two additional safety
    properties:

    * Adds a default ``http://`` scheme when ``target`` is a bare host so
      the join works deterministically.
    * Refuses to return a URL whose host differs from ``target``'s host.
      The schema already rejects absolute URLs and protocol-relative
      paths; this is defense-in-depth in case a future schema relaxation
      lets one slip through.
    """
    if "://" not in target:
        base = "http://" + target.strip("/") + "/"
    elif target.endswith("/"):
        base = target
    else:
        base = target + "/"
    candidate = urljoin(base, path)
    base_host = urlparse(base).hostname
    cand_host = urlparse(candidate).hostname
    if base_host != cand_host:
        raise ValueError(
            f"path {path!r} resolved to a different host "
            f"({cand_host!r}) than the target ({base_host!r}); refusing"
        )
    return candidate


def _eval_status(matcher: StatusMatcher, status_code: int) -> bool:
    matched = status_code in matcher.status
    return matched != matcher.negative


def _haystack_for_part(
    part: str, body: str, headers_text: str
) -> str:
    if part == "header":
        return headers_text
    if part == "response":
        return f"{headers_text}\n\n{body}"
    return body


def _eval_words(matcher: WordMatcher, body: str, headers_text: str) -> bool:
    haystack = _haystack_for_part(matcher.part, body, headers_text)
    if matcher.case_insensitive:
        haystack_cmp = haystack.lower()
        words = [w.lower() for w in matcher.words]
    else:
        haystack_cmp = haystack
        words = list(matcher.words)
    hits = [w in haystack_cmp for w in words]
    matched = all(hits) if matcher.condition == "and" else any(hits)
    return matched != matcher.negative


def _eval_regex(matcher: RegexMatcher, body: str, headers_text: str) -> bool:
    haystack = _haystack_for_part(matcher.part, body, headers_text)
    # MULTILINE so `^` / `$` anchor to line boundaries, matching the nuclei
    # convention. DOTALL is deliberately NOT enabled — `.` not crossing newlines
    # makes templates more predictable.
    hits = [
        re.search(p, haystack, re.MULTILINE) is not None for p in matcher.regex
    ]
    matched = all(hits) if matcher.condition == "and" else any(hits)
    return matched != matcher.negative


def _eval_matcher(
    matcher: Matcher, status_code: int, body: str, headers_text: str
) -> bool:
    if isinstance(matcher, StatusMatcher):
        return _eval_status(matcher, status_code)
    if isinstance(matcher, WordMatcher):
        return _eval_words(matcher, body, headers_text)
    if isinstance(matcher, RegexMatcher):
        return _eval_regex(matcher, body, headers_text)
    raise TypeError(f"unknown matcher type: {type(matcher)!r}")  # pragma: no cover


def _format_headers(headers: Iterable[tuple[str, str]]) -> str:
    return "\n".join(f"{k}: {v}" for k, v in headers)


def _excerpt(text: str) -> str:
    if len(text) <= _EXCERPT_LIMIT:
        return text
    return text[:_EXCERPT_LIMIT] + "...[truncated]"


def _build_finding(
    template: Template,
    request: HttpRequest,
    full_url: str,
    status_code: int,
    body: str,
    headers_text: str,
    fired_matchers: list[Matcher],
) -> Finding:
    info = template.info
    fired_summary = ", ".join(m.type for m in fired_matchers)
    return Finding(
        id=template.finding_id,
        title=info.name,
        severity=info.severity,
        confidence=Confidence.FIRM,
        target=full_url,
        category=info.category,
        cwe=info.cwe,
        description=(
            f"{info.description.strip()}\n\n"
            f"Template `{template.id}` matched on {request.method} {full_url} "
            f"(matchers: {fired_summary})."
        ).strip(),
        remediation=info.remediation,
        references=list(info.references),
        detected_by=f"templates.{template.id}",
        tags=list(info.tags),
        evidence=[
            Evidence(
                description=f"{request.method} {full_url}",
                response_excerpt=_excerpt(
                    f"HTTP {status_code}\n{headers_text}\n\n{body}"
                ),
            )
        ],
    )


async def _run_request(
    template: Template,
    request: HttpRequest,
    target: str,
    scope: ScopePolicy,
    client: Client,
) -> list[Finding]:
    out: list[Finding] = []
    for path in request.path:
        try:
            url = _build_target_url(target, path)
        except ValueError:
            continue
        # Defensive: even though Client also scope-checks, fail fast if the
        # built URL is somehow out of scope (e.g. exotic redirect-style path).
        if not scope.is_in_scope(url):
            continue
        try:
            response = await client.request(
                request.method,
                url,
                headers=dict(request.headers) if request.headers else None,
                content=request.body,
            )
        except OutOfScopeError:
            continue
        except Exception:
            # Network errors are not template hits; keep going.
            continue
        body = response.text or ""
        headers_text = _format_headers(response.headers.items())
        results = [
            _eval_matcher(m, response.status_code, body, headers_text)
            for m in request.matchers
        ]
        fired = all(results) if request.matchers_condition == "and" else any(results)
        if fired:
            fired_matchers = [
                m for m, r in zip(request.matchers, results, strict=True) if r
            ]
            out.append(
                _build_finding(
                    template,
                    request,
                    url,
                    response.status_code,
                    body,
                    headers_text,
                    fired_matchers,
                )
            )
    return out


async def run_template(
    template: Template,
    target: str,
    scope: ScopePolicy,
    client: Client,
) -> list[Finding]:
    """Run a single template against one target URL."""
    findings: list[Finding] = []
    for request in template.requests:
        findings.extend(await _run_request(template, request, target, scope, client))
    return findings


async def run_templates_against(
    templates: Iterable[Template],
    targets: Iterable[str],
    scope: ScopePolicy,
    client: Client,
) -> list[Finding]:
    """Run every template against every target."""
    out: list[Finding] = []
    for target in targets:
        # Outer scope check; per-request check still happens via Client.
        if not scope.is_in_scope(target):
            raise OutOfScopeError(
                f"target {target!r} is not allowed by scope; refusing to run templates"
            )
        for tpl in templates:
            out.extend(await run_template(tpl, target, scope, client))
    return out
