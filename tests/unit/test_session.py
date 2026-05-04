"""Tests for :mod:`sentinelweb.scope.session`.

These cover:

* YAML/JSON loading shape errors
* Per-host cookie/header selection
* The scope-binding guard that prevents credentials leaking to
  out-of-scope hosts even when a cookie domain pattern would match.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from sentinelweb.scope.policy import Engagement, ScopePolicy
from sentinelweb.scope.session import Session, SessionCookie, SessionError


def _policy(in_scope: tuple[str, ...] = ("example.test", "*.example.test")) -> ScopePolicy:
    return ScopePolicy(
        in_scope=in_scope,
        out_of_scope=("admin.example.test",),
        rate_per_sec=10.0,
        max_concurrency=2,
        engagement=Engagement(
            program="t", authorization="a", contact="c@example.test"
        ),
    )


def test_session_from_yaml_file(tmp_path: Path) -> None:
    p = tmp_path / "session.yaml"
    p.write_text(
        """
cookies:
  - name: token
    value: abc123
    domain: example.test
headers:
  Authorization: Bearer xyz
""",
        encoding="utf-8",
    )
    sess = Session.load(p)
    assert sess.cookies == (
        SessionCookie(name="token", value="abc123", domain="example.test", path="/"),
    )
    assert sess.headers == {"Authorization": "Bearer xyz"}


def test_session_from_json_file(tmp_path: Path) -> None:
    p = tmp_path / "session.json"
    p.write_text(
        json.dumps(
            {
                "cookies": [{"name": "sid", "value": "42"}],
                "headers": {"X-Test": "1"},
            }
        ),
        encoding="utf-8",
    )
    sess = Session.load(p)
    assert sess.cookies[0].name == "sid"
    assert sess.headers == {"X-Test": "1"}


def test_session_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(SessionError, match="not found"):
        Session.load(tmp_path / "missing.yaml")


def test_session_invalid_shape_raises(tmp_path: Path) -> None:
    p = tmp_path / "bad.yaml"
    p.write_text("- just a list\n", encoding="utf-8")
    with pytest.raises(SessionError, match="mapping"):
        Session.load(p)


def test_session_cookie_without_name_raises() -> None:
    with pytest.raises(SessionError, match=r"cookie\.name"):
        Session.from_dict({"cookies": [{"value": "v"}]})


def test_cookies_for_returns_only_matching_in_scope() -> None:
    sess = Session(
        cookies=(
            SessionCookie(name="a", value="1", domain="example.test"),
            SessionCookie(name="b", value="2", domain="other.test"),
            SessionCookie(name="c", value="3", domain="*"),
        )
    )
    cookies = sess.cookies_for("https://example.test/", _policy())
    names = {c.name for c in cookies}
    assert names == {"a", "c"}, "only matching + wildcard cookies should be sent"


def test_cookies_for_out_of_scope_returns_empty() -> None:
    """Even if a cookie's domain matches, refuse to send it out of scope."""
    sess = Session(
        cookies=(SessionCookie(name="a", value="1", domain="*"),)
    )
    cookies = sess.cookies_for("https://attacker.test/", _policy())
    assert cookies == [], "cookies must NEVER be sent to out-of-scope hosts"


def test_cookies_for_explicitly_out_of_scope_returns_empty() -> None:
    """A host that matches in_scope but is also in out_of_scope is denied."""
    sess = Session(cookies=(SessionCookie(name="a", value="1", domain="*"),))
    cookies = sess.cookies_for("https://admin.example.test/", _policy())
    assert cookies == []


def test_headers_for_merges_global_and_host_headers() -> None:
    sess = Session(
        headers={"X-Global": "g"},
        host_headers={"api.example.test": {"X-Specific": "s"}},
    )
    h = sess.headers_for("https://api.example.test/", _policy())
    assert h == {"X-Global": "g", "X-Specific": "s"}


def test_headers_for_out_of_scope_returns_empty() -> None:
    sess = Session(headers={"Authorization": "Bearer x"})
    assert sess.headers_for("https://attacker.test/", _policy()) == {}


def test_bind_rejects_cookie_domain_outside_scope() -> None:
    """Cookies with a domain that no in-scope pattern could match must
    be refused at bind time so they cannot leak to unrelated hosts."""
    sess = Session(
        cookies=(SessionCookie(name="a", value="1", domain="other.test"),)
    )
    with pytest.raises(SessionError, match="not covered"):
        sess.bind(_policy())


def test_bind_accepts_wildcard_cookie() -> None:
    """A wildcard ``domain="*"`` cookie is allowed because the per-host
    scope check at send time will still gate it."""
    sess = Session(cookies=(SessionCookie(name="a", value="1", domain="*"),))
    assert sess.bind(_policy()) is sess


def test_bind_accepts_subdomain_of_in_scope_pattern() -> None:
    sess = Session(
        cookies=(SessionCookie(name="a", value="1", domain="api.example.test"),)
    )
    assert sess.bind(_policy(in_scope=("*.example.test",))) is sess


# -- Client integration ------------------------------------------------------


@pytest.mark.asyncio
async def test_client_attaches_session_to_in_scope_request() -> None:
    """Client must inject session cookies + headers on in-scope requests."""
    import respx
    from httpx import Response

    from sentinelweb.utils.http import make_client

    sess = Session(
        cookies=(SessionCookie(name="token", value="abc", domain="example.test"),),
        headers={"Authorization": "Bearer xyz"},
    )

    captured: dict[str, str] = {}

    def handler(request: Any) -> Response:
        captured["cookie"] = request.headers.get("cookie", "")
        captured["authorization"] = request.headers.get("authorization", "")
        return Response(200, text="ok")

    with respx.mock:
        respx.get("https://example.test/").mock(side_effect=handler)
        async with make_client(
            rate_per_sec=100, session=sess, policy=_policy()
        ) as client:
            await client.get("https://example.test/")

    assert "token=abc" in captured["cookie"]
    assert captured["authorization"] == "Bearer xyz"


@pytest.mark.asyncio
async def test_client_does_not_leak_session_to_out_of_scope_host() -> None:
    """Even if respx routes the request, the session must not be attached
    when the host is not in policy.in_scope."""
    import respx
    from httpx import Response

    from sentinelweb.utils.http import make_client

    sess = Session(
        cookies=(SessionCookie(name="token", value="abc", domain="*"),),
        headers={"Authorization": "Bearer xyz"},
    )

    captured: dict[str, str] = {}

    def handler(request: Any) -> Response:
        captured["cookie"] = request.headers.get("cookie", "")
        captured["authorization"] = request.headers.get("authorization", "")
        return Response(200, text="ok")

    with respx.mock:
        respx.get("https://attacker.test/").mock(side_effect=handler)
        async with make_client(
            rate_per_sec=100, session=sess, policy=_policy()
        ) as client:
            await client.get("https://attacker.test/")

    assert captured["cookie"] == "", "no cookies should leak to out-of-scope host"
    assert captured["authorization"] == "", "no auth header should leak"


@pytest.mark.asyncio
async def test_client_caller_supplied_headers_win_over_session() -> None:
    """If a scanner supplies an Authorization header on a single request,
    the session header must NOT clobber it (case-insensitive merge)."""
    import respx
    from httpx import Response

    from sentinelweb.utils.http import make_client

    sess = Session(headers={"Authorization": "Bearer SESSION"})

    captured: dict[str, str] = {}

    def handler(request: Any) -> Response:
        captured["authorization"] = request.headers.get("authorization", "")
        return Response(200, text="ok")

    with respx.mock:
        respx.get("https://example.test/").mock(side_effect=handler)
        async with make_client(
            rate_per_sec=100, session=sess, policy=_policy()
        ) as client:
            await client.get(
                "https://example.test/",
                headers={"Authorization": "Bearer CALLER"},
            )

    assert captured["authorization"] == "Bearer CALLER"
