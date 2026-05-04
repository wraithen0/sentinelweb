from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from sentinelweb.scope.policy import (
    OutOfScopeError,
    ScopeError,
    ScopePolicy,
    example_yaml,
)


def _write(tmp_path: Path, contents: str) -> Path:
    p = tmp_path / "scope.yaml"
    p.write_text(contents)
    return p


def test_example_yaml_parses(tmp_path: Path) -> None:
    p = _write(tmp_path, example_yaml())
    policy = ScopePolicy.load(p)
    assert policy.engagement.program
    assert policy.in_scope


def test_missing_in_scope_rejected(tmp_path: Path) -> None:
    p = _write(
        tmp_path,
        textwrap.dedent(
            """
            engagement:
              program: x
              authorization: https://example.test
            in_scope: []
            """
        ),
    )
    with pytest.raises(ScopeError):
        ScopePolicy.load(p)


def test_missing_engagement_rejected(tmp_path: Path) -> None:
    p = _write(
        tmp_path,
        textwrap.dedent(
            """
            in_scope: ["example.test"]
            """
        ),
    )
    with pytest.raises(ScopeError):
        ScopePolicy.load(p)


def test_in_scope_matching(policy: ScopePolicy) -> None:
    assert policy.is_in_scope("example.test")
    assert policy.is_in_scope("api.example.test")
    assert policy.is_in_scope("https://api.example.test/foo?bar=1")
    assert not policy.is_in_scope("evil.test")
    # explicit out-of-scope wins
    assert not policy.is_in_scope("admin.example.test")


def test_assert_in_scope_raises(policy: ScopePolicy) -> None:
    with pytest.raises(OutOfScopeError):
        policy.assert_in_scope("admin.example.test")
    with pytest.raises(OutOfScopeError):
        policy.assert_in_scope("not-our-domain.test")


def test_rate_limit_validation(tmp_path: Path) -> None:
    p = _write(
        tmp_path,
        textwrap.dedent(
            """
            engagement:
              program: x
              authorization: y
            in_scope: ["example.test"]
            rate_per_sec: 9999
            """
        ),
    )
    with pytest.raises(ScopeError):
        ScopePolicy.load(p)


def test_filter_in_scope(policy: ScopePolicy) -> None:
    candidates = [
        "api.example.test",
        "evil.test",
        "admin.example.test",
        "example.test",
    ]
    assert policy.filter_in_scope(candidates) == ["api.example.test", "example.test"]


def test_wildcard_does_not_match_apex(policy: ScopePolicy) -> None:
    only_wild = ScopePolicy(
        in_scope=("*.example.test",),
        out_of_scope=(),
        rate_per_sec=2.0,
        max_concurrency=4,
        engagement=policy.engagement,
    )
    assert only_wild.is_in_scope("api.example.test")
    assert not only_wild.is_in_scope("example.test")
