"""Shared pytest fixtures."""

from __future__ import annotations

import pytest

from sentinelweb.scope.policy import Engagement, ScopePolicy


@pytest.fixture
def policy() -> ScopePolicy:
    return ScopePolicy(
        in_scope=("*.example.test", "example.test"),
        out_of_scope=("admin.example.test",),
        rate_per_sec=10.0,
        max_concurrency=2,
        engagement=Engagement(
            program="test-program",
            authorization="https://example.test/program",
            contact="sec@example.test",
        ),
    )
