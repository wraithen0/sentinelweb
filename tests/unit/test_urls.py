from __future__ import annotations

from sentinelweb.utils.urls import host_matches, normalize_host, registered_domain


def test_normalize_host() -> None:
    assert normalize_host("https://API.Example.Test/foo") == "api.example.test"
    assert normalize_host("api.example.test") == "api.example.test"
    assert normalize_host("") == ""


def test_host_matches_exact() -> None:
    assert host_matches("api.example.test", "api.example.test")
    assert not host_matches("api.example.test", "other.example.test")


def test_host_matches_wildcard() -> None:
    assert host_matches("api.example.test", "*.example.test")
    assert host_matches("a.b.c.example.test", "*.example.test")
    # Apex does NOT match wildcard.
    assert not host_matches("example.test", "*.example.test")


def test_registered_domain() -> None:
    assert registered_domain("a.b.example.com") == "example.com"
    assert registered_domain("example.com") == "example.com"
