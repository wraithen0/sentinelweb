"""Unit tests for the FirefoxVerifier wrapper.

These tests do NOT actually launch Firefox. They monkeypatch
``_import_selenium`` and ``shutil.which`` so the wrapper can be exercised
on any CI environment.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from sentinelweb.headless import firefox as firefox_module
from sentinelweb.headless.firefox import FirefoxVerifier, VerifierUnavailable
from sentinelweb.scope.policy import OutOfScopeError, ScopePolicy

# --------------------------------------------------------------------- is_available


def test_is_available_reports_missing_selenium(monkeypatch: pytest.MonkeyPatch) -> None:
    def _missing() -> Any:
        raise VerifierUnavailable("Selenium is not installed.")

    monkeypatch.setattr(firefox_module, "_import_selenium", _missing)

    ok, reason = FirefoxVerifier.is_available()
    assert not ok
    assert "Selenium" in reason


def test_is_available_reports_missing_firefox(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(firefox_module, "_import_selenium", lambda: (object, object))
    monkeypatch.setattr(firefox_module.shutil, "which", lambda name: None)

    ok, reason = FirefoxVerifier.is_available()
    assert not ok
    assert "Firefox" in reason


def test_is_available_reports_missing_geckodriver(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(firefox_module, "_import_selenium", lambda: (object, object))
    monkeypatch.setattr(
        firefox_module.shutil,
        "which",
        lambda name: "/usr/bin/firefox" if name == "firefox" else None,
    )

    ok, reason = FirefoxVerifier.is_available()
    assert not ok
    assert "geckodriver" in reason


def test_is_available_when_everything_present(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(firefox_module, "_import_selenium", lambda: (object, object))
    monkeypatch.setattr(firefox_module.shutil, "which", lambda name: f"/usr/bin/{name}")

    ok, reason = FirefoxVerifier.is_available()
    assert ok
    assert reason == ""


# --------------------------------------------------------------------- context manager


def test_context_manager_creates_and_quits_driver(
    policy: ScopePolicy, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_driver = MagicMock()
    fake_driver_class = MagicMock(return_value=fake_driver)
    fake_options_class = MagicMock()

    monkeypatch.setattr(
        firefox_module,
        "_import_selenium",
        lambda: (fake_driver_class, fake_options_class),
    )

    with FirefoxVerifier(scope=policy) as v:
        assert v._driver is fake_driver
        fake_driver_class.assert_called_once()
        fake_driver.set_page_load_timeout.assert_called_once()

    fake_driver.quit.assert_called_once()


def test_context_manager_raises_when_firefox_fails_to_start(
    policy: ScopePolicy, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("firefox not found")

    fake_driver_class = MagicMock(side_effect=boom)
    fake_options_class = MagicMock()
    monkeypatch.setattr(
        firefox_module,
        "_import_selenium",
        lambda: (fake_driver_class, fake_options_class),
    )

    with pytest.raises(VerifierUnavailable, match="Failed to start Firefox"):
        FirefoxVerifier(scope=policy).__enter__()


# --------------------------------------------------------------------- verify_title_change


def test_verify_title_change_returns_true_when_marker_appears(
    policy: ScopePolicy, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_driver = MagicMock()
    fake_driver.title = "SW_XSS_abc123 the rest"
    # Make switch_to.alert raise so dismiss is a no-op.
    fake_driver.switch_to.alert = MagicMock(
        side_effect=Exception("no alert present")
    )

    monkeypatch.setattr(
        firefox_module,
        "_import_selenium",
        lambda: (MagicMock(return_value=fake_driver), MagicMock()),
    )

    with FirefoxVerifier(scope=policy, timeout=0.5) as v:
        out = v.verify_title_change("https://example.test/?q=foo", "abc123")

    assert out is True
    fake_driver.get.assert_called_once_with("https://example.test/?q=foo")


def test_verify_title_change_returns_false_on_timeout(
    policy: ScopePolicy, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_driver = MagicMock()
    fake_driver.title = "boring page"

    monkeypatch.setattr(
        firefox_module,
        "_import_selenium",
        lambda: (MagicMock(return_value=fake_driver), MagicMock()),
    )

    with FirefoxVerifier(scope=policy, timeout=0.2) as v:
        out = v.verify_title_change("https://example.test/?q=foo", "abc123")

    assert out is False


def test_verify_title_change_refuses_out_of_scope(
    policy: ScopePolicy, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_driver = MagicMock()
    monkeypatch.setattr(
        firefox_module,
        "_import_selenium",
        lambda: (MagicMock(return_value=fake_driver), MagicMock()),
    )

    with FirefoxVerifier(scope=policy) as v, pytest.raises(OutOfScopeError):
        v.verify_title_change("https://admin.example.test/?q=foo", "abc")

    # Crucially: driver.get was never called for the out-of-scope URL.
    fake_driver.get.assert_not_called()


def test_verify_title_change_swallows_get_exceptions(
    policy: ScopePolicy, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_driver = MagicMock()
    fake_driver.get.side_effect = RuntimeError("page load failed")

    monkeypatch.setattr(
        firefox_module,
        "_import_selenium",
        lambda: (MagicMock(return_value=fake_driver), MagicMock()),
    )

    with FirefoxVerifier(scope=policy) as v:
        out = v.verify_title_change("https://example.test/?q=foo", "abc")

    assert out is False


def test_verify_without_entering_context_raises(policy: ScopePolicy) -> None:
    v = FirefoxVerifier(scope=policy)
    with pytest.raises(VerifierUnavailable):
        v.verify_title_change("https://example.test/", "abc")
