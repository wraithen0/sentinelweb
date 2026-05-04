"""Selenium + Firefox/geckodriver verifier (Fedora-friendly).

The class :class:`FirefoxVerifier` is a minimal wrapper around the
Selenium ``Firefox`` driver. Its only job is to decide whether a given
URL fires a ``<svg/onload>`` payload that sets ``document.title`` to a
per-call nonce. Anything more elaborate would expand the attack surface
of the framework's verifier and is intentionally out of scope.

Selenium is imported lazily so the rest of SentinelWeb keeps working
when the ``[headless]`` extra is not installed.
"""

from __future__ import annotations

import logging
import shutil
import time
from contextlib import AbstractContextManager
from types import TracebackType
from typing import TYPE_CHECKING

from ..scope.policy import ScopePolicy

if TYPE_CHECKING:  # pragma: no cover - import only for type checkers
    from selenium.webdriver import Firefox

log = logging.getLogger(__name__)


class VerifierUnavailable(RuntimeError):
    """Raised when the verifier cannot run in this environment.

    The user should see a clear message rather than an obscure stack
    trace if Selenium is missing or Firefox / geckodriver isn't on
    ``PATH``.
    """


def _import_selenium() -> tuple[type, type]:
    """Lazy-import Selenium; return ``(Firefox, FirefoxOptions)``.

    Raises :class:`VerifierUnavailable` if the package isn't installed.
    """
    try:
        from selenium.webdriver import Firefox
        from selenium.webdriver.firefox.options import Options as FirefoxOptions
    except ImportError as exc:  # pragma: no cover - covered indirectly
        raise VerifierUnavailable(
            "Selenium is not installed. Install the optional extra with "
            'pip install -e ".[headless]" and retry.'
        ) from exc
    return Firefox, FirefoxOptions


class FirefoxVerifier(AbstractContextManager["FirefoxVerifier"]):
    """Headless Firefox driver wrapper for one-shot XSS verification.

    Use as a context manager so the browser is always torn down:

    .. code-block:: python

        with FirefoxVerifier(scope=policy) as v:
            confirmed = v.verify_title_change(probe_url, nonce)
    """

    def __init__(
        self,
        scope: ScopePolicy,
        *,
        timeout: float = 5.0,
        page_load_timeout: float = 10.0,
    ) -> None:
        self._scope = scope
        self._timeout = timeout
        self._page_load_timeout = page_load_timeout
        self._driver: Firefox | None = None

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def is_available() -> tuple[bool, str]:
        """Return ``(ok, reason)`` describing whether verification can run.

        Checks for both the Selenium import and the ``firefox`` /
        ``geckodriver`` binaries on ``PATH``.
        """
        try:
            _import_selenium()
        except VerifierUnavailable as exc:
            return False, str(exc)
        if shutil.which("firefox") is None and shutil.which("firefox-bin") is None:
            return False, (
                "Firefox binary not found on PATH. On Fedora install with "
                "`sudo dnf install firefox`."
            )
        if shutil.which("geckodriver") is None:
            return False, (
                "geckodriver binary not found on PATH. On Fedora install "
                "with `sudo dnf install geckodriver`."
            )
        return True, ""

    # ------------------------------------------------------------------ lifecycle

    def __enter__(self) -> FirefoxVerifier:
        Firefox, FirefoxOptions = _import_selenium()
        opts = FirefoxOptions()
        # Headless + a tiny window keep memory low when called per-finding.
        opts.add_argument("-headless")
        opts.add_argument("--width=320")
        opts.add_argument("--height=240")
        # Disable network features we don't need so a malicious page can't
        # try to phone home through the verifier process.
        opts.set_preference("network.http.use-cache", False)
        opts.set_preference("dom.webnotifications.enabled", False)
        opts.set_preference("media.autoplay.default", 5)
        try:
            self._driver = Firefox(options=opts)
        except Exception as exc:  # pragma: no cover - depends on local Firefox
            raise VerifierUnavailable(
                f"Failed to start Firefox: {exc}. Make sure firefox + "
                "geckodriver are installed and runnable."
            ) from exc
        self._driver.set_page_load_timeout(self._page_load_timeout)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._driver is not None:
            try:
                self._driver.quit()
            except Exception:
                # We never want a teardown error to mask a real failure.
                log.debug("driver.quit() failed", exc_info=True)
            self._driver = None

    # ------------------------------------------------------------------ verify

    def verify_title_change(self, url: str, nonce: str) -> bool:
        """Open ``url`` and check whether the page title contains ``nonce``.

        The caller is responsible for embedding the verification payload
        (e.g. ``<svg/onload=document.title='SW_XSS_<NONCE>'>``) into the
        URL via the parameter the XSS scanner flagged.

        Scope is re-checked before navigation: even if a buggy caller
        passes an out-of-scope URL, the browser will refuse it.
        """
        if self._driver is None:
            raise VerifierUnavailable(
                "FirefoxVerifier was not entered as a context manager"
            )
        self._scope.assert_in_scope(url)

        marker = f"SW_XSS_{nonce}"
        try:
            self._driver.get(url)
        except Exception:
            log.debug("driver.get(%r) raised", url, exc_info=True)
            return False

        # Auto-dismiss any payload-triggered alert so we can read .title.
        self._dismiss_alert_if_present()

        deadline = time.monotonic() + self._timeout
        while time.monotonic() < deadline:
            try:
                title = self._driver.title or ""
            except Exception:
                log.debug("driver.title raised", exc_info=True)
                return False
            if marker in title:
                return True
            self._dismiss_alert_if_present()
            time.sleep(0.1)
        return False

    def _dismiss_alert_if_present(self) -> None:
        if self._driver is None:  # pragma: no cover - guarded by callers
            return
        try:
            alert = self._driver.switch_to.alert
        except Exception:
            return
        try:
            alert.dismiss()
        except Exception:
            log.debug("alert.dismiss() failed", exc_info=True)
