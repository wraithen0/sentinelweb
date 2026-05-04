"""Headless-browser verification of reflected-XSS findings.

This subpackage upgrades the static XSS detector with an optional
headless re-check: open the parameter-mutated URL in headless Firefox
(via Selenium + system ``geckodriver``) with a benign payload that
sets ``document.title`` to a unique nonce. If the title actually
changes, the parameter executes attacker-controlled HTML and the
finding is promoted from "candidate" to "verified".

Selenium is an optional dependency. Install via:

.. code-block:: bash

    pip install -e ".[headless]"
    sudo dnf install firefox geckodriver  # or apt equivalents

When the dependency is missing, :func:`FirefoxVerifier.is_available`
returns a clear reason string and the CLI falls back to skipping
verification rather than crashing.

Safety properties of the verification payload:

* No ``fetch``, ``XMLHttpRequest``, ``WebSocket``, ``localStorage``,
  or form submission — the only side effect is setting
  ``document.title`` to a per-finding nonce.
* No navigation to anywhere other than the original target host.
* Every URL is scope-checked before a single byte is loaded.
* The browser is created per-finding and torn down immediately.
"""

from __future__ import annotations

from .firefox import FirefoxVerifier, VerifierUnavailable
from .verify_xss import verify_xss_findings

__all__ = ["FirefoxVerifier", "VerifierUnavailable", "verify_xss_findings"]
