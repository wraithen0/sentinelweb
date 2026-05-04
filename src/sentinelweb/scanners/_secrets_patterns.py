"""Curated, high-precision secret patterns for the secrets scanner.

Design goals
------------
- **High precision over recall.** A noisy secrets scanner trains people to
  ignore findings. Each pattern here is deliberately tight (provider-prefixed,
  fixed-length, charset-bounded) so that a positive match almost always means
  a real secret, not a false alarm.
- **Provider-specific only.** We do *not* ship generic ``api_key = "..."``
  heuristics — those have well-documented FP rates >70% in public studies and
  belong behind a separate ``--aggressive`` flag (out of scope here).
- **Safe by construction.** Findings carry a *redacted* fingerprint of the
  secret (first 4 + last 4 chars of the matched value, with the middle
  replaced by ``***``); the full secret is never written to logs or reports.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from re import Pattern

from ..reporting.findings import Confidence, Severity


@dataclass(frozen=True)
class SecretPattern:
    """Definition of a single secret-detection rule."""

    id: str
    """Stable slug. Becomes ``SECRETS-<ID>`` in the finding id."""
    name: str
    """Human-readable provider/family name."""
    regex: Pattern[str]
    """Compiled regex. Must match exactly the raw secret value (group 0)."""
    severity: Severity
    confidence: Confidence
    cwe: str = "798"  # CWE-798: Use of Hard-coded Credentials
    publishable: bool = False
    """When True, the matched key class is *intentionally* public-facing
    (e.g. Stripe ``pk_live_*``). We still emit a finding, but at INFO."""
    description: str = ""
    """One-sentence explanation appended to the finding description."""
    references: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# Pattern catalog
#
# Where prefixes and lengths come from the provider's own documentation,
# we cite the doc URL in ``references``. Where they come from public
# disclosures (e.g. truffleHog, gitleaks rule corpora), we cite the source.
# ---------------------------------------------------------------------------


_PATTERNS: tuple[SecretPattern, ...] = (
    # ---- AWS ----------------------------------------------------------------
    SecretPattern(
        id="AWS-ACCESS-KEY-ID",
        name="AWS Access Key ID",
        regex=re.compile(r"\b(?:AKIA|ASIA|AGPA|AROA|AIDA|ANPA|ANVA|AIPA)[0-9A-Z]{16}\b"),
        severity=Severity.HIGH,
        confidence=Confidence.FIRM,
        description=(
            "AWS Access Key ID present in the response. The key prefix encodes "
            "the principal type (AKIA=long-term user, ASIA=temporary STS, etc.)."
        ),
        references=(
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html",
        ),
    ),
    # ---- GitHub -------------------------------------------------------------
    SecretPattern(
        id="GITHUB-PAT-CLASSIC",
        name="GitHub classic personal access token",
        regex=re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
        severity=Severity.HIGH,
        confidence=Confidence.CERTAIN,
        description="Classic GitHub personal access token (ghp_ prefix).",
        references=(
            "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens",
        ),
    ),
    SecretPattern(
        id="GITHUB-PAT-FINE-GRAINED",
        name="GitHub fine-grained personal access token",
        regex=re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b"),
        severity=Severity.HIGH,
        confidence=Confidence.CERTAIN,
        description="GitHub fine-grained personal access token (github_pat_ prefix).",
        references=(
            "https://github.blog/2022-10-18-introducing-fine-grained-personal-access-tokens-for-github/",
        ),
    ),
    SecretPattern(
        id="GITHUB-OAUTH",
        name="GitHub OAuth access token",
        regex=re.compile(r"\bgho_[A-Za-z0-9]{36}\b"),
        severity=Severity.HIGH,
        confidence=Confidence.CERTAIN,
        description="GitHub OAuth access token (gho_ prefix).",
    ),
    SecretPattern(
        id="GITHUB-APP-TOKEN",
        name="GitHub App installation token",
        regex=re.compile(r"\bghs_[A-Za-z0-9]{36}\b"),
        severity=Severity.HIGH,
        confidence=Confidence.CERTAIN,
        description="GitHub App server-to-server token (ghs_ prefix).",
    ),
    SecretPattern(
        id="GITHUB-USER-TOKEN",
        name="GitHub user-to-server token",
        regex=re.compile(r"\bghu_[A-Za-z0-9]{36}\b"),
        severity=Severity.HIGH,
        confidence=Confidence.CERTAIN,
        description="GitHub user-to-server token (ghu_ prefix).",
    ),
    SecretPattern(
        id="GITHUB-REFRESH-TOKEN",
        name="GitHub refresh token",
        regex=re.compile(r"\bghr_[A-Za-z0-9]{36}\b"),
        severity=Severity.HIGH,
        confidence=Confidence.CERTAIN,
        description="GitHub OAuth refresh token (ghr_ prefix).",
    ),
    # ---- Slack --------------------------------------------------------------
    SecretPattern(
        id="SLACK-TOKEN",
        name="Slack token",
        regex=re.compile(r"\bxox[baprs]-(?:[A-Za-z0-9-]{10,72})\b"),
        severity=Severity.HIGH,
        confidence=Confidence.FIRM,
        description=(
            "Slack token (xoxb=bot, xoxp=user, xoxa=app, xoxr=refresh, xoxs=workspace)."
        ),
        references=(
            "https://api.slack.com/authentication/token-types",
        ),
    ),
    SecretPattern(
        id="SLACK-WEBHOOK",
        name="Slack incoming webhook URL",
        regex=re.compile(
            r"\bhttps://hooks\.slack\.com/services/T[A-Z0-9]{8,12}/B[A-Z0-9]{8,12}/[A-Za-z0-9]{24}\b"
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.CERTAIN,
        description=(
            "Slack incoming webhook URL. Anyone with this URL can post messages "
            "into the linked channel."
        ),
        references=("https://api.slack.com/messaging/webhooks",),
    ),
    # ---- Stripe -------------------------------------------------------------
    SecretPattern(
        id="STRIPE-SECRET-LIVE",
        name="Stripe live secret key",
        regex=re.compile(r"\bsk_live_[0-9a-zA-Z]{24,99}\b"),
        severity=Severity.CRITICAL,
        confidence=Confidence.CERTAIN,
        description="Stripe live-mode secret key. Allows full API access on production.",
        references=("https://stripe.com/docs/keys",),
    ),
    SecretPattern(
        id="STRIPE-RESTRICTED-LIVE",
        name="Stripe live restricted key",
        regex=re.compile(r"\brk_live_[0-9a-zA-Z]{24,99}\b"),
        severity=Severity.HIGH,
        confidence=Confidence.CERTAIN,
        description="Stripe live-mode restricted key with scoped API access.",
    ),
    SecretPattern(
        id="STRIPE-SECRET-TEST",
        name="Stripe test secret key",
        regex=re.compile(r"\bsk_test_[0-9a-zA-Z]{24,99}\b"),
        severity=Severity.LOW,
        confidence=Confidence.CERTAIN,
        description=(
            "Stripe test-mode secret key. Cannot move real money but reveals "
            "merchant identity and test ledger contents."
        ),
    ),
    SecretPattern(
        id="STRIPE-PUBLISHABLE-LIVE",
        name="Stripe live publishable key",
        regex=re.compile(r"\bpk_live_[0-9a-zA-Z]{24,99}\b"),
        severity=Severity.INFO,
        confidence=Confidence.CERTAIN,
        publishable=True,
        description=(
            "Stripe live publishable key. These are intentionally public and "
            "safe to embed; reported as INFO for inventory completeness."
        ),
    ),
    # ---- Google -------------------------------------------------------------
    SecretPattern(
        id="GOOGLE-API-KEY",
        name="Google API key",
        regex=re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        severity=Severity.HIGH,
        confidence=Confidence.FIRM,
        description=(
            "Google API key (AIza* prefix). Risk depends on the API and key "
            "restrictions; verify scope before triaging."
        ),
        references=(
            "https://cloud.google.com/docs/authentication/api-keys",
        ),
    ),
    SecretPattern(
        id="GOOGLE-OAUTH-CLIENT-ID",
        name="Google OAuth client id",
        regex=re.compile(
            r"\b[0-9]+-[0-9a-z]{32}\.apps\.googleusercontent\.com\b"
        ),
        severity=Severity.INFO,
        confidence=Confidence.CERTAIN,
        publishable=True,
        description=(
            "Google OAuth 2.0 client id. These are intentionally public; "
            "reported as INFO for inventory only."
        ),
    ),
    # ---- npm / PyPI ---------------------------------------------------------
    SecretPattern(
        id="NPM-TOKEN",
        name="npm access token",
        regex=re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
        severity=Severity.HIGH,
        confidence=Confidence.CERTAIN,
        description="npm access token (npm_ prefix).",
        references=(
            "https://docs.npmjs.com/about-access-tokens",
        ),
    ),
    SecretPattern(
        id="PYPI-TOKEN",
        name="PyPI API token",
        regex=re.compile(r"\bpypi-AgE[A-Za-z0-9_\-]{50,200}\b"),
        severity=Severity.HIGH,
        confidence=Confidence.CERTAIN,
        description="PyPI API upload token (pypi-AgE* prefix).",
        references=("https://pypi.org/help/#apitoken",),
    ),
    # ---- Twilio / SendGrid / Mailgun ----------------------------------------
    SecretPattern(
        id="TWILIO-ACCOUNT-SID",
        name="Twilio account SID",
        regex=re.compile(r"\bAC[0-9a-fA-F]{32}\b"),
        severity=Severity.MEDIUM,
        confidence=Confidence.FIRM,
        description=(
            "Twilio account SID. Often paired with an auth token in the same "
            "response — review surrounding context."
        ),
    ),
    SecretPattern(
        id="SENDGRID-API-KEY",
        name="SendGrid API key",
        regex=re.compile(r"\bSG\.[A-Za-z0-9_\-]{16,32}\.[A-Za-z0-9_\-]{16,64}\b"),
        severity=Severity.HIGH,
        confidence=Confidence.CERTAIN,
        description="SendGrid API key (SG.<id>.<secret> shape).",
    ),
    SecretPattern(
        id="MAILGUN-API-KEY",
        name="Mailgun API key",
        regex=re.compile(r"\bkey-[a-z0-9]{32}\b"),
        severity=Severity.HIGH,
        confidence=Confidence.FIRM,
        description="Mailgun API key (key-* prefix).",
    ),
    # ---- Square -------------------------------------------------------------
    SecretPattern(
        id="SQUARE-ACCESS-TOKEN",
        name="Square access token",
        regex=re.compile(r"\bsq0atp-[A-Za-z0-9_\-]{22,128}\b"),
        severity=Severity.HIGH,
        confidence=Confidence.CERTAIN,
        description="Square access token (sq0atp- prefix).",
    ),
    SecretPattern(
        id="SQUARE-OAUTH-SECRET",
        name="Square OAuth secret",
        regex=re.compile(r"\bsq0csp-[A-Za-z0-9_\-]{43,128}\b"),
        severity=Severity.HIGH,
        confidence=Confidence.CERTAIN,
        description="Square OAuth client secret (sq0csp- prefix).",
    ),
    # ---- Private keys -------------------------------------------------------
    SecretPattern(
        id="PRIVATE-KEY-PEM",
        name="PEM-encoded private key",
        regex=re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"
        ),
        severity=Severity.CRITICAL,
        confidence=Confidence.CERTAIN,
        description=(
            "PEM private-key header in the response body. The corresponding "
            "private key material is exposed."
        ),
    ),
    # ---- JWT (signal-only, low severity) ------------------------------------
    SecretPattern(
        id="JWT",
        name="JSON Web Token",
        # header.payload.signature; both first segments must start with the
        # base64url encoding of '{"' which is `eyJ`.
        regex=re.compile(r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"),
        severity=Severity.LOW,
        confidence=Confidence.TENTATIVE,
        cwe="522",  # CWE-522: Insufficiently Protected Credentials
        description=(
            "JWT-shaped string in the response. JWTs are not always secret "
            "(some are intentionally public), but they may carry sensitive "
            "claims or grant access if leaked."
        ),
    ),
)


def patterns() -> tuple[SecretPattern, ...]:
    """Return the immutable pattern catalog."""
    return _PATTERNS


def redact_match(match: str) -> str:
    """Redact a matched secret to a non-reversible fingerprint.

    For tokens 12+ chars: ``first4 + '***' + last4``
    For shorter matches (rare): collapse to a uniform placeholder so a long
    secret cannot be reconstructed by combining low-entropy fragments.
    """
    n = len(match)
    if n >= 12:
        return f"{match[:4]}***{match[-4:]}"
    return "***"
