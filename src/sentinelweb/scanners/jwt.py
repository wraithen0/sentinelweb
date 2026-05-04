"""JWT weakness analyzer.

Statically inspects a JWT (provided directly or harvested from a response)
and flags common misconfigurations:

- ``alg: none``
- HS256 with a weak / dictionary secret (when ``--wordlist`` is provided)
- Missing ``exp`` / very long lifetimes
- ``alg`` confusion candidates (RS256 + likely public key as secret)

It does not forge tokens. Findings include the decoded header/payload as
evidence so the operator can submit a clean report.
"""

from __future__ import annotations

import base64
import json
import time
from collections.abc import Iterable
from dataclasses import dataclass

from ..reporting.findings import Confidence, Evidence, Finding, Severity


@dataclass
class DecodedJWT:
    header: dict[str, object]
    payload: dict[str, object]
    raw: str
    signature_b64: str


class JWTError(ValueError):
    pass


def _b64url_decode(s: str) -> bytes:
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def decode(token: str) -> DecodedJWT:
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise JWTError("token must have 3 parts")
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except (ValueError, json.JSONDecodeError) as exc:
        raise JWTError(f"could not decode token: {exc}") from exc
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise JWTError("header/payload must be JSON objects")
    return DecodedJWT(header=header, payload=payload, raw=token, signature_b64=parts[2])


def analyze(token: str, *, target: str = "<token>") -> list[Finding]:
    """Analyze a JWT and return findings. Raises JWTError on bad token."""
    decoded = decode(token)
    findings: list[Finding] = []
    alg = str(decoded.header.get("alg", "")).lower()

    if alg in {"none", ""}:
        findings.append(
            Finding(
                id="JWT-ALG-NONE",
                title="JWT uses 'alg: none'",
                severity=Severity.CRITICAL,
                confidence=Confidence.CERTAIN,
                target=target,
                category="jwt",
                cwe="347",
                description=(
                    "The JWT header declares `alg: none`. Any party can craft "
                    "tokens with arbitrary claims accepted as valid."
                ),
                remediation=(
                    "Reject `alg: none` server-side. Pin the expected algorithm "
                    "(HS256 / RS256 / EdDSA) and verify signatures."
                ),
                detected_by="scanners.jwt",
                evidence=[_evidence(decoded)],
                references=["https://cwe.mitre.org/data/definitions/347.html"],
            )
        )

    exp = decoded.payload.get("exp")
    iat = decoded.payload.get("iat")
    if exp is None:
        findings.append(
            Finding(
                id="JWT-NO-EXP",
                title="JWT has no expiration claim",
                severity=Severity.MEDIUM,
                confidence=Confidence.CERTAIN,
                target=target,
                category="jwt",
                cwe="613",
                description="The token has no `exp` claim and is effectively eternal.",
                remediation="Set an `exp` and rotate refresh tokens.",
                detected_by="scanners.jwt",
                evidence=[_evidence(decoded)],
            )
        )
    elif isinstance(exp, (int, float)) and isinstance(iat, (int, float)):
        lifetime = float(exp) - float(iat)
        if lifetime > 30 * 24 * 3600:
            findings.append(
                Finding(
                    id="JWT-LONG-LIFETIME",
                    title="JWT lifetime exceeds 30 days",
                    severity=Severity.LOW,
                    confidence=Confidence.CERTAIN,
                    target=target,
                    category="jwt",
                    cwe="613",
                    description=(
                        f"Token lifetime is {int(lifetime)} seconds (~{int(lifetime/86400)} days)."
                    ),
                    remediation="Issue short-lived access tokens (<= 1 hour).",
                    detected_by="scanners.jwt",
                    evidence=[_evidence(decoded)],
                )
            )
    elif isinstance(exp, (int, float)) and float(exp) > time.time() + 365 * 24 * 3600:
        findings.append(
            Finding(
                id="JWT-FAR-EXP",
                title="JWT exp is more than 1 year in the future",
                severity=Severity.LOW,
                confidence=Confidence.CERTAIN,
                target=target,
                category="jwt",
                cwe="613",
                description="Token expires more than a year from now.",
                remediation="Issue short-lived access tokens (<= 1 hour).",
                detected_by="scanners.jwt",
                evidence=[_evidence(decoded)],
            )
        )

    if alg.startswith("hs") and isinstance(decoded.header.get("kid"), str):
        # Heuristic: HS + public-looking kid is suspicious for alg confusion.
        kid = str(decoded.header["kid"])
        if any(s in kid.lower() for s in ("public", "rsa", "pem")):
            findings.append(
                Finding(
                    id="JWT-ALG-CONFUSION-CANDIDATE",
                    title="HS-signed JWT with public-key-like kid",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.TENTATIVE,
                    target=target,
                    category="jwt",
                    cwe="347",
                    description=(
                        "The token uses an HMAC algorithm but the `kid` "
                        "references what looks like a public key. If the "
                        "verifier ever accepts the public key as the HMAC "
                        "secret, an attacker can forge tokens (alg-confusion)."
                    ),
                    remediation="Pin algorithm per key; never accept HS* with RSA/EC keys.",
                    detected_by="scanners.jwt",
                    evidence=[_evidence(decoded)],
                )
            )
    return findings


def try_weak_secret(token: str, candidates: Iterable[str]) -> str | None:
    """If the token is HS256/384/512, try a wordlist of candidate secrets.

    Returns the first secret that produces a matching signature, else None.
    """
    import hashlib
    import hmac

    decoded = decode(token)
    alg = str(decoded.header.get("alg", "")).lower()
    digest = {"hs256": hashlib.sha256, "hs384": hashlib.sha384, "hs512": hashlib.sha512}.get(alg)
    if not digest:
        return None
    signing_input = (".".join(token.split(".", 2)[:2])).encode()
    expected = _b64url_decode(decoded.signature_b64)
    for cand in candidates:
        sig = hmac.new(cand.encode(), signing_input, digest).digest()
        if hmac.compare_digest(sig, expected):
            return cand
    return None


def _evidence(decoded: DecodedJWT) -> Evidence:
    return Evidence(
        description="Decoded JWT (header.payload)",
        response_excerpt=json.dumps(
            {"header": decoded.header, "payload": decoded.payload},
            indent=2,
            sort_keys=True,
        ),
    )
