"""Minimal CVSS v3.1 base-score implementation.

Only the *base* metrics are supported. Temporal/environmental scores are
out of scope (most bug bounty programs only require base score + vector).

Reference: FIRST CVSS v3.1 Specification, section 7.1.
"""

from __future__ import annotations

from dataclasses import dataclass

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}


class CVSSError(ValueError):
    pass


@dataclass(frozen=True)
class CVSSv31:
    av: str  # Attack Vector: N, A, L, P
    ac: str  # Attack Complexity: L, H
    pr: str  # Privileges Required: N, L, H
    ui: str  # User Interaction: N, R
    s: str   # Scope: U, C
    c: str   # Confidentiality: N, L, H
    i: str   # Integrity: N, L, H
    a: str   # Availability: N, L, H

    @classmethod
    def parse(cls, vector: str) -> CVSSv31:
        v = vector.strip()
        prefix = "CVSS:3.1/"
        if not v.startswith(prefix):
            raise CVSSError("vector must start with 'CVSS:3.1/'")
        body = v[len(prefix):]
        parts = {}
        for token in body.split("/"):
            if not token:
                continue
            if ":" not in token:
                raise CVSSError(f"malformed metric: {token!r}")
            k, val = token.split(":", 1)
            parts[k] = val
        try:
            return cls(
                av=parts["AV"],
                ac=parts["AC"],
                pr=parts["PR"],
                ui=parts["UI"],
                s=parts["S"],
                c=parts["C"],
                i=parts["I"],
                a=parts["A"],
            )
        except KeyError as exc:
            raise CVSSError(f"missing metric {exc.args[0]!r}") from exc

    def vector(self) -> str:
        return (
            f"CVSS:3.1/AV:{self.av}/AC:{self.ac}/PR:{self.pr}/UI:{self.ui}/"
            f"S:{self.s}/C:{self.c}/I:{self.i}/A:{self.a}"
        )

    def score(self) -> float:
        try:
            av = _AV[self.av]
            ac = _AC[self.ac]
            pr_table = _PR_C if self.s == "C" else _PR_U
            pr = pr_table[self.pr]
            ui = _UI[self.ui]
            c = _CIA[self.c]
            i = _CIA[self.i]
            a = _CIA[self.a]
        except KeyError as exc:
            raise CVSSError(f"invalid metric value: {exc.args[0]!r}") from exc

        iss = 1 - ((1 - c) * (1 - i) * (1 - a))
        impact = (
            6.42 * iss
            if self.s == "U"
            else 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        )
        exploitability = 8.22 * av * ac * pr * ui

        if impact <= 0:
            return 0.0
        if self.s == "U":
            base = min(impact + exploitability, 10.0)
        else:
            base = min(1.08 * (impact + exploitability), 10.0)
        return _roundup(base)


def _roundup(value: float) -> float:
    """CVSS v3.1 'Roundup' to one decimal place (spec section 7.1)."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000
    return (int_input // 10000 + 1) / 10.0


def score(vector: str) -> float:
    """Convenience: parse and score a vector string."""
    return CVSSv31.parse(vector).score()
