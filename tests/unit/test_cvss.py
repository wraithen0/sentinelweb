from __future__ import annotations

import pytest

from sentinelweb.reporting.cvss import CVSSError, score


@pytest.mark.parametrize(
    "vector, expected",
    [
        # Cross-checked against the FIRST CVSS v3.1 calculator.
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", 6.5),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    ],
)
def test_known_scores(vector: str, expected: float) -> None:
    assert score(vector) == expected


def test_invalid_prefix() -> None:
    with pytest.raises(CVSSError):
        score("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")


def test_missing_metric() -> None:
    with pytest.raises(CVSSError):
        score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H")
