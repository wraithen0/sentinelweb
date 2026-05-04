from __future__ import annotations

from pathlib import Path

from sentinelweb.scope.audit import AuditLog, verify


def test_chain_appends_and_verifies(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.jsonl", actor="tester")
    log.append("run.start", "example.test", {"foo": 1})
    log.append("scan.start", "https://example.test", {"scanner": "headers"})
    log.append("scan.complete", "https://example.test", {"findings": 3})
    ok, n, err = verify(tmp_path / "audit.jsonl")
    assert ok, err
    assert n == 3


def test_chain_detects_tampering(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    log = AuditLog(p, actor="tester")
    log.append("a", "x")
    log.append("b", "y")
    # tamper with line 1
    lines = p.read_text().splitlines()
    lines[0] = lines[0].replace("\"x\"", "\"hacked\"")
    p.write_text("\n".join(lines) + "\n")
    ok, _n, err = verify(p)
    assert not ok
    assert "hash" in err
