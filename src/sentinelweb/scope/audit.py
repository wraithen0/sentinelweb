"""Tamper-evident JSONL audit log.

Each entry is hash-chained: ``prev_hash`` of entry N is the SHA-256 of
entry N-1's serialized payload. A consumer can verify the chain end-to-end
to detect tampering / deletion.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


@dataclass
class AuditEvent:
    timestamp: float
    actor: str
    action: str
    target: str
    detail: dict[str, Any]
    prev_hash: str
    hash: str

    def to_json(self) -> str:
        return json.dumps(
            {
                "timestamp": self.timestamp,
                "actor": self.actor,
                "action": self.action,
                "target": self.target,
                "detail": self.detail,
                "prev_hash": self.prev_hash,
                "hash": self.hash,
            },
            sort_keys=True,
            separators=(",", ":"),
        )


def _hash_payload(payload: dict[str, Any]) -> str:
    canon = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canon).hexdigest()


class AuditLog:
    """Append-only JSONL audit log."""

    def __init__(self, path: str | Path, actor: str | None = None) -> None:
        self.path = Path(path)
        self.actor = actor or os.environ.get("USER", "unknown")
        self._last_hash: str = self._scan_last_hash()

    def _scan_last_hash(self) -> str:
        if not self.path.exists():
            return GENESIS
        last = GENESIS
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    last = rec.get("hash") or last
                except json.JSONDecodeError:
                    # Corrupt line: stop and surface; chain verify will fail.
                    break
        return last

    def append(
        self,
        action: str,
        target: str,
        detail: dict[str, Any] | None = None,
    ) -> AuditEvent:
        timestamp = time.time()
        normalized_detail: dict[str, Any] = detail or {}
        payload: dict[str, Any] = {
            "timestamp": timestamp,
            "actor": self.actor,
            "action": action,
            "target": target,
            "detail": normalized_detail,
            "prev_hash": self._last_hash,
        }
        h = _hash_payload(payload)
        event = AuditEvent(
            timestamp=timestamp,
            actor=self.actor,
            action=action,
            target=target,
            detail=normalized_detail,
            prev_hash=self._last_hash,
            hash=h,
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(event.to_json() + "\n")
        self._last_hash = h
        return event


def verify(path: str | Path) -> tuple[bool, int, str]:
    """Verify an audit log's hash chain.

    Returns ``(ok, lines_checked, error_message)``.
    """
    p = Path(path)
    if not p.exists():
        return False, 0, f"audit log not found: {p}"

    prev = GENESIS
    n = 0
    with p.open("r", encoding="utf-8") as fh:
        for i, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            n += 1
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as exc:
                return False, n, f"line {i}: not valid JSON ({exc})"

            stored_hash = rec.pop("hash", None)
            if stored_hash is None:
                return False, n, f"line {i}: missing hash"
            if rec.get("prev_hash") != prev:
                return False, n, f"line {i}: prev_hash mismatch"
            recomputed = _hash_payload(rec)
            if recomputed != stored_hash:
                return False, n, f"line {i}: hash does not match payload"
            prev = stored_hash
    return True, n, ""


def iter_events(path: str | Path) -> Iterable[dict[str, Any]]:
    """Yield events as plain dicts (no verification)."""
    p = Path(path)
    if not p.exists():
        return
    with p.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue
