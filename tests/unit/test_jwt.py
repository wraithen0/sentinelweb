from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

import pytest

from sentinelweb.scanners import jwt as jwt_mod


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def make_jwt(header: dict, payload: dict, secret: str = "secret", alg: str = "HS256") -> str:
    h = b64u(json.dumps(header, separators=(",", ":")).encode())
    p = b64u(json.dumps(payload, separators=(",", ":")).encode())
    msg = f"{h}.{p}".encode()
    sig = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
    return f"{h}.{p}.{b64u(sig)}"


def test_alg_none_flagged() -> None:
    h = b64u(b'{"alg":"none","typ":"JWT"}')
    p = b64u(b'{"sub":"x","exp":9999999999}')
    token = f"{h}.{p}."
    findings = jwt_mod.analyze(token)
    ids = [f.id for f in findings]
    assert "JWT-ALG-NONE" in ids


def test_no_exp_flagged() -> None:
    token = make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "x"})
    ids = [f.id for f in jwt_mod.analyze(token)]
    assert "JWT-NO-EXP" in ids


def test_long_lifetime_flagged() -> None:
    iat = int(time.time())
    exp = iat + 365 * 24 * 3600
    token = make_jwt(
        {"alg": "HS256", "typ": "JWT"}, {"sub": "x", "iat": iat, "exp": exp}
    )
    ids = [f.id for f in jwt_mod.analyze(token)]
    assert "JWT-LONG-LIFETIME" in ids


def test_weak_secret_recovered() -> None:
    token = make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "x"}, secret="hunter2")
    found = jwt_mod.try_weak_secret(token, ["password", "qwerty", "hunter2", "letmein"])
    assert found == "hunter2"


def test_weak_secret_returns_none_on_strong() -> None:
    token = make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "x"}, secret="kJ#9$mZ!")
    found = jwt_mod.try_weak_secret(token, ["password", "qwerty"])
    assert found is None


def test_decode_invalid() -> None:
    with pytest.raises(jwt_mod.JWTError):
        jwt_mod.decode("not-a-jwt")
