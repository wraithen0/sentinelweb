# Contributing

Thanks for considering a contribution. A few project-specific rules:

## Defensive-only

SentinelWeb is a **defensive** framework. PRs that add features designed to
cause harm — destructive payloads, credential theft, exploitation pivots,
mass scanners that ignore scope — will be rejected. If you're unsure
whether a feature crosses that line, open an issue first.

## Code

- Python 3.11+, type-hinted.
- Run `ruff check src tests` and `mypy src` before pushing.
- New scanners must:
  - take a `ScopePolicy` and a rate-limited `Client`
  - call `policy.assert_in_scope()` before any outbound traffic
  - return `list[Finding]` — no I/O side-effects beyond the HTTP probe
  - ship with unit tests using `respx` (no live network calls in CI)

## Tests

```bash
pip install -e ".[dev]"
pytest -ra --cov=sentinelweb
```

## Reporting security issues

Open an issue at https://github.com/wraithen0/sentinelweb/issues — for
sensitive matters, mark the title with `[security]`.
