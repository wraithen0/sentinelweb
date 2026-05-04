# Usage

## scope

| Command                       | Description                                                |
| ----------------------------- | ---------------------------------------------------------- |
| `sentinelweb scope init`      | Print example `scope.yaml` to stdout                       |
| `sentinelweb scope validate`  | Parse + validate a scope file                              |
| `sentinelweb scope check`     | Check if a host/URL is in scope (exit 2 if out of scope)   |
| `sentinelweb scope audit-verify` | Verify hash-chain integrity of an `audit.jsonl` log    |

## recon

| Command                          | Description                                                  |
| -------------------------------- | ------------------------------------------------------------ |
| `sentinelweb recon subs DOMAIN`  | Subdomain enum via crt.sh (+ optional `--wordlist`)          |
| `sentinelweb recon ports HOST`   | nmap wrapper (host must be in scope)                         |
| `sentinelweb recon tech URL`     | Tech-stack fingerprint from headers + body + cookies         |
| `sentinelweb recon endpoints URL`| Extract URLs / forms / parameters from a single page         |

## scan

```bash
sentinelweb scan \
  --scope scope.yaml \
  --audit audit.jsonl \
  --session session.yaml \
  --scanner all \
  --report-dir reports/run-N \
  --format md --format html --format sarif \
  https://example.test/ https://api.example.test/foo?id=1
```

`--scanner` may be repeated; choices are `headers`, `cors`, `redirect`,
`xss`, `sqli`, `tls`, `takeover`, or `all`.

### Authenticated sessions

`--session FILE` loads a YAML/JSON bundle of cookies + headers for the
in-scope target. Credentials are attached **only** to in-scope hosts —
even a wildcard cookie will not be sent to a third-party domain the
target redirects you to.

```yaml
# session.yaml
cookies:
  - name: session
    value: "abc123"
    domain: "example.test"      # or "*" for any in-scope host
    path: "/"
headers:
  Authorization: "Bearer eyJ..."
host_headers:                   # optional per-host overrides
  api.example.test:
    X-Internal-Token: "..."
```

## takeover

Probes one or more in-scope hostnames for dangling-CNAME subdomain
takeovers (signal-only — never claims the resource):

```bash
sentinelweb takeover --scope scope.yaml \
  orphan.example.test legacy.example.test
```

Detection follows the public ``can-i-take-over-xyz`` fingerprints for
GitHub Pages, S3, Heroku, Vercel, Netlify, Azure, Bitbucket, Shopify,
and Tumblr. The same logic is also reachable via
`sentinelweb scan --scanner takeover`.

## jwt

Static analysis of a token (no network):

```bash
sentinelweb jwt --wordlist common-secrets.txt $TOKEN
```

## ssrf

Sends SSRF probes pointing at a callback URL **you** control (use an
out-of-band listener like Burp Collaborator or interactsh). The framework
records that the probe was sent — confirmation comes from your listener.

```bash
sentinelweb ssrf \
  --scope scope.yaml \
  --callback https://abcdef.oast.example/ \
  https://example.test/import?source=https://placeholder
```

## Audit log

Every command that takes `--audit PATH` appends hash-chained JSONL events
to that path. Verify any time with:

```bash
sentinelweb scope audit-verify audit.jsonl
```

A failed verification means the file has been tampered with or truncated.
