# Example templates

These are hand-authored YAML detection templates demonstrating the
engine's matcher syntax. Drop them into a `--templates-dir` to run them.

| File | What it detects |
| ---- | --------------- |
| `header-disclosure.yaml` | A response header that leaks the underlying tech stack (e.g. `X-Powered-By: PHP/5.4`). |
| `directory-traversal-canary.yaml` | A canary file at a known sensitive path responding with the file's literal contents (signal of unprotected static-file serving). |

The bundled built-ins live at
`src/sentinelweb/templates/builtin/`; they auto-load when no
`--templates-dir` is given.

See [`docs/usage.md#templates`](../../docs/usage.md#templates) for the
full template syntax reference.
