# Contributing

Thanks for helping improve `code-review-mcp`.

## Getting set up

```bash
git clone https://github.com/ZhouZG-Gaogle/code-review-mcp.git
cd code-review-mcp
uv sync --extra dev
```

## Before you open a pull request

```bash
uv run pytest                          # the whole suite
uv run python scripts/check_rules.py   # rule YAML syntax + id uniqueness
uv run python scripts/e2e_check.py     # end-to-end over the real stdio protocol
uv run code-review scan . --quiet      # the repo must scan itself clean
```

The last one matters: **this repository must not contain live malware signatures or credential
literals**, otherwise endpoint security software will quarantine it. Test fixtures are assembled
at runtime from fragments (see `tests/fixtures.py`) — keep it that way.

## Adding a detection rule

Rules live in `src/code_review_mcp/rules/*.yaml`. Please:

1. Put the pattern in a YAML block scalar (`pattern: |-`) so no escaping gymnastics are needed.
2. Give it a stable, descriptive `id` — that is how users override it.
3. Add a `recommendation` that says what to *do*, not just what was found.
4. Add `prefilter` if the rule has an obvious literal anchor — it makes the scan noticeably faster.
5. If the rule matches a value (not a structural pattern), put it in capture group 1 and consider a
   `validator` (Luhn, national-ID checksum) to suppress false positives.
6. Add a test under `tests/` using the fixtures in `tests/fixtures.py`.

## Style

- Python 3.11+, type hints, no new runtime dependencies without discussion.
- Keep the server read-only: never write into the scanned directory, never execute scanned code,
  never make network calls.
- Subprocesses must be spawned with `stdin=subprocess.DEVNULL` — the MCP stdin is the JSON-RPC
  pipe and a child that inherits it deadlocks the protocol.

## Reporting a bug

Please include: your OS, Python version, the path you scanned (a minimal reproduction is ideal),
and the output of `uv run code-review scan <path> --severity-min info`.

If you think you found a false positive, please open an issue with the matching snippet —
false positives are the main thing that keeps this tool useful.
