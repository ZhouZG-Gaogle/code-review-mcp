# code-review-mcp

English | [简体中文](README.md)

> A **code-review MCP server** for AI coding agents: it finds secrets & personal data,
> cache artifacts & oversized files, and malicious files & malware behaviour.
>
> An MCP server that gives AI coding agents a real code reviewer — all local, all redacted.

[![CI](https://github.com/ZhouZG-Gaogle/code-review-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/ZhouZG-Gaogle/code-review-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)

---

## Why

AI-generated code routinely hardcodes an API key, commits `node_modules`, or pastes in an
unverified `curl … | bash`. This MCP lets an agent catch all of that **before** the commit,
and hand back actionable remediation steps.

- **Local only** — no network calls, no uploads; everything happens on the local filesystem.
- **Redacted output** — the original secret **never** appears in a report; only a few leading
  and trailing characters survive, enough to tell you which kind of secret it is.
- **Rules as data** — every detection rule is YAML, so tuning never means editing code.

---

## What it detects

### Track 1 — secrets, PII, cache artifacts, oversized files

| Category | Coverage |
| --- | --- |
| **Keys & credentials** | AWS / Google / GitHub / GitLab / Slack / Stripe / OpenAI / Anthropic / HuggingFace / Alibaba Cloud / Tencent Cloud / npm / PyPI / Atlassian / SendGrid / Mailgun keys and tokens; PEM / OpenSSH / PuTTY private keys; JWTs; Basic auth embedded in URLs; plaintext passwords in connection strings; `.npmrc` / `.pypirc` / `.netrc` / `.htpasswd`; cloud service-account JSON; pre-signed URLs; hardcoded `password = "…"` |
| **Personal data** | CN mobile numbers, national ID numbers (MOD 11-2 checksum), bank card numbers (Luhn checksum), emails, US SSNs, passport numbers, home addresses, MAC addresses, internal IP ranges |
| **Cache artifacts** | `__pycache__` / `.pytest_cache` / `node_modules` / `dist` / `build` / `target` and friends; `*.pyc` / `*.class` / `*.log` / `*.tmp` / `.DS_Store`; minified single-line bundles; large embedded Base64 / data URIs |
| **Oversized files** | Warn at 1 MiB, high at 5 MiB by default; archives, documents, media, fonts and model weights get their own hints |

### Track 2 — malicious files & malware behaviour

| Category | Coverage |
| --- | --- |
| **File spoofing** | An image extension that is really a PE executable; a source file that is really an executable; `invoice.pdf.exe` double extensions; UPX packing; abnormal code-file entropy (obfuscation / encrypted payload) |
| **Download-and-execute** | Piping a download straight into a shell or interpreter; PowerShell download-then-run; Python download-then-eval |
| **Reverse shells** | Shell `/dev/tcp`; netcat `-e`; Python socket + `pty.spawn`; PowerShell `TCPClient` |
| **Destructive commands** | Recursive deletion of root / system directories (shell, `shutil.rmtree`, PowerShell `Remove-Item`, raw device writes) |
| **Ransomware & theft** | Ransom-note text; SSH private keys, browser credential stores, wallet files, Windows credential dumping |
| **Persistence & injection** | Registry Run keys, `schtasks /create`, crontab; `CreateRemoteThread`, `WriteProcessMemory`, `VirtualAllocEx` |
| **EICAR** | The standard anti-malware test sample |

### Bonus: "sitting in the working tree" vs "already in version control"

When the target is a Git repository, the tool reads `git ls-files` and tells the two apart:

| Situation | Severity |
| --- | --- |
| `.env` only in the working tree | high |
| `.env` already committed | **critical**, plus "the credential is now in version history" |
| Cache directory untracked | low |
| Cache directory committed | medium |

Only read-only git commands are used (`rev-parse`, `ls-files`); the repository is never modified.

---

## Quick start

### Install

```bash
git clone https://github.com/ZhouZG-Gaogle/code-review-mcp.git
cd code-review-mcp
uv sync --extra dev          # or: uv pip install -e .
```

pip works too:

```bash
pip install -e .
```

### Try it from the shell

```bash
uv run code-review scan /path/to/your/project
```

### Wire it into your agent

See [Connecting to agents and clients](#connecting-to-agents-and-clients).

---

## Connecting to agents and clients

### Do I need per-agent adaptation?

**No.** MCP is a protocol-level contract (JSON-RPC over stdio or HTTP), so the *same* server
binary serves every client — there is no per-client code path, exactly like a portable
server rather than a Claude-only plugin.

This is worth contrasting with Claude Code's Skills:

|  | Skills | MCP |
| --- | --- | --- |
| Shape | Prompt / instruction text the agent reads and follows | A long-running process exposing **callable tools** |
| Portability | Claude Code specific (`.claude/skills/`) | Client-agnostic standard — any MCP-capable client works |
| Capability | Can only *advise* | Can actually act: read files, hash them, run rules, invoke Defender |

Only three things differ per client, and none of them require code changes:

1. **Registration** — each client reads a different file and key name (table below).
2. **Transport** — `stdio` locally, `code-review-mcp --transport http` for remote setups or
   clients that only speak HTTP.
3. **Tool description language** — descriptions here are bilingual, so Chinese- and
   English-speaking agents both pick the right tool.

> The server **never executes scanned code**, **never touches the network**, and **never
> writes into the scanned directory**, so attaching it to any agent that can read files is safe.

### Generic config shape

Most clients read the same `mcpServers` structure:

```json
{
  "mcpServers": {
    "code-review": {
      "command": "uv",
      "args": ["--directory", "/absolute/path/to/code-review-mcp", "run", "code-review-mcp"]
    }
  }
}
```

On Windows prefer forward slashes, or escape the backslashes:

```json
{
  "mcpServers": {
    "code-review": {
      "command": "uv",
      "args": ["--directory", "C:/path/to/code-review-mcp", "run", "code-review-mcp"]
    }
  }
}
```

### Where each client keeps its config

| Client | File | Top-level key |
| --- | --- | --- |
| **Claude Code** | `~/.claude.json` (user)<br>`.mcp.json` (project, committable) | `mcpServers` |
| **Claude Desktop** | Windows: `%APPDATA%\Claude\claude_desktop_config.json`<br>macOS: `~/Library/Application Support/Claude/claude_desktop_config.json` | `mcpServers` |
| **Cursor** | `~/.cursor/mcp.json` (global)<br>`.cursor/mcp.json` (project) | `mcpServers` |
| **VS Code (Copilot)** | `.vscode/mcp.json` (project)<br>user scope via `MCP: Open User Configuration` | `servers` (not `mcpServers`; needs an explicit `"type"`) |
| **Windsurf** | `~/.codeium/windsurf/mcp_config.json` | `mcpServers` |
| **Cline / Roo Code** | `cline_mcp_settings.json` / `mcp_settings.json` | `mcpServers` |
| **Continue** | `~/.continue/config.yaml` | `mcpServers:` (YAML list) |
| **Zed** | `~/.config/zed/settings.json` | `context_servers` |
| **Codex CLI** | `~/.codex/config.toml` | `[mcp_servers.<name>]` (TOML) |
| **Gemini CLI** | `~/.gemini/settings.json` | `mcpServers` |
| **Trae** | `~/.trae/mcp.json` or `<project>/.trae/mcp.json` | `mcpServers` |
| **Cherry Studio** | GUI: Settings → MCP Servers → Add server | — |

VS Code uses a different shape:

```json
{
  "servers": {
    "code-review": {
      "type": "stdio",
      "command": "uv",
      "args": ["--directory", "/absolute/path/to/code-review-mcp", "run", "code-review-mcp"]
    }
  }
}
```

For Claude Code the CLI is easiest:

```bash
claude mcp add code-review --scope user -- uv --directory /absolute/path/to/code-review-mcp run code-review-mcp
```

> **Two Windows gotchas** (see [FAQ](#faq)): `claude mcp add` rejects flags after `--`, and the
> MCP command must not be a `.cmd` / `.bat` file.

### HTTP transport (remote setups, HTTP-only clients)

```bash
uv run code-review-mcp --transport http --host 127.0.0.1 --port 8765
```

The endpoint is `http://127.0.0.1:8765/mcp` (streamable-http):

```json
{
  "mcpServers": {
    "code-review": {
      "type": "http",
      "url": "http://127.0.0.1:8765/mcp"
    }
  }
}
```

---

## Tools

| Tool | Purpose |
| --- | --- |
| `review_sensitive_data(path)` | Secrets + personal data + cache artifacts + oversized files |
| `review_malware(path)` | Malicious files / malware behaviour (optional Defender pass) |
| `review_code(path)` | All of the above in one pass |
| `review_git_diff(repo_path, base, mode)` | Only files touched by Git changes (`worktree` / `staged` / `base`) |
| `review_code_snippet(code, language)` | Review a single snippet — nothing written, nothing sent |
| `list_rules(category)` | Show the rules currently in effect |
| `export_rules(target_dir)` | Export the built-in rules as YAML |
| `review_status()` | Server configuration and rule inventory |

Useful parameters:

- `severity_min` — `critical` / `high` / `medium` / `low` / `info` (default `info`, report everything).
- `output_json_path` — also write a JSON report, handy for CI archiving or dashboards.
- `use_defender` — `review_malware` / `review_code` can additionally run a local Windows
  Defender custom scan (`-DisableRemediation`: detect only, never quarantine).

---

## Configuration

### Project-level `.code-review-mcp.yaml` (in the root of the scanned repo)

```yaml
exclude_dirs: [".git", "node_modules", ".venv"]   # directories to skip while walking
max_content_scan_bytes: 1048576                  # larger files are only size/type checked
large_file_warn_bytes: 1048576                   # 1 MiB
large_file_error_bytes: 5242880                  # 5 MiB
entropy_threshold: 7.2                          # code-file entropy alert threshold
report_placeholders: false                      # report placeholder-looking values too
defender:
  enabled: false
  timeout_seconds: 600
```

A user-level config at `~/.code-review-mcp/config.yaml` is overridden by the project-level one.

### Customising rules

**Override a single rule by id** — `.code-review-mcp-rules.yaml` in the project root:

```yaml
sensitive:
  rules:
    - id: generic-credential-assignment
      severity: medium
      recommendation: Read it from an environment variable instead.
    - id: my-custom-rule
      severity: high
      description: Example custom rule
      pattern: 'my-secret-[A-Za-z0-9]{8,}'
      prefilter: my-secret
```

**Replace a whole category** — `~/.code-review-mcp/rules/sensitive.yaml`
(edit the file produced by `export_rules` and drop it there).

Rule fields:

| Field | Meaning |
| --- | --- |
| `id` | Unique identifier; used to match overrides |
| `severity` | `critical` / `high` / `medium` / `low` / `info` |
| `pattern` | Regex; capture group 1 is the value to validate |
| `prefilter` | Optional literal prefilter for speed, `\|` separated |
| `validator` | Optional: `luhn` / `cn_id` / `cn_mobile` / `mac` / `entropy` |
| `hash_guard` | Optional: skip hits that sit inside a long hex string such as a sha256 |
| `extensions` | Optional: only apply to these file extensions |
| `exclude_dirs` | Optional: skip these directories |

---

## CLI / CI

```bash
# full scan; exit code 1 when anything at high or above is found
uv run code-review scan . --fail-on high

# only the files changed in Git, with a JSON report
uv run code-review scan . --diff base --base origin/main --json report.json

# one-line summary only
uv run code-review scan . --quiet

# rule inventory
uv run code-review rules --category malware
```

Typical CI step:

```yaml
- run: uv run code-review scan . --severity-min high --fail-on high --json review-report.json
```

---

## Security & compliance

This project is a *scanner*, so it has to be compliant itself. Full details in
[SECURITY.md](SECURITY.md); the essentials:

- **Read-only** — writes nothing except an explicitly requested JSON report; never executes or
  imports scanned code.
- **No network** — the only external call is the optional local Windows Defender (local IPC).
- **Redacted evidence** — key material never reaches the report.
- **Subprocesses get `stdin=DEVNULL`** — the MCP stdin is the JSON-RPC pipe; a child process
  inheriting it deadlocks the whole protocol stream.
- **The repo itself is clean** — no live malware signatures and no credential literals; test
  fixtures are assembled at runtime from fragments.

> If your endpoint security product flags this repository (the rule text necessarily contains
> phrases like "reverse shell" and "ransomware"), whitelist the directory.

---

## Development

```bash
uv run pytest                          # the whole suite
uv run python scripts/check_rules.py   # rule YAML syntax + id uniqueness
uv run python scripts/e2e_check.py     # end-to-end check over the real stdio protocol
uv run python scripts/platform_probe.py Linux   # run the suite under a simulated platform
uv run code-review scan . --quiet      # scan this repo with this repo's own tool
```

The end-to-end script really starts a stdio server and calls every tool, so it proves the
*protocol* works — not just the library functions.

### Layout

```
code-review-mcp/
├── pyproject.toml
├── LICENSE
├── SECURITY.md            # security & compliance notes
├── src/code_review_mcp/
│   ├── server.py          # MCP server and tool definitions
│   ├── cli.py             # command-line entry point (for CI)
│   ├── pipeline.py        # scan pipeline
│   ├── models.py          # Finding / ScanResult
│   ├── rules.py           # rule loading and merging
│   ├── config.py          # configuration
│   ├── walker.py          # file walking
│   ├── binary.py          # magic bytes / entropy / binary detection
│   ├── redactor.py        # redaction and placeholder detection
│   ├── validators.py      # Luhn / national ID checksums
│   ├── gitdiff.py         # Git change parsing and tracked-file state
│   ├── debuglog.py        # debug logging
│   ├── report.py          # report rendering
│   ├── rules/             # built-in rule YAML
│   └── scanners/          # the individual scanners
├── scripts/
│   ├── check_rules.py     # rule YAML syntax + id uniqueness check
│   ├── e2e_check.py       # MCP protocol end-to-end check
│   ├── platform_probe.py  # run the suite under a simulated platform
│   └── raw_probe.py       # raw JSON-RPC probe
└── tests/
```

### Debugging

Set `CODE_REVIEW_MCP_DEBUG=1` and each scan phase is logged to stderr (stdout stays clean for
the protocol stream):

```
[code-review-mcp +   0.05s] 配置与规则加载完成 (C:\repo)
[code-review-mcp +   0.05s] 文件遍历完成: 128 个文件
[code-review-mcp +   0.12s] Git 状态查询完成: available=True
[code-review-mcp +   0.20s] 扫描完成: 7 条发现
```

---

## FAQ

**Q: `claude mcp add ... -- uv --directory <path> run code-review-mcp` fails with
`unknown option '--directory'` on Windows.**

Current `claude mcp add` treats flags after `--` as its own options. Pass parameters through
the environment instead:

```powershell
claude mcp add code-review --scope user -e UV_PROJECT="C:/path/to/code-review-mcp" -- uv run code-review-mcp
```

**Q: Pointing the command at a `.cmd` / `.bat` gives `CONNECTION_CLOSED` on Windows.**

Since the CVE-2024-27980 fix, Node's `child_process.spawn` refuses to launch batch files when
`shell: false`, and that is exactly how MCP clients spawn the server. Point at the real
executable instead:

```powershell
claude mcp add code-review --scope user -- "C:\path\to\code-review-mcp\.venv\Scripts\code-review-mcp.exe"
```

**Q: Too many false positives, or missing detections?**

Run `list_rules` to confirm the rules are in effect, then override `severity` or `enabled` per
rule id in `.code-review-mcp-rules.yaml`. Placeholder-looking values (`your-api-key`, `${VAR}`)
are filtered out by default; set `report_placeholders: true` to see them anyway.

**Q: Does it send my code anywhere?**

No. Everything runs locally; there are no network requests.

---

## License

[MIT](LICENSE) © 2026 ZhouZG-Gaogle
