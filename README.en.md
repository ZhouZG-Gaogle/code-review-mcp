# code-review-mcp

English | [简体中文](README.md)

> An MCP server that gives AI coding agents a real code reviewer: secrets & PII, cache & oversized
> files, malicious files & malware behaviour — all local, all redacted.
>
> 一个给 AI 编码 agent 用的**代码审查 MCP 服务**：查敏感信息与个人信息，查缓存数据与大文件，
> 查病毒文件与恶意代码。

[![CI](https://github.com/ZhouZG-Gaogle/code-review-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/ZhouZG-Gaogle/code-review-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)

---

## Features

| Category | Coverage |
| --- | --- |
| **Keys & credentials** | Key and token patterns for AWS / Google / GitHub / GitLab / Slack / Stripe / OpenAI / Anthropic / HuggingFace / Alibaba Cloud / Tencent Cloud / npm / PyPI / Atlassian / SendGrid / Mailgun; PEM / OpenSSH / PuTTY private keys; JWTs; Basic auth embedded in URLs; plaintext passwords in connection strings; `.npmrc` / `.pypirc` / `.netrc` / `.htpasswd`; cloud service-account JSON; pre-signed URLs; hardcoded `password = "…"` |
| **Personal data** | CN mobile numbers, national ID numbers (MOD 11-2 checksum), bank card numbers (Luhn checksum), emails, US SSNs, passport numbers, home addresses, MAC addresses, internal IPs |
| **Cache artifacts** | `__pycache__` / `.pytest_cache` / `node_modules` / `dist` / `build` / `target` cache and build directories; `*.pyc` / `*.class` / `*.log` / `*.tmp` / `.DS_Store` cache files; minified single-line bundles; large embedded Base64 / data URIs |
| **Oversized files** | Warn at 1 MiB, high at 5 MiB by default; archives, documents, media, fonts and model weights get their own hints |
| **File spoofing** | An image extension that is really a PE executable; a source file that is really an executable; `invoice.pdf.exe` double extensions; UPX packing; abnormal code-file entropy (obfuscation / encrypted payload) |
| **Download-and-execute** | Piping a download straight into a shell or interpreter; PowerShell download-then-run; Python download-then-eval |
| **Reverse shells** | Shell `/dev/tcp`; netcat `-e`; Python socket + `pty.spawn`; PowerShell `TCPClient` |
| **Destructive commands** | Recursive deletion of root / system directories (shell, `shutil.rmtree`, PowerShell `Remove-Item`, raw device writes) |
| **Ransomware & theft** | Ransom-note text; SSH private keys / browser credential stores / wallet files / Windows credential dumping |
| **Persistence & injection** | Registry Run keys, `schtasks /create`, crontab; `CreateRemoteThread`, `WriteProcessMemory`, `VirtualAllocEx` |
| **EICAR** | The standard anti-malware test sample |

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

VS Code:

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

Registering with Claude Code:

```bash
claude mcp add code-review --scope user -- uv --directory /absolute/path/to/code-review-mcp run code-review-mcp
```

> **Two gotchas on Windows**: `claude mcp add` rejects flags after `--`;
> the MCP command must not be a `.cmd` / `.bat` file.

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

Common parameters:

- `severity_min` — `critical` / `high` / `medium` / `low` / `info`, default `info` (report everything).
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
- **Redacted evidence** — key material is masked.
- **Subprocesses get `stdin=DEVNULL`** — the MCP stdin is the JSON-RPC pipe; a child process
  inheriting it deadlocks the whole protocol stream.
- **The repo itself is clean** — no live malware signatures and no credential literals; test
  fixtures are assembled at runtime from fragments.

> If your endpoint security product flags this repository (the rule text necessarily contains
> phrases like "reverse shell" and "ransomware"), whitelist the directory.

---

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

---

## License

[MIT](LICENSE) © 2026 ZhouZG-Gaogle
