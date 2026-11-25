# code-review-mcp

[English](README.en.md) | 简体中文

> 一个给 AI 编码 agent 用的**代码审查 MCP 服务**：查敏感信息与个人信息，查缓存数据与大文件，
> 查病毒文件与恶意代码。
>
> An MCP server that gives AI coding agents a real code reviewer: secrets & PII, cache & oversized
> files, malicious files & malware behaviour — all local, all redacted.

[![CI](https://github.com/ZhouZG-Gaogle/code-review-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/ZhouZG-Gaogle/code-review-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)



---

## 功能



| 类别 | 覆盖内容 |
| --- | --- |
| **密钥与凭据** | AWS / Google / GitHub / GitLab / Slack / Stripe / OpenAI / Anthropic / HuggingFace / 阿里云 / 腾讯云 / npm / PyPI / Atlassian / SendGrid / Mailgun 的 Key 与 Token；PEM / OpenSSH / PuTTY 私钥；JWT；URL 内嵌 Basic 认证；数据库连接串明文口令；`.npmrc` / `.pypirc` / `.netrc` / `.htpasswd`；云服务账号 JSON；预签名 URL；硬编码 `password = "…"` |
| **个人信息** | 中国大陆手机号、身份证号（带 MOD 11-2 校验）、银行卡号（Luhn 校验）、邮箱、美国 SSN、护照号、居住地址、MAC 地址、内网 IP |
| **缓存数据** | `__pycache__` / `.pytest_cache` / `node_modules` / `dist` / `build` / `target` 等缓存与构建目录；`*.pyc` / `*.class` / `*.log` / `*.tmp` / `.DS_Store` 等缓存文件；压缩后的单行代码；源码内嵌的大段 Base64 / data URI |
| **大文件** | 默认 1 MiB 告警、5 MiB 高危；压缩包 / 文档 / 媒体 / 字体 / 模型权重等二进制制品单独提示 |
| **文件伪装** | 图片扩展名实为 PE 可执行文件；源码文件实为可执行文件；`invoice.pdf.exe` 双扩展名；UPX 加壳；代码文件香农熵异常（混淆 / 加密载荷） |
| **下载即执行** | 下载内容直接管道给 shell / 解释器；PowerShell 下载后立即执行；Python 下载后直接求值 |
| **反弹 Shell** | shell 的 `/dev/tcp` 特性；netcat `-e`；Python socket + `pty.spawn`；PowerShell `TCPClient` |
| **破坏性命令** | 递归删除根目录 / 系统目录（shell、`shutil.rmtree`、PowerShell `Remove-Item`、裸设备写入） |
| **勒索与窃密** | 加密勒索信文本；SSH 私钥 / 浏览器凭据库 / 钱包文件 / Windows 凭据导出 |
| **持久化与注入** | 注册表 Run 键、`schtasks /create`、crontab；`CreateRemoteThread`、`WriteProcessMemory`、`VirtualAllocEx` |
| **EICAR** | 标准杀毒测试样本 |

## 快速开始

### 安装

```bash
git clone https://github.com/ZhouZG-Gaogle/code-review-mcp.git
cd code-review-mcp
uv sync --extra dev          # 或: uv pip install -e .
```

用 pip 也可以：

```bash
pip install -e .
```

### 命令行先试一把

```bash
uv run code-review scan /path/to/your/project
```

> 

### 通用配置格式

绝大多数客户端读同一个 `mcpServers` 结构：

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

Windows 路径建议用正斜杠，或把反斜杠写成 `\\`：

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

### 各客户端配置位置

| 客户端 | 配置文件 | 顶层字段 |
| --- | --- | --- |
| **Claude Code** | `~/.claude.json`（用户级）<br>`.mcp.json`（项目级，可提交） | `mcpServers` |
| **Claude Desktop** | Windows: `%APPDATA%\Claude\claude_desktop_config.json`<br>macOS: `~/Library/Application Support/Claude/claude_desktop_config.json` | `mcpServers` |
| **Cursor** | `~/.cursor/mcp.json`（全局）<br>`.cursor/mcp.json`（项目级） | `mcpServers` |
| **VS Code (Copilot)** | `.vscode/mcp.json`（项目级）<br>用户级 `MCP: Open User Configuration` | `servers`（注意不是 `mcpServers`，且需显式写 `"type"`） |
| **Windsurf** | `~/.codeium/windsurf/mcp_config.json` | `mcpServers` |
| **Cline / Roo Code** | `cline_mcp_settings.json` / `mcp_settings.json` | `mcpServers` |
| **Continue** | `~/.continue/config.yaml` | `mcpServers:`（YAML 列表） |
| **Zed** | `~/.config/zed/settings.json` | `context_servers` |
| **Codex CLI** | `~/.codex/config.toml` | `[mcp_servers.<name>]`（TOML） |
| **Gemini CLI** | `~/.gemini/settings.json` | `mcpServers` |
| **Trae** | `~/.trae/mcp.json` 或 `<项目>/.trae/mcp.json` | `mcpServers` |
| **Cherry Studio** | 图形界面：设置 → MCP Servers → 添加服务器 | — |

VS Code ：

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

Claude Code 注册：

```bash
claude mcp add code-review --scope user -- uv --directory /absolute/path/to/code-review-mcp run code-review-mcp
```

> **Windows 上的两个坑**（详见本文末尾「常见问题」）：`claude mcp add` 不接受 `--` 之后的 flag；
> MCP 命令不能是 `.cmd` / `.bat` 文件。

## 工具一览

| 工具 | 用途 |
| --- | --- |
| `review_sensitive_data(path)` | 敏感信息 + 个人信息 + 缓存数据 + 大文件 |
| `review_malware(path)` | 病毒文件 / 恶意代码（可选 Defender 联动） |
| `review_code(path)` | 上述全部，一次跑完 |
| `review_git_diff(repo_path, base, mode)` | 只审查 Git 变更文件（`worktree` / `staged` / `base`） |
| `review_code_snippet(code, language)` | 审查一段代码片段，不落盘、不联网 |
| `list_rules(category)` | 查看当前生效的规则 |
| `export_rules(target_dir)` | 导出内置规则以便定制 |
| `review_status()` | 查看服务配置与规则数量 |

常用参数：

- `severity_min`：`critical` / `high` / `medium` / `low` / `info`，默认 `info`（全部报告）。
- `output_json_path`：额外落一份 JSON 报告，便于 CI 归档或接入看板。
- `use_defender`：`review_malware` / `review_code` 可开启，额外调用本机 Windows Defender 做一次
  自定义扫描（`-DisableRemediation`，只检测不隔离）。

---

## 配置

### 项目级 `.code-review-mcp.yaml`（放在被审查仓库根目录）

```yaml
exclude_dirs: [".git", "node_modules", ".venv"]   # 遍历时排除的目录
max_content_scan_bytes: 1048576                  # 超过此大小只做体积/类型检查
large_file_warn_bytes: 1048576                   # 1 MiB
large_file_error_bytes: 5242880                  # 5 MiB
entropy_threshold: 7.2                          # 代码文件熵值告警阈值
report_placeholders: false                      # 是否上报占位符（如 your-api-key）
defender:
  enabled: false
  timeout_seconds: 600
```

用户级配置放在 `~/.code-review-mcp/config.yaml`，优先级低于项目级。

### 规则定制

**按 id 覆盖单条规则** —— 项目根目录 `.code-review-mcp-rules.yaml`：

```yaml
sensitive:
  rules:
    - id: generic-credential-assignment
      severity: medium
      recommendation: 改为从环境变量读取。
    - id: my-custom-rule
      severity: high
      description: 自定义规则示例
      pattern: 'my-secret-[A-Za-z0-9]{8,}'
      prefilter: my-secret
```

**整体替换某类规则** —— `~/.code-review-mcp/rules/sensitive.yaml`
（把 `export_rules` 导出的文件改好后放进去即可）。

规则字段：

| 字段 | 说明 |
| --- | --- |
| `id` | 唯一标识，覆盖时用它匹配 |
| `severity` | `critical` / `high` / `medium` / `low` / `info` |
| `pattern` | 正则，捕获组 1 为待校验的值 |
| `prefilter` | 可选，子串预筛加速，多个用 `\|` 分隔 |
| `validator` | 可选，`luhn` / `cn_id` / `cn_mobile` / `mac` / `entropy` |
| `hash_guard` | 可选，为 true 时跳过落在 sha256 等长十六进制串里的命中 |
| `extensions` | 可选，仅对这些扩展名的文件生效 |
| `exclude_dirs` | 可选，命中这些目录时跳过 |

---

## 命令行 / CI

```bash
# 全量审查，有 high 以上问题时退出码为 1
uv run code-review scan . --fail-on high

# 只审查 Git 变更文件，输出 JSON 报告
uv run code-review scan . --diff base --base origin/main --json report.json

# 只出一行摘要
uv run code-review scan . --quiet

# 查看规则清单
uv run code-review rules --category malware
```

典型 CI 用法：

```yaml
- run: uv run code-review scan . --severity-min high --fail-on high --json review-report.json
```

---

## 安全与合规

本工具是**扫描器**，所以它自己必须先做到合规。完整说明见 [SECURITY.md](SECURITY.md)，要点：

- **只读**：除显式指定的 JSON 报告外不写任何文件；不执行、不导入被扫描的代码。
- **不联网**：唯一的外部调用是可选的本机 Windows Defender（本地 IPC）。
- **证据脱敏**：屏蔽密钥原文。
- **子进程切断 stdin**：MCP 的 stdin 是 JSON-RPC 管道，子进程继承它会挂死整条协议流。
- **仓库自身干净**：不携带活体恶意签名与凭据字面量；测试夹具运行时分行拼接。

> 如果你的杀毒软件对本工程目录告警（规则文本里必然出现「反向 Shell」「勒索软件」等描述性词汇），
> 请把本目录加入白名单。

---

### 目录结构

```
code-review-mcp/
├── pyproject.toml
├── LICENSE
├── SECURITY.md            # 安全与合规说明
├── src/code_review_mcp/
│   ├── server.py          # MCP 服务与工具定义
│   ├── cli.py             # 命令行入口（CI 用）
│   ├── pipeline.py        # 扫描流水线
│   ├── models.py          # Finding / ScanResult
│   ├── rules.py           # 规则加载与合并
│   ├── config.py          # 配置
│   ├── walker.py          # 文件遍历
│   ├── binary.py          # 魔数 / 熵 / 二进制识别
│   ├── redactor.py        # 脱敏与占位符识别
│   ├── validators.py      # Luhn / 身份证校验
│   ├── gitdiff.py         # Git 变更解析与跟踪状态
│   ├── debuglog.py        # 调试日志
│   ├── report.py          # 报告渲染
│   ├── rules/             # 内置规则 YAML
│   └── scanners/          # 各扫描器
├── scripts/
│   ├── check_rules.py     # 规则 YAML 语法与 id 唯一性自检
│   ├── e2e_check.py       # MCP 协议端到端自检
│   ├── platform_probe.py  # 模拟其它平台跑测试
│   └── raw_probe.py       # 原始 JSON-RPC 探针
└── tests/
```

---

## License

[MIT](LICENSE) © 2026 ZhouZG-Gaogle
