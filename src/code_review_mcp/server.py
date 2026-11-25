"""MCP 服务入口：对外暴露代码审查工具。

工具描述同时提供中英文：MCP 协议本身与客户端无关，
双语描述能让不同语言的 agent 都准确理解每个工具的用途与边界。
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP

from .config import Config
from .gitdiff import MODE_BASE, MODE_STAGED, MODE_WORKTREE, list_changed_files
from .models import CATEGORY_LABEL, Category, Severity
from .pipeline import ScanRequest, run_scan, scan_snippet
from .report import render_json, render_markdown, render_summary
from .rules import export_default_rules, load_rules

mcp = FastMCP(
    "code-review-mcp",
    instructions=(
        "代码审查 MCP。两条主线："
        "(1) review_sensitive_data —— 敏感信息、个人信息、缓存数据、大文件；"
        "(2) review_malware —— 病毒文件与恶意代码。"
        "报告中的证据片段已脱敏，不会泄露密钥原文。\n"
        "A code-review MCP server with two tracks: "
        "(1) review_sensitive_data — secrets, PII, cache artifacts and large files; "
        "(2) review_malware — malicious files and malware behaviour. "
        "All matched values are redacted before they are returned."
    ),
)

CATEGORY_HELP = {
    "sensitive": "敏感信息（密钥 / 令牌 / 口令 / 私钥） / secrets, tokens, credentials, private keys",
    "pii": "个人信息（手机号 / 身份证 / 银行卡 / 邮箱） / personal data",
    "cache": "缓存数据与构建产物 / cache and build artifacts",
    "large_file": "大文件与二进制制品 / oversized and binary files",
    "malware": "病毒文件与恶意代码 / malicious files and malware",
}


def _categories(raw: list[str] | None, default: set[Category]) -> set[Category]:
    if not raw:
        return default
    out: set[Category] = set()
    for item in raw:
        try:
            out.add(Category(item.strip().lower()))
        except ValueError:
            continue
    return out or default


def _severity(raw: str | None, default: Severity = Severity.INFO) -> Severity:
    if not raw:
        return default
    try:
        return Severity(str(raw).strip().lower())
    except ValueError:
        return default


def _resolve(path: str) -> Path:
    p = Path(path).expanduser()
    return p if p.is_absolute() else (Path.cwd() / p)


def _write_json(path: str, result: Any) -> str | None:
    try:
        target = Path(path).expanduser()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(render_json(result), encoding="utf-8")
    except OSError as exc:
        return f"JSON 报告写入失败: {exc}"
    return None


# ------------------------------------------------------------------ 工具


@mcp.tool()
def review_sensitive_data(
    path: Annotated[str, "要审查的目录或仓库根路径 / directory or repository root to scan"],
    categories: Annotated[
        list[str] | None,
        "要启用的分类，可选 sensitive / pii / cache / large_file；默认全部四项 / "
        "categories to enable; defaults to all four",
    ] = None,
    severity_min: Annotated[
        str, "严重级别下限：critical / high / medium / low / info，默认 info / minimum severity to report"
    ] = "info",
    output_json_path: Annotated[str | None, "额外把 JSON 报告写到该路径 / also write a JSON report here"] = None,
) -> str:
    """审查代码中的敏感信息、个人信息、缓存数据与大文件。

    Scan a codebase for secrets, personal data, cache artifacts and oversized files.

    覆盖：AWS/GitHub/阿里云等各类密钥与令牌、私钥文件、连接串口令、手机号/身份证/银行卡/邮箱、
    缓存目录与构建产物、被误提交的大文件与二进制制品。命中内容一律脱敏后输出。
    Covers: cloud API keys and tokens, private key files, connection-string credentials,
    phone / national-ID / bank-card / email, cache and build directories,
    oversized and binary artifacts. Every matched value is redacted before it is returned.
    """
    root = _resolve(path)
    if not root.is_dir():
        return f"❌ 路径不存在或不是目录: {root}"

    wanted = _categories(categories, {Category.SENSITIVE, Category.PII, Category.CACHE, Category.LARGE_FILE})
    result = run_scan(ScanRequest(
        root=root,
        categories=wanted,
        severity_min=_severity(severity_min),
    ))
    if output_json_path:
        err = _write_json(output_json_path, result)
        if err:
            result.notes.append(err)
    return render_markdown(result, "代码审查报告 · 敏感信息 / 个人信息 / 缓存 / 大文件")


@mcp.tool()
def review_malware(
    path: Annotated[str, "要审查的目录或仓库根路径 / directory or repository root to scan"],
    severity_min: Annotated[
        str, "严重级别下限：critical / high / medium / low / info，默认 info / minimum severity to report"
    ] = "info",
    use_defender: Annotated[
        bool, "是否额外调用本机 Windows Defender 做一次自定义扫描（较慢，仅 Windows 可用） / "
              "also run a local Windows Defender custom scan (slow, Windows only)"
    ] = False,
    output_json_path: Annotated[str | None, "额外把 JSON 报告写到该路径 / also write a JSON report here"] = None,
) -> str:
    """审查代码中的病毒文件与恶意代码。

    Scan for malicious files and malware behaviour in a codebase.

    覆盖：可执行 / 脚本 / 二进制制品、扩展名伪装（图片实为 PE）、双扩展名、UPX 加壳、
    代码高熵混淆、下载即执行、反向 Shell、勒索软件、凭据窃取、持久化与进程注入等行为特征。
    Covers: executables and scripts, extension spoofing (an image that is really a PE),
    double extensions, UPX packing, high-entropy obfuscation, download-and-execute chains,
    reverse shells, ransomware notes, credential theft, persistence and process injection.
    """
    root = _resolve(path)
    if not root.is_dir():
        return f"❌ 路径不存在或不是目录: {root}"

    result = run_scan(ScanRequest(
        root=root,
        categories={Category.MALWARE},
        severity_min=_severity(severity_min),
        use_defender=use_defender,
    ))
    if output_json_path:
        err = _write_json(output_json_path, result)
        if err:
            result.notes.append(err)
    return render_markdown(result, "代码审查报告 · 病毒文件 / 恶意代码")


@mcp.tool()
def review_code(
    path: Annotated[str, "要审查的目录或仓库根路径 / directory or repository root to scan"],
    severity_min: Annotated[
        str, "严重级别下限：critical / high / medium / low / info，默认 info / minimum severity to report"
    ] = "info",
    use_defender: Annotated[bool, "是否额外调用 Windows Defender 扫描 / also run a local Defender scan"] = False,
    output_json_path: Annotated[str | None, "额外把 JSON 报告写到该路径 / also write a JSON report here"] = None,
) -> str:
    """一次性完成全部审查：敏感信息 + 个人信息 + 缓存数据 + 大文件 + 病毒文件。

    Run every check in one pass: secrets, personal data, cache artifacts, large files and malware.
    """
    root = _resolve(path)
    if not root.is_dir():
        return f"❌ 路径不存在或不是目录: {root}"

    result = run_scan(ScanRequest(
        root=root,
        categories=set(Category),
        severity_min=_severity(severity_min),
        use_defender=use_defender,
    ))
    if output_json_path:
        err = _write_json(output_json_path, result)
        if err:
            result.notes.append(err)
    return render_markdown(result, "代码审查报告 · 全量检查")


@mcp.tool()
def review_git_diff(
    repo_path: Annotated[str, "Git 仓库根路径 / root of the Git repository"],
    base: Annotated[
        str | None,
        "对比基准分支或提交（如 origin/main、HEAD~1）；mode=base 时必填 / "
        "base branch or commit to compare against (required when mode=base)",
    ] = None,
    mode: Annotated[
        str, "worktree（工作区全部改动，默认）/ staged（已暂存）/ base（相对 base 的差异） / "
            "which changes to review: worktree (default), staged, or base"
    ] = "worktree",
    severity_min: Annotated[str, "严重级别下限，默认 info / minimum severity to report"] = "info",
    use_defender: Annotated[bool, "是否额外调用 Windows Defender 扫描 / also run a local Defender scan"] = False,
    output_json_path: Annotated[str | None, "额外把 JSON 报告写到该路径 / also write a JSON report here"] = None,
) -> str:
    """只审查 Git 变更涉及的文件（适合接入 CI / PR 流程）。

    Review only the files touched by Git changes — useful in CI or on a pull request.
    """
    root = _resolve(repo_path)
    if not root.is_dir():
        return f"❌ 路径不存在或不是目录: {root}"

    mode_key = (mode or MODE_WORKTREE).strip().lower()
    if mode_key not in (MODE_WORKTREE, MODE_STAGED, MODE_BASE):
        return f"❌ 未知的 mode: {mode}（可选 worktree / staged / base）"

    change = list_changed_files(root, mode=mode_key, base=base)
    if change.errors:
        return "❌ " + "\n".join(change.errors)
    if not change.files:
        return f"✅ Git（{mode_key}）没有检测到变更文件。"

    result = run_scan(ScanRequest(
        root=root,
        categories=set(Category),
        only_files=change.files,
        severity_min=_severity(severity_min),
        use_defender=use_defender,
    ))
    result.scope = f"git:{mode_key}" + (f"({base})" if base and mode_key == MODE_BASE else "")
    result.notes.append(f"Git 变更文件 {len(change.files)} 个：" + "、".join(change.files[:20])
                        + ("…" if len(change.files) > 20 else ""))
    if output_json_path:
        err = _write_json(output_json_path, result)
        if err:
            result.notes.append(err)
    return render_markdown(result, "代码审查报告 · Git 变更")


@mcp.tool()
def review_code_snippet(
    code: Annotated[str, "要审查的代码片段原文 / the source code to review"],
    language: Annotated[str, "语言提示，如 python / javascript / java，可留空 / language hint, may be empty"] = "",
) -> str:
    """审查一段代码片段中的敏感信息与恶意代码特征（不落盘、不联网）。

    Review a single snippet for secrets and malware indicators — nothing is written to disk and
    nothing goes over the network.
    """
    if not code.strip():
        return "❌ code 不能为空。"
    result = scan_snippet(code, language)
    return render_markdown(result, "代码片段审查报告")


@mcp.tool()
def list_rules(
    category: Annotated[
        str | None, "只列出某一类规则：sensitive / pii / cache / large_file / malware / one category only"
    ] = None,
) -> str:
    """列出当前生效的规则，便于确认检测覆盖范围与自定义规则是否生效。

    List the rules currently in effect — useful to confirm coverage and to check that your
    custom overrides were picked up.
    """
    rs = load_rules()
    wanted = _categories([category] if category else None, set(Category))

    rows: list[str] = []
    for cat in Category:
        if cat not in wanted:
            continue
        content_rules = rs.by_category(cat)
        file_rules = rs.file_rules_for(cat)
        ext_rules = rs.extension_rules_for(cat)
        total = len(content_rules) + len(file_rules) + len(ext_rules)
        rows.append(f"\n### {CATEGORY_LABEL[cat]}（{CATEGORY_HELP.get(cat.value, '')}）共 {total} 条")
        for r in content_rules:
            rows.append(f"- `{r.id}` [{r.severity.value}] {r.description}")
        for r in file_rules:
            rows.append(f"- `{r.id}` [{r.severity.value}] {r.description}（{r.kind}）")
        for r in ext_rules:
            rows.append(f"- `{r.id}` [{r.severity.value}] {r.description}（扩展名 {', '.join(r.extensions[:6])}…）")

    header = f"当前生效规则共 {sum(1 for _ in rs.content_rules) + len(rs.file_rules) + len(rs.extension_rules)} 条。"
    tail = (
        "\n\n自定义方式：\n"
        "- 覆盖单条规则：项目根目录建 `.code-review-mcp-rules.yaml`，"
        "写入 `sensitive: [{id: 规则ID, severity: high, ...}]`\n"
        "- 整体替换某类规则：`~/.code-review-mcp/rules/sensitive.yaml`\n"
        "- 调整阈值等参数：项目根目录 `.code-review-mcp.yaml`\n\n"
        "Overriding:\n"
        "- single rule: create `.code-review-mcp-rules.yaml` in the project root with "
        "`sensitive: [{id: <rule-id>, severity: high, ...}]`\n"
        "- whole category: `~/.code-review-mcp/rules/sensitive.yaml`\n"
        "- thresholds: `.code-review-mcp.yaml` in the project root"
    )
    return header + "\n" + "\n".join(rows) + tail


@mcp.tool()
def export_rules(
    target_dir: Annotated[str, "把内置规则导出到该目录，便于修改后覆盖 / where to write the exported rules"],
) -> str:
    """把内置的规则文件导出成 YAML，便于在项目里定制检测规则。

    Export the built-in rule files as YAML so you can tailor the detection to your project.
    """
    target = _resolve(target_dir)
    try:
        written = export_default_rules(target)
    except OSError as exc:
        return f"❌ 导出失败: {exc}"
    listing = "\n".join(f"- {p}" for p in written)
    return f"✅ 已导出 {len(written)} 个规则文件到 {target}：\n{listing}"


@mcp.tool()
def review_status() -> str:
    """查看服务自身的配置与规则概览（不扫描文件）。

    Show the server's own configuration and a rule inventory without scanning anything.
    """
    cfg = Config.load()
    rs = load_rules()
    status = {
        "config": {
            "max_content_scan_bytes": cfg.max_content_scan_bytes,
            "large_file_warn_bytes": cfg.large_file_warn_bytes,
            "large_file_error_bytes": cfg.large_file_error_bytes,
            "entropy_threshold": cfg.entropy_threshold,
            "exclude_dirs": sorted(cfg.exclude_dirs),
            "defender_enabled": cfg.defender.enabled,
        },
        "rules": {
            "content": len(rs.content_rules),
            "file": len(rs.file_rules),
            "extension": len(rs.extension_rules),
        },
        "categories": [c.value for c in rs.categories()],
    }
    return json.dumps(status, ensure_ascii=False, indent=2)


def main(argv: list[str] | None = None) -> None:
    """启动 MCP 服务。

    默认 stdio（大多数客户端用这个）；`--transport http` 走 streamable-http，
    供只支持 HTTP 的客户端或远程部署使用。
    """
    parser = argparse.ArgumentParser(
        prog="code-review-mcp",
        description="代码审查 MCP 服务 / code review MCP server",
    )
    parser.add_argument(
        "--transport", choices=["stdio", "http"], default="stdio",
        help="stdio（默认，本地客户端）/ http（streamable-http，远程或只支持 HTTP 的客户端）",
    )
    parser.add_argument("--host", default="127.0.0.1", help="HTTP 监听地址")
    parser.add_argument("--port", type=int, default=8765, help="HTTP 监听端口")
    args = parser.parse_args(argv)

    if args.transport == "http":
        mcp.settings.host = args.host
        mcp.settings.port = args.port
        mcp.run(transport="streamable-http")
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
