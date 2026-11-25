"""命令行入口：便于在 CI / 终端里直接跑审查。

    code-review scan <path> [--json out.json] [--severity-min high] [--categories ...]
    code-review diff <repo> [--base origin/main]
    code-review rules [--category malware]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .gitdiff import MODE_BASE, MODE_STAGED, MODE_WORKTREE, list_changed_files
from .models import Category, Severity
from .pipeline import ScanRequest, run_scan
from .report import render_json, render_markdown, render_summary
from .rules import load_rules


def _categories(raw: list[str] | None) -> set[Category]:
    if not raw:
        return set(Category)
    out: set[Category] = set()
    for item in raw:
        try:
            out.add(Category(item.strip().lower()))
        except ValueError:
            print(f"忽略未知分类: {item}", file=sys.stderr)
    return out or set(Category)


def _severity(raw: str | None) -> Severity:
    try:
        return Severity((raw or "info").strip().lower())
    except ValueError:
        return Severity.INFO


def cmd_scan(args: argparse.Namespace) -> int:
    root = Path(args.path).expanduser().resolve()
    if not root.is_dir():
        print(f"路径不存在或不是目录: {root}", file=sys.stderr)
        return 2

    only_files = None
    scope = "directory"
    if args.diff:
        mode = args.diff
        change = list_changed_files(root, mode=mode, base=args.base)
        if change.errors:
            for err in change.errors:
                print(err, file=sys.stderr)
            return 2
        if not change.files:
            print("没有检测到变更文件。")
            return 0
        only_files = change.files
        scope = f"git:{mode}"

    result = run_scan(ScanRequest(
        root=root,
        categories=_categories(args.categories),
        only_files=only_files,
        severity_min=_severity(args.severity_min),
        use_defender=args.defender,
    ))
    result.scope = scope

    if args.json:
        target = Path(args.json).expanduser()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(render_json(result), encoding="utf-8")
        print(f"JSON 报告已写入 {target}", file=sys.stderr)

    if args.quiet:
        print(render_summary(result))
    else:
        print(render_markdown(result))

    counts = result.counts_by_severity()
    if args.fail_on:
        limit = _severity(args.fail_on)
        rank = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
        if any(rank[f.severity] <= rank[limit] for f in result.findings):
            return 1
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    rs = load_rules()
    wanted = _categories([args.category] if args.category else None)
    data = {
        c.value: {
            "content_rules": [r.id for r in rs.by_category(c)],
            "file_rules": [r.id for r in rs.file_rules_for(c)],
            "extension_rules": [r.id for r in rs.extension_rules_for(c)],
        }
        for c in Category if c in wanted
    }
    print(json.dumps(data, ensure_ascii=False, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="code-review", description="代码审查：敏感信息 / 个人信息 / 缓存 / 大文件 / 病毒文件")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="审查目录")
    scan.add_argument("path", help="要审查的目录")
    scan.add_argument("--json", dest="json", help="把 JSON 报告写到该路径")
    scan.add_argument("--severity-min", dest="severity_min", default="info",
                      choices=[s.value for s in Severity], help="只输出不低于该级别的发现")
    scan.add_argument("--categories", nargs="*", help="限定分类")
    scan.add_argument("--diff", choices=[MODE_WORKTREE, MODE_STAGED, MODE_BASE], help="只审查 Git 变更文件")
    scan.add_argument("--base", help="--diff base 时的对比基准")
    scan.add_argument("--defender", action="store_true", help="额外调用本机 Windows Defender")
    scan.add_argument("--fail-on", dest="fail_on", choices=[s.value for s in Severity],
                      help="存在该级别及以上的发现时以退出码 1 结束（CI 用）")
    scan.add_argument("--quiet", action="store_true", help="只输出一行摘要")
    scan.set_defaults(func=cmd_scan)

    rules = sub.add_parser("rules", help="列出规则")
    rules.add_argument("--category", choices=[c.value for c in Category])
    rules.set_defaults(func=cmd_rules)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
