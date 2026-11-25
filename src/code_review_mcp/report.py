"""审查报告渲染（Markdown / JSON）。"""

from __future__ import annotations

import json
from typing import Any

from .models import CATEGORY_LABEL, SEVERITY_LABEL, Category, Finding, ScanResult, Severity

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
SEVERITY_ICON = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


def _escape(text: str) -> str:
    return text.replace("`", "'").replace("\n", " ").strip()


def _location(finding: Finding) -> str:
    if finding.line:
        return f"{finding.path}:{finding.line}"
    return finding.path


def render_markdown(result: ScanResult, title: str = "代码审查报告") -> str:
    findings = result.sorted_findings()
    counts = result.counts_by_severity()
    cat_counts = result.counts_by_category()

    lines: list[str] = [f"# {title}", ""]
    lines.append(f"- 审查路径：`{result.root}`")
    lines.append(f"- 审查范围：{result.scope}")
    lines.append(f"- 扫描文件：{result.files_scanned} 个")
    if counts[Severity.CRITICAL.value] or counts[Severity.HIGH.value]:
        verdict = "**不建议直接提交 / 发布**，存在必须先处理的高危问题。"
    elif counts[Severity.MEDIUM.value]:
        verdict = "存在需要关注的问题，建议处理后再提交。"
    else:
        verdict = "未发现明显的高危问题。"
    lines.append(f"- 结论：{verdict}")
    lines.append("")

    # 概览表
    lines.append("## 概览")
    lines.append("")
    lines.append("| 分类 | 严重 | 高危 | 中危 | 低危 | 提示 | 合计 |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: |")
    for category in Category:
        row = [CATEGORY_LABEL[category]]
        total = 0
        for severity in SEVERITY_ORDER:
            n = sum(1 for f in findings if f.category is category and f.severity is severity)
            row.append(str(n))
            total += n
        row.append(f"**{total}**")
        lines.append("| " + " | ".join(row) + " |")
    total_row = ["**合计**"]
    for severity in SEVERITY_ORDER:
        total_row.append(f"**{counts[severity.value]}**")
    total_row.append(f"**{len(findings)}**")
    lines.append("| " + " | ".join(total_row) + " |")
    lines.append("")

    if not findings:
        lines.append("## 详情")
        lines.append("")
        lines.append("未发现符合规则的问题。")
        lines.append("")
    else:
        lines.append("## 详情")
        lines.append("")
        for severity in SEVERITY_ORDER:
            group = [f for f in findings if f.severity is severity]
            if not group:
                continue
            lines.append(f"### {SEVERITY_ICON[severity]} {SEVERITY_LABEL[severity]}（{len(group)}）")
            lines.append("")
            for finding in group:
                lines.append(f"#### {CATEGORY_LABEL[finding.category]} · {_escape(finding.description)}")
                lines.append("")
                lines.append(f"- 位置：`{_location(finding)}`")
                lines.append(f"- 规则：`{finding.rule_id}`")
                if finding.message:
                    lines.append(f"- 说明：{_escape(finding.message)}")
                if finding.evidence:
                    lines.append(f"- 证据：`{_escape(finding.evidence)}`（已脱敏）")
                if finding.extra.get("size_human"):
                    lines.append(f"- 大小：{finding.extra['size_human']}")
                if finding.extra.get("sha256"):
                    lines.append(f"- SHA256：`{finding.extra['sha256']}`")
                if finding.recommendation:
                    lines.append(f"- 建议：{_escape(finding.recommendation)}")
                lines.append("")

    if result.notes:
        lines.append("## 说明")
        lines.append("")
        for note in result.notes:
            lines.append(f"- {note}")
        lines.append("")

    if result.errors:
        lines.append("## 过程中的问题")
        lines.append("")
        for err in result.errors:
            lines.append(f"- {err}")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("> 报告中的证据片段均已脱敏，不会包含密钥原文；文件内容仅在本地读取，未上传任何外部服务。")
    return "\n".join(lines)


def render_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), ensure_ascii=False, indent=2)


def render_summary(result: ScanResult) -> str:
    """一句话摘要，适合放进 CI 输出。"""
    counts = result.counts_by_severity()
    parts = [f"{SEVERITY_LABEL[s]} {counts[s.value]}" for s in SEVERITY_ORDER if counts[s.value]]
    if not parts:
        return f"✅ 审查通过：{result.files_scanned} 个文件，未发现问题。"
    return f"审查 {result.files_scanned} 个文件，发现 {len(result.findings)} 个问题（" + "、".join(parts) + "）。"
