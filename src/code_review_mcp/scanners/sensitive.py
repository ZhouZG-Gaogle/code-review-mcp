"""敏感信息 / 个人信息扫描。"""

from __future__ import annotations

from typing import Iterator

from ..config import Config
from ..gitdiff import GitContext
from ..models import Category, Finding, Severity, bump_severity
from ..rules import RuleSet
from ..walker import FileEntry
from .content import load_text, scan_rules


def scan_sensitive(
    entries: list[FileEntry],
    rs: RuleSet,
    cfg: Config,
    git: GitContext | None = None,
) -> Iterator[Finding]:
    """扫描敏感信息（密钥 / 令牌 / 私钥）与个人信息。"""
    file_rules = rs.file_rules_for(Category.SENSITIVE) + rs.file_rules_for(Category.PII)
    content_rules = rs.by_category(Category.SENSITIVE) + rs.by_category(Category.PII)

    # ---- 文件级：高危文件名 ----
    for entry in entries:
        tracked = bool(git and git.is_tracked(entry.rel_path))
        for rule in file_rules:
            try:
                hit = rule.compile().search(entry.rel_path)
            except ValueError:
                continue
            if not hit:
                continue
            message = f"文件路径命中规则 {rule.id}"
            severity = rule.severity
            if tracked:
                severity = bump_severity(severity, steps=2 if severity is Severity.CRITICAL else 1)
                message += "；该文件已被提交到 Git，凭据已进入版本历史"
            yield Finding(
                category=rule.category,
                rule_id=rule.id,
                severity=severity,
                description=rule.description,
                path=entry.rel_path,
                message=message,
                recommendation=rule.recommendation,
                extra={"matched": hit.group(0), "git_tracked": tracked},
            )

    # ---- 内容级：正则匹配 ----
    for entry in entries:
        loaded = load_text(entry, cfg)
        if loaded is None:
            continue
        tracked = bool(git and git.is_tracked(entry.rel_path))
        for finding in scan_rules(loaded, content_rules, cfg):
            if tracked:
                finding.severity = bump_severity(finding.severity)
                finding.message += "；该文件已被提交到 Git，凭据已进入版本历史"
                finding.extra["git_tracked"] = True
            yield finding
