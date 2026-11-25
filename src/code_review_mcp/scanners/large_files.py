"""大文件 / 二进制制品扫描。"""

from __future__ import annotations

from typing import Iterator

from ..config import Config
from ..models import Category, Finding, Severity
from ..rules import RuleSet
from ..walker import FileEntry


def human_size(num: int) -> str:
    step = 1024.0
    value = float(num)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < step:
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= step
    return f"{value:.1f} PB"


def scan_large_files(
    entries: list[FileEntry],
    rs: RuleSet,
    cfg: Config,
    git: GitContext | None = None,
) -> Iterator[Finding]:
    """报告超过阈值的大文件，以及不该入库的二进制制品。"""
    artifact_rules = rs.extension_rules_for(Category.LARGE_FILE)

    for entry in entries:
        size = entry.size
        tracked = bool(git and git.is_tracked(entry.rel_path))
        if size >= cfg.large_file_error_bytes:
            severity = Severity.HIGH
            level = "严重超限"
        elif size >= cfg.large_file_warn_bytes:
            severity = Severity.MEDIUM
            level = "超限"
        else:
            severity = None
            level = ""

        if severity is not None:
            message = f"文件大小 {human_size(size)}，{level}（告警阈值 {human_size(cfg.large_file_warn_bytes)}）。"
            if tracked:
                message += " 该文件已被提交到 Git，仓库体积会持续增长且历史难以清理。"
            yield Finding(
                category=Category.LARGE_FILE,
                rule_id="large-file",
                severity=severity,
                description="大文件",
                path=entry.rel_path,
                message=message,
                recommendation=(
                    "建议改用制品库 / 对象存储 / Git LFS 分发，"
                    "或确认该文件是否本就该入库（模型权重、数据集、媒体素材等）。"
                ),
                extra={"size_bytes": size, "size_human": human_size(size), "git_tracked": tracked},
            )

        for rule in artifact_rules:
            if entry.suffix in rule.extensions:
                yield Finding(
                    category=Category.LARGE_FILE,
                    rule_id=rule.id,
                    severity=rule.severity,
                    description=rule.description,
                    path=entry.rel_path,
                    message=f"仓库中包含二进制制品 {entry.suffix}（{human_size(size)}）。",
                    recommendation=rule.recommendation,
                    extra={"size_bytes": size, "size_human": human_size(size)},
                )
                break
