"""审查结果的数据模型。"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Category(str, Enum):
    """审查分类，与用户提出的两条主线一一对应。"""

    SENSITIVE = "sensitive"      # 敏感信息（密钥、口令、令牌）
    PII = "pii"                  # 个人信息
    CACHE = "cache"              # 缓存数据 / 构建产物
    LARGE_FILE = "large_file"    # 大文件
    MALWARE = "malware"          # 病毒文件 / 恶意代码


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

SEVERITY_LABEL: dict[Severity, str] = {
    Severity.CRITICAL: "严重",
    Severity.HIGH: "高危",
    Severity.MEDIUM: "中危",
    Severity.LOW: "低危",
    Severity.INFO: "提示",
}

CATEGORY_LABEL: dict[Category, str] = {
    Category.SENSITIVE: "敏感信息",
    Category.PII: "个人信息",
    Category.CACHE: "缓存数据",
    Category.LARGE_FILE: "大文件",
    Category.MALWARE: "病毒文件",
}

SEVERITY_LADDER: list[Severity] = [
    Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL,
]


def bump_severity(severity: Severity, steps: int = 1) -> Severity:
    """把严重级别往上抬一级（用于「已被提交进 Git」这类加重情节）。"""
    try:
        idx = SEVERITY_LADDER.index(severity)
    except ValueError:
        return severity
    return SEVERITY_LADDER[min(idx + steps, len(SEVERITY_LADDER) - 1)]


@dataclass(slots=True)
class Finding:
    """单条审查发现。"""

    category: Category
    rule_id: str
    severity: Severity
    description: str
    path: str                      # 相对扫描根目录的路径（POSIX 风格）
    message: str = ""
    line: int | None = None
    column: int | None = None
    evidence: str = ""             # 已脱敏的证据片段
    recommendation: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category.value,
            "category_label": CATEGORY_LABEL[self.category],
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "severity_label": SEVERITY_LABEL[self.severity],
            "description": self.description,
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "message": self.message,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "extra": self.extra,
        }


@dataclass
class ScanResult:
    """一次扫描的完整结果。"""

    root: str
    scope: str
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    bytes_scanned: int = 0
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def extend(self, findings: list[Finding]) -> None:
        self.findings.extend(findings)

    def sorted_findings(self) -> list[Finding]:
        return sorted(
            self.findings,
            key=lambda f: (SEVERITY_RANK[f.severity], f.category.value, f.path, f.line or 0),
        )

    def counts_by_severity(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def counts_by_category(self) -> dict[str, int]:
        counts = {c.value: 0 for c in Category}
        for f in self.findings:
            counts[f.category.value] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "scope": self.scope,
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "bytes_scanned": self.bytes_scanned,
            "counts_by_severity": self.counts_by_severity(),
            "counts_by_category": self.counts_by_category(),
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "errors": self.errors,
            "notes": self.notes,
        }
