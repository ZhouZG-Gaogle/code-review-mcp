"""规则加载与合并。

规则全部以 YAML 描述，内置一套默认值，并允许在用户目录 / 项目目录下覆盖：

- 整文件覆盖：``~/.code-review-mcp/rules/sensitive.yaml``
- 按 id 覆盖：``<项目>/.code-review-mcp-rules.yaml``，形如 ``sensitive: [{id: xxx, ...}]``
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import yaml

from .models import Category, Severity

RULES_DIR = Path(__file__).parent / "rules"
USER_RULES_DIR = Path.home() / ".code-review-mcp" / "rules"
PROJECT_RULES_NAME = ".code-review-mcp-rules.yaml"

_FLAG_MAP = {
    "ignorecase": re.IGNORECASE,
    "i": re.IGNORECASE,
    "multiline": re.MULTILINE,
    "m": re.MULTILINE,
    "dotall": re.DOTALL,
    "s": re.DOTALL,
    "unicode": re.UNICODE,
    "u": re.UNICODE,
}


def _severity(value: Any, default: Severity = Severity.MEDIUM) -> Severity:
    try:
        return Severity(str(value).lower())
    except ValueError:
        return default


@dataclass
class Rule:
    """一条内容匹配规则。"""

    id: str
    category: Category
    severity: Severity
    description: str
    pattern: str
    recommendation: str = ""
    flags: tuple[str, ...] = ()
    prefilter: str | None = None
    validator: str | None = None
    extensions: tuple[str, ...] | None = None
    exclude_dirs: tuple[str, ...] = ()
    match_group: int = 1
    hash_guard: bool = False
    enabled: bool = True
    _compiled: re.Pattern[str] | None = field(default=None, repr=False, compare=False)

    def compile(self) -> re.Pattern[str]:
        if self._compiled is None:
            flag_value = 0
            for flag in self.flags:
                flag_value |= _FLAG_MAP.get(flag.lower(), 0)
            try:
                self._compiled = re.compile(self.pattern, flag_value)
            except re.error as exc:
                raise ValueError(f"规则 {self.id} 正则无效: {exc}") from exc
        return self._compiled

    def applies_to(self, rel_path: str, suffix: str) -> bool:
        if self.extensions and suffix.lower() not in self.extensions:
            return False
        if self.exclude_dirs:
            parts = {p.lower() for p in rel_path.replace("\\", "/").split("/")}
            if parts & {d.lower() for d in self.exclude_dirs}:
                return False
        return True


@dataclass
class FileRule:
    """基于路径 / 文件名 / 内容特征的规则（缓存产物、敏感文件、可疑文件名）。"""

    id: str
    category: Category
    kind: str                     # dir | file | path | content | keyword
    pattern: str
    description: str
    severity: Severity = Severity.LOW
    recommendation: str = ""
    min_size: int = 0
    _compiled: re.Pattern[str] | None = field(default=None, repr=False, compare=False)

    def compile(self) -> re.Pattern[str]:
        if self._compiled is None:
            try:
                self._compiled = re.compile(self.pattern)
            except re.error as exc:
                raise ValueError(f"规则 {self.id} 正则无效: {exc}") from exc
        return self._compiled


@dataclass
class ExtensionRule:
    """基于文件扩展名的规则。"""

    id: str
    category: Category
    kind: str                     # executable | script | artifact
    extensions: tuple[str, ...]
    description: str
    severity: Severity = Severity.MEDIUM
    recommendation: str = ""


@dataclass
class RuleSet:
    content_rules: list[Rule] = field(default_factory=list)
    file_rules: list[FileRule] = field(default_factory=list)
    extension_rules: list[ExtensionRule] = field(default_factory=list)

    def by_category(self, category: Category) -> list[Rule]:
        return [r for r in self.content_rules if r.category is category]

    def file_rules_for(self, category: Category) -> list[FileRule]:
        return [r for r in self.file_rules if r.category is category]

    def extension_rules_for(self, category: Category) -> list[ExtensionRule]:
        return [r for r in self.extension_rules if r.category is category]

    def categories(self) -> list[Category]:
        found = {r.category for r in self.content_rules}
        found.update(r.category for r in self.file_rules)
        found.update(r.category for r in self.extension_rules)
        return sorted(found, key=lambda c: c.value)


# ---------------------------------------------------------------- 加载


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return {}
    return raw if isinstance(raw, dict) else {}


def _rule_from_dict(data: dict[str, Any], default_category: Category) -> Rule | None:
    try:
        category = Category(data.get("category", default_category.value))
    except ValueError:
        category = default_category
    rule_id = str(data.get("id") or "").strip()
    pattern = data.get("pattern")
    if not rule_id or not pattern:
        return None
    return Rule(
        id=rule_id,
        category=category,
        severity=_severity(data.get("severity")),
        description=str(data.get("description", rule_id)),
        pattern=str(pattern),
        recommendation=str(data.get("recommendation", "")),
        flags=tuple(str(f) for f in (data.get("flags") or [])),
        prefilter=(str(data["prefilter"]) if data.get("prefilter") else None),
        validator=(str(data["validator"]) if data.get("validator") else None),
        extensions=tuple(str(e).lower() for e in data["extensions"]) if data.get("extensions") else None,
        exclude_dirs=tuple(str(d) for d in (data.get("exclude_dirs") or [])),
        match_group=int(data.get("match_group", 1)),
        hash_guard=bool(data.get("hash_guard", False)),
        enabled=bool(data.get("enabled", True)),
    )


def _file_rule_from_dict(data: dict[str, Any], category: Category, kind: str) -> FileRule | None:
    rule_id = str(data.get("id") or "").strip()
    pattern = data.get("pattern")
    if not pattern:
        return None
    return FileRule(
        id=rule_id or f"{category.value}-{kind}-{pattern}",
        category=category,
        kind=str(data.get("kind", kind)),
        pattern=str(pattern),
        description=str(data.get("description", rule_id or kind)),
        severity=_severity(data.get("severity"), Severity.LOW),
        recommendation=str(data.get("recommendation", "")),
        min_size=int(data.get("min_size", 0) or 0),
    )


def _extension_rules_from(data: dict[str, Any], category: Category) -> list[ExtensionRule]:
    rules: list[ExtensionRule] = []
    groups = (
        ("executable_extensions", "executable", category),
        ("script_extensions", "script", category),
        ("binary_artifacts", "artifact", Category.LARGE_FILE),
    )
    for key, kind, group_category in groups:
        for item in data.get(key, []) or []:
            if not isinstance(item, dict):
                continue
            exts = tuple(str(e).lower() for e in (item.get("extensions") or []))
            if not exts:
                continue
            rules.append(ExtensionRule(
                id=str(item.get("id") or f"malware-ext-{kind}"),
                category=group_category,
                kind=kind,
                extensions=exts,
                description=str(item.get("description", "可疑文件类型")),
                severity=_severity(item.get("severity"), Severity.MEDIUM),
                recommendation=str(item.get("recommendation", "")),
            ))
    return rules


def load_rules(project_root: Path | None = None) -> RuleSet:
    """加载全部规则（默认 + 用户覆盖 + 项目覆盖）。"""
    rs = RuleSet()

    sensitive = _load_yaml(RULES_DIR / "sensitive.yaml")
    pii = _load_yaml(RULES_DIR / "pii.yaml")
    malware = _load_yaml(RULES_DIR / "malware.yaml")
    cache = _load_yaml(RULES_DIR / "cache.yaml")

    rs.content_rules.extend(_rules_from(sensitive, Category.SENSITIVE))
    rs.content_rules.extend(_rules_from(pii, Category.PII))
    rs.content_rules.extend(_rules_from(malware, Category.MALWARE))

    # 文件 / 路径级规则
    for item in sensitive.get("sensitive_files", []) or []:
        rule = _file_rule_from_dict(item, Category.SENSITIVE, "path")
        if rule:
            rs.file_rules.append(rule)
    for item in pii.get("pii_files", []) or []:
        rule = _file_rule_from_dict(item, Category.PII, "path")
        if rule:
            rs.file_rules.append(rule)
    for name in cache.get("dirs", []) or []:
        rs.file_rules.append(FileRule(
            id=f"cache-dir-{name}",
            category=Category.CACHE,
            kind="dir",
            pattern=str(name),
            description=f"缓存 / 构建目录 {name}",
            severity=Severity.LOW,
            recommendation="确认该目录未被提交到版本库，建议加入 .gitignore 并在 CI 中清理。",
        ))
    for item in cache.get("files", []) or []:
        rule = _file_rule_from_dict(item, Category.CACHE, "file")
        if rule:
            rs.file_rules.append(rule)
    for item in cache.get("content", []) or []:
        # 内容特征走内容扫描引擎，因此转成 Rule
        if not isinstance(item, dict):
            continue
        data = dict(item)
        data.setdefault("category", Category.CACHE.value)
        rule = _rule_from_dict(data, Category.CACHE)
        if rule is not None:
            rs.content_rules.append(rule)
    for item in malware.get("filename_keywords", []) or []:
        rule = _file_rule_from_dict(item, Category.MALWARE, "keyword")
        if rule:
            rs.file_rules.append(rule)

    rs.extension_rules.extend(_extension_rules_from(malware, Category.MALWARE))

    # 用户级整文件覆盖
    for category, target in (
        (Category.SENSITIVE, rs.content_rules),
        (Category.PII, rs.content_rules),
        (Category.MALWARE, rs.content_rules),
    ):
        _apply_overrides(_load_yaml(USER_RULES_DIR / f"{category.value}.yaml"), category, target)

    # 项目级按 id 覆盖
    if project_root is not None:
        project_overrides = _load_yaml(project_root / PROJECT_RULES_NAME)
        for category, target in (
            (Category.SENSITIVE, rs.content_rules),
            (Category.PII, rs.content_rules),
            (Category.MALWARE, rs.content_rules),
        ):
            _apply_overrides(project_overrides.get(category.value, {}), category, target)

    return rs


def _rules_from(data: dict[str, Any], category: Category) -> list[Rule]:
    out: list[Rule] = []
    for item in data.get("rules", []) or []:
        if isinstance(item, dict):
            rule = _rule_from_dict(item, category)
            if rule is not None:
                out.append(rule)
    return out


def _apply_overrides(data: Any, category: Category, target: list[Rule]) -> None:
    """按 id 覆盖已有规则；`enabled: false` 表示停用；未知 id 视为新增规则。"""
    if isinstance(data, dict):
        items: Iterable[Any] = data.get("rules", []) or []
    elif isinstance(data, list):
        items = data
    else:
        return
    for item in items:
        if not isinstance(item, dict):
            continue
        rule = _rule_from_dict(item, category)
        if rule is None:
            continue
        existing = next((r for r in target if r.id == rule.id), None)
        if existing is None:
            target.append(rule)
        else:
            target[target.index(existing)] = rule


def export_default_rules(target_dir: Path) -> list[Path]:
    """把内置规则导出到目录，供用户修改。"""
    target_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for src in sorted(RULES_DIR.glob("*.yaml")):
        dst = target_dir / src.name
        dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
        written.append(dst)
    return written
