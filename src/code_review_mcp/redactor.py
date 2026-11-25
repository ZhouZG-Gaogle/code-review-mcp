"""敏感内容脱敏。

审查报告会被贴进聊天记录 / CI 日志，因此绝不能把密钥原文写出去。
所有命中片段在进入 Finding 之前先经过这里。
"""

from __future__ import annotations

import re

# 明显是占位符 / 示例值的标记，命中后不应当当作真实密钥上报。
# 注意：这些判定只作用于「值」（捕获组），不作用于结构性特征串。
PLACEHOLDER_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^\$?\{[^}]*\}$"),
    re.compile(r"^<[^>]*>$"),
    re.compile(r"^\{\{[^}]*\}\}$"),
    re.compile(r"^(%[A-Za-z0-9_]+%)$"),
    re.compile(r"^(process\.env\.[\w.]+|os\.environ(\[[^\]]*\])?|ENV\[[^\]]*\])$"),
    re.compile(r"^(your|my|the|some|any|change|replace)[-_ ]", re.I),
    re.compile(r"^[Xx]{4,}$"),
    re.compile(r"^\*{3,}$"),
    re.compile(r"^test[-_](?:key|token|secret|password|user)", re.I),
    re.compile(r"^dummy", re.I),
    # 占位符关键词必须落在词边界上：形如「AKIA」开头的 20 位示例串不能被误判
    re.compile(
        r"(?<![A-Za-z0-9])(?:placeholder|dummy|fake|sample|redacted|changeme|example"
        r"|insert[_-]?here|todo|fixme)(?![A-Za-z0-9])",
        re.I,
    ),
    re.compile(
        r"(?<![A-Za-z0-9])(?:example|test|foo|bar)\.(?:com|org|net)(?![A-Za-z0-9])",
        re.I,
    ),
    re.compile(r"^(none|null|nil|undefined|true|false|empty)$", re.I),
]


def is_placeholder(value: str) -> bool:
    """判断一个匹配片段是否只是占位符/示例值。"""
    if not value:
        return True
    v = value.strip()
    if len(v) < 6:
        return True
    return any(p.search(v) for p in PLACEHOLDER_PATTERNS)


def redact(value: str, keep_prefix: int = 4, keep_suffix: int = 2) -> str:
    """保留少量首尾字符，其余用 * 遮盖，用于确认「是哪一类密钥」而不泄露内容。"""
    if not value:
        return ""
    v = value.strip()
    if len(v) <= keep_prefix + keep_suffix + 2:
        return v[:1] + "*" * max(0, len(v) - 1)
    hidden = "*" * min(12, len(v) - keep_prefix - keep_suffix)
    return f"{v[:keep_prefix]}{hidden}{v[-keep_suffix:]}"


def redact_path(path: str) -> str:
    """路径本身不含机密，仅做规范化。"""
    return path.replace("\\", "/")
