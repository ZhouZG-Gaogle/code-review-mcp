"""内容扫描引擎：把正则规则跑在文本文件上，产出带行号的发现。"""

from __future__ import annotations

import bisect
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

from ..binary import decode_text
from ..config import Config
from ..models import Category, Finding, Severity
from ..redactor import is_placeholder, redact
from ..rules import Rule
from ..validators import apply_validator
from ..walker import FileEntry

MAX_MATCHES_PER_RULE = 20

_HEX_CHARS = "0123456789abcdefABCDEF"

# 规则定义文件的特征：数据文件 + 若干规则字段
_RULEBOOK_HINT = re.compile(
    r"^\s*(?:-\s+)?(?:id|pattern|severity|prefilter|validator|recommendation)\s*:",
    re.MULTILINE,
)
_RULEBOOK_EXTENSIONS = {".yaml", ".yml", ".json", ".toml", ".cfg", ".ini"}


def looks_like_rulebook(text: str, suffix: str) -> bool:
    """判断一个文件是否「规则定义文件」。

    规则书里必然写着检测特征串，用它自己的规则扫自己必然命中。
    识别出来并降级，避免用户自定义规则文件产生噪音告警。
    """
    if suffix.lower() not in _RULEBOOK_EXTENSIONS:
        return False
    return len(_RULEBOOK_HINT.findall(text)) >= 3


def _in_hash_context(text: str, start: int, end: int) -> bool:
    """判断命中值是否落在哈希 / 长十六进制串内部。

    ``uv.lock``、``package-lock.json`` 这类文件里全是 sha256，
    里面天然会出现「11 位数字」「16~19 位数字」，
    不加这道守卫会被误判成手机号 / 银行卡号。
    """
    i = start
    while i > 0 and text[i - 1].isalnum():
        i -= 1
    j = end
    n = len(text)
    while j < n and text[j].isalnum():
        j += 1
    if len(text[i:j]) >= 32:
        return True
    before = text[i - 1] if i > 0 else ""
    after = text[j] if j < n else ""
    if before and before in _HEX_CHARS:
        return True
    if after and after in _HEX_CHARS:
        return True
    return False


@dataclass
class LoadedFile:
    """已读入内存的文本文件。"""

    entry: FileEntry
    text: str
    line_starts: list[int]

    def line_of(self, offset: int) -> int:
        """把字符偏移换算成 1-based 行号。"""
        return bisect.bisect_right(self.line_starts, offset)

    def line_text(self, line_no: int) -> str:
        if line_no < 1 or line_no > len(self.line_starts):
            return ""
        start = self.line_starts[line_no - 1]
        end = (
            self.line_starts[line_no]
            if line_no < len(self.line_starts)
            else len(self.text)
        )
        return self.text[start:end].strip()


def load_text(entry: FileEntry, cfg: Config) -> LoadedFile | None:
    """读取文本内容；非文本或过大时返回 None。"""
    if entry.size > cfg.max_content_scan_bytes:
        return None
    try:
        data = entry.path.read_bytes()
    except OSError:
        return None
    if not data:
        return None

    text = decode_text(data)
    if text is None:
        return None

    line_starts = [0]
    for idx, ch in enumerate(text):
        if ch == "\n":
            line_starts.append(idx + 1)
    return LoadedFile(entry=entry, text=text, line_starts=line_starts)


def _prefilter_hit(prefilter: str | None, lowered: str) -> bool:
    """预筛：任一子串命中即可。多子串用 | 分隔。"""
    if not prefilter:
        return True
    return any(alt and alt.lower() in lowered for alt in prefilter.split("|"))


def scan_rules(
    loaded: LoadedFile,
    rules: Iterable[Rule],
    cfg: Config,
    category: Category | None = None,
) -> Iterator[Finding]:
    """对单个文件跑一批规则。"""
    entry = loaded.entry
    lowered = loaded.text.lower()
    # 规则定义文件里的命中是「自指」，降级为提示
    rulebook = looks_like_rulebook(loaded.text, entry.suffix)

    for rule in rules:
        if not rule.enabled:
            continue
        if category is not None and rule.category is not category:
            continue
        if not rule.applies_to(entry.rel_path, entry.suffix):
            continue
        if not _prefilter_hit(rule.prefilter, lowered):
            continue
        try:
            pattern = rule.compile()
        except ValueError:
            continue

        matched = 0
        truncated = False
        # 只有「捕获组里的值」才做占位符判定与校验器验证；
        # 没有捕获组的规则是结构性特征串（如下载即执行），不能拿占位符逻辑去卡。
        has_group = pattern.groups >= rule.match_group
        for m in pattern.finditer(loaded.text):
            if matched >= MAX_MATCHES_PER_RULE:
                truncated = True
                break
            value = m.group(rule.match_group) if has_group else m.group(0)
            if not value:
                continue
            if has_group:
                if not apply_validator(rule.validator, value):
                    continue
                if not cfg.report_placeholders and is_placeholder(value):
                    continue
            if rule.hash_guard and _in_hash_context(loaded.text, m.start(), m.end()):
                continue

            line_no = loaded.line_of(m.start())
            severity = Severity.INFO if rulebook else rule.severity
            message = f"命中规则 {rule.id}"
            if rulebook:
                message += "；该文件疑似规则定义文件，命中属预期"
            yield Finding(
                category=rule.category,
                rule_id=rule.id,
                severity=severity,
                description=rule.description,
                path=entry.rel_path,
                line=line_no,
                column=m.start() - (loaded.line_starts[line_no - 1] if line_no >= 1 else 0) + 1,
                message=message,
                evidence=redact(value),
                recommendation=rule.recommendation,
                extra={"rule_description": rule.description, "rulebook": rulebook},
            )
            matched += 1

        if truncated:
            yield Finding(
                category=rule.category,
                rule_id=f"{rule.id}:truncated",
                severity=Severity.INFO,
                description=f"规则 {rule.id} 命中过多，已截断",
                path=entry.rel_path,
                message=f"该文件内 {rule.id} 命中超过 {MAX_MATCHES_PER_RULE} 次，仅展示前 {MAX_MATCHES_PER_RULE} 条",
                recommendation="请人工打开该文件确认全貌。",
            )
