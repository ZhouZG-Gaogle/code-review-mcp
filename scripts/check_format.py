"""README 格式体检：连续空行、行尾空白、空引用块、结尾换行。

    uv run python scripts/check_format.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = ("README.md", "README.en.md")


def _is_quote_paragraph_separator(lines: list[str], idx: int) -> bool:
    """引用块里独占一行的 `>` 是段落分隔符，不算空引用块。"""
    for nxt in lines[idx + 1:]:
        if nxt.strip() == "":
            continue
        return nxt.strip().startswith(">")
    return False


def _table_cols(stripped: str) -> int:
    """统计表格列数，忽略转义管道 ``\\|``。"""
    return len(re.findall(r"(?<!\\)\|", stripped))


def check(path: Path) -> list[str]:
    issues: list[str] = []
    raw = path.read_bytes()
    text = raw.decode("utf-8")
    lines = text.split("\n")

    if not raw.endswith(b"\n"):
        issues.append("文件结尾缺少换行")
    if raw.startswith(b"\xef\xbb\xbf"):
        issues.append("文件带 UTF-8 BOM")

    blank = 0
    for i, line in enumerate(lines, start=1):
        if line.strip() == "":
            blank += 1
            continue
        if blank >= 2:
            issues.append(f"L{i - blank}: 连续 {blank} 个空行")
        blank = 0
        if line != line.rstrip():
            issues.append(f"L{i}: 行尾有多余空白")
        if line.strip() == ">" and not _is_quote_paragraph_separator(lines, i - 1):
            issues.append(f"L{i}: 空的引用块")

    # 表格列数一致性
    in_table = False
    header_cols = 0
    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("|"):
            cols = _table_cols(stripped)
            if not in_table:
                in_table = True
                header_cols = cols
            elif cols != header_cols:
                issues.append(f"L{i}: 表格列数 {cols} 与表头 {header_cols} 不一致")
        else:
            in_table = False

    return issues


def main() -> int:
    total = 0
    for name in FILES:
        issues = check(ROOT / name)
        if issues:
            print(f"{name}:")
            for issue in issues:
                print(f"  - {issue}")
            total += len(issues)
        else:
            print(f"{name}: ✓ 无格式问题")
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
