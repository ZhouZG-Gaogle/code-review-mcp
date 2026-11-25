"""对比 README.md 与 README.en.md 的结构是否对齐。

检查：标题序列、表格行数、代码块数量、链接集合是否一致。
用于保证两份文档同步维护。
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def headings(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.startswith("#")]


def table_rows(text: str) -> int:
    return sum(1 for line in text.splitlines() if line.strip().startswith("|"))


def code_blocks(text: str) -> int:
    return sum(1 for line in text.splitlines() if line.strip().startswith("```"))


def links(text: str) -> set[str]:
    # 语言切换链接两边本来就指向对方，单独排除
    return {u for u in re.findall(r"\[[^\]]+\]\(([^)]+)\)", text)
            if u not in ("README.md", "README.en.md")}


def main() -> int:
    cn = (ROOT / "README.md").read_text(encoding="utf-8")
    en = (ROOT / "README.en.md").read_text(encoding="utf-8")

    problems: list[str] = []

    cn_h, en_h = headings(cn), headings(en)
    if len(cn_h) != len(en_h):
        problems.append(f"标题数量不同: cn={len(cn_h)} en={len(en_h)}")
    for i, (a, b) in enumerate(zip(cn_h, en_h)):
        if a.count("#") != b.count("#"):
            problems.append(f"第 {i+1} 个标题层级不同: {a!r} vs {b!r}")

    if table_rows(cn) != table_rows(en):
        problems.append(f"表格行数不同: cn={table_rows(cn)} en={table_rows(en)}")
    if code_blocks(cn) != code_blocks(en):
        problems.append(f"代码块数量不同: cn={code_blocks(cn)} en={code_blocks(en)}")

    cn_links, en_links = links(cn), links(en)
    if cn_links != en_links:
        problems.append(f"链接集合不同:\n  仅 cn: {cn_links - en_links}\n  仅 en: {en_links - cn_links}")

    print(f"标题 {len(cn_h)}/{len(en_h)}  表格行 {table_rows(cn)}/{table_rows(en)}  "
          f"代码块 {code_blocks(cn)//2}/{code_blocks(en)//2}  链接 {len(cn_links)}/{len(en_links)}")

    if problems:
        print("\n差异：")
        for p in problems:
            print("  -", p)
        return 1
    print("✓ 两份 README 结构一致")
    return 0


if __name__ == "__main__":
    sys.exit(main())
