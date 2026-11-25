"""开发辅助脚本：检查规则 YAML 解析情况与 id 唯一性。"""
import pathlib
import sys
from collections import Counter

sys.path.insert(0, str(pathlib.Path("src").resolve()))

import yaml  # noqa: E402

from code_review_mcp.rules import load_rules  # noqa: E402

d = pathlib.Path("src/code_review_mcp/rules")
failed = 0
for f in sorted(d.iterdir()):
    if f.suffix != ".yaml":
        continue
    try:
        data = yaml.safe_load(f.read_text(encoding="utf-8"))
        keys = list(data.keys()) if isinstance(data, dict) else type(data).__name__
        print(f"{f.name}: OK  {keys}")
    except Exception as e:
        failed += 1
        print(f"{f.name}: FAIL {type(e).__name__}")
        print("   ", str(e)[:500])

rs = load_rules()
print(f"\ncontent rules={len(rs.content_rules)} file rules={len(rs.file_rules)} ext rules={len(rs.extension_rules)}")

for label, ids in (
    ("content", [r.id for r in rs.content_rules]),
    ("file", [r.id for r in rs.file_rules]),
    ("ext", [r.id for r in rs.extension_rules]),
):
    dupes = [i for i, n in Counter(ids).items() if n > 1]
    if dupes:
        failed += 1
        print(f"DUPLICATE {label} rule ids: {dupes}")

sys.exit(1 if failed else 0)
