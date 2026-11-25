"""规则本身的完整性：全部正则必须可编译、id 唯一、分类合法。"""

from __future__ import annotations

from code_review_mcp.models import Category
from code_review_mcp.rules import load_rules


def test_all_patterns_compile(rules):
    for rule in rules.content_rules:
        rule.compile()  # 非法正则会抛 ValueError


def test_rule_ids_unique(rules):
    ids = [r.id for r in rules.content_rules]
    assert len(ids) == len(set(ids)), f"规则 id 重复: {[i for i in ids if ids.count(i) > 1]}"


def test_file_rule_ids_unique(rules):
    ids = [r.id for r in rules.file_rules]
    assert len(ids) == len(set(ids))


def test_all_categories_covered(rules):
    covered = {r.category for r in rules.content_rules}
    covered |= {r.category for r in rules.file_rules}
    covered |= {r.category for r in rules.extension_rules}
    for category in Category:
        assert category in covered, f"分类 {category.value} 没有任何规则"


def test_every_category_has_content_rules(rules):
    for category in (Category.SENSITIVE, Category.PII, Category.MALWARE):
        assert rules.by_category(category), f"{category.value} 缺少内容规则"


def test_malware_has_extension_rules(rules):
    assert rules.extension_rules_for(Category.MALWARE)
