"""个人信息检测。"""

from __future__ import annotations

from pathlib import Path

from code_review_mcp.models import Category
from code_review_mcp.pipeline import ScanRequest, run_scan

from . import fixtures
from .conftest import write


def _run(root: Path):
    return run_scan(ScanRequest(root=root, categories={Category.PII}))


def test_detects_mobile_with_context(repo):
    write(repo, "user.py", f'phone = "{fixtures.cn_mobile()}"\n')
    result = _run(repo)
    ids = {f.rule_id for f in result.findings}
    assert "pii-cn-mobile-labeled" in ids


def test_detects_id_card(repo):
    write(repo, "user.py", f'id_no = "{fixtures.cn_id_card()}"\n')
    result = _run(repo)
    ids = {f.rule_id for f in result.findings}
    assert "pii-cn-id-card" in ids


def test_invalid_id_card_checksum_ignored(repo):
    write(repo, "user.py", f'id_no = "{fixtures.cn_id_card_bad_checksum()}"\n')
    result = _run(repo)
    ids = {f.rule_id for f in result.findings}
    assert "pii-cn-id-card" not in ids


def test_detects_bank_card(repo):
    write(repo, "pay.py", f'card = "{fixtures.bank_card()}"\n')
    result = _run(repo)
    ids = {f.rule_id for f in result.findings}
    assert "pii-cn-bank-card" in ids


def test_luhn_failure_ignored(repo):
    write(repo, "pay.py", f'card = "{fixtures.bank_card_bad_checksum()}"\n')
    result = _run(repo)
    ids = {f.rule_id for f in result.findings}
    assert "pii-cn-bank-card" not in ids


def test_detects_email(repo):
    write(repo, "crm.py", f'owner = "{fixtures.real_looking_email()}"\n')
    result = _run(repo)
    ids = {f.rule_id for f in result.findings}
    assert "pii-email-address" in ids


def test_example_email_ignored(repo):
    write(repo, "crm.py", f'owner = "{fixtures.example_email()}"\n')
    result = _run(repo)
    ids = {f.rule_id for f in result.findings}
    assert "pii-email-address" not in ids


def test_hash_digits_not_mistaken_for_pii(repo):
    """sha256 里的数字串不应被误判成卡号 / 手机号。"""
    digest = "f3d6ed6a98cfd19155996605474982cc470d7601746a6439078f1a5a3fa8b050"
    write(repo, "uv.lock", f'hash = "sha256:{digest}"\n')
    result = _run(repo)
    ids = {f.rule_id for f in result.findings}
    assert "pii-cn-bank-card" not in ids
    assert "pii-cn-mobile-bare" not in ids


def test_real_card_still_detected_next_to_text(repo):
    write(repo, "pay.py", f'card = "{fixtures.bank_card()}"\n')
    result = _run(repo)
    ids = {f.rule_id for f in result.findings}
    assert "pii-cn-bank-card" in ids
