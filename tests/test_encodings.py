"""文本编码处理。

回归背景：早期版本按「可打印字节比例」判断二进制，UTF-8 中文文件
（多字节序列 ≥ 0x80）被整体判成二进制跳过 —— 中文代码库等于没扫。
现在判定改为解码之后做，这组用例锁住该行为。
"""

from __future__ import annotations

from pathlib import Path

from code_review_mcp.binary import decode_text
from code_review_mcp.models import Category
from code_review_mcp.pipeline import ScanRequest, run_scan

from . import fixtures
from .conftest import write

SECRET = fixtures.aws_access_key()


def _run(root: Path):
    return run_scan(ScanRequest(root=root, categories={Category.SENSITIVE}))


def test_utf8_chinese_file_is_scanned(repo):
    write(repo, "config.py", f'# 数据库连接配置\nAWS_KEY = "{SECRET}"\n')
    result = _run(repo)
    ids = {f.rule_id for f in result.findings}
    assert "aws-access-key-id" in ids


def test_utf8_chinese_only_file_is_scanned(repo):
    write(repo, "说明.md", "# 说明\n\n这里是一段中文文档，用来验证不会被误判为二进制。\n")
    result = _run(repo)
    # 至少不应抛错，且不应把文件当成二进制
    assert not result.errors


def test_gb18030_file_is_scanned(repo):
    target = repo / "legacy.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(f'# 老项目\nAWS_KEY = "{SECRET}"\n'.encode("gb18030"))
    result = _run(repo)
    ids = {f.rule_id for f in result.findings}
    assert "aws-access-key-id" in ids


def test_utf16_file_is_scanned(repo):
    target = repo / "wide.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(f'AWS_KEY = "{SECRET}"\n'.encode("utf-16"))
    result = _run(repo)
    ids = {f.rule_id for f in result.findings}
    assert "aws-access-key-id" in ids


def test_binary_file_is_skipped_not_crashed(repo):
    target = repo / "blob.bin"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(bytes(range(256)) * 40)
    result = _run(repo)
    assert not result.errors


def test_decode_text_returns_none_for_binary():
    assert decode_text(b"\x00\x01\x02\x03binary\x00") is None


def test_decode_text_handles_chinese():
    text = decode_text("中文内容".encode("utf-8"))
    assert text == "中文内容"


def test_decode_text_handles_gb18030():
    text = decode_text("中文内容".encode("gb18030"))
    assert text == "中文内容"
