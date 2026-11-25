from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_review_mcp.config import Config  # noqa: E402
from code_review_mcp.rules import load_rules  # noqa: E402


@pytest.fixture(scope="session")
def rules():
    return load_rules()


@pytest.fixture
def cfg():
    return Config()


def write(root: Path, rel: str, content: str | bytes) -> Path:
    """在 root 下写入文件（自动建目录），返回路径。"""
    target = root / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        target.write_bytes(content)
    else:
        target.write_text(content, encoding="utf-8")
    return target


@pytest.fixture
def repo(tmp_path):
    return tmp_path
