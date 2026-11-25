"""大文件与二进制制品检测。"""

from __future__ import annotations

from pathlib import Path

from code_review_mcp.config import Config
from code_review_mcp.models import Category, Severity
from code_review_mcp.pipeline import ScanRequest, run_scan

from .conftest import write


def _run(root: Path, cfg: Config | None = None):
    return run_scan(ScanRequest(root=root, categories={Category.LARGE_FILE}, config=cfg))


def test_detects_large_file(repo):
    write(repo, "data.bin", b"x" * (2 * 1024 * 1024))
    result = _run(repo)
    large = [f for f in result.findings if f.rule_id == "large-file"]
    assert large
    assert large[0].severity is Severity.MEDIUM


def test_detects_huge_file_as_high(repo):
    write(repo, "dump.bin", b"x" * (6 * 1024 * 1024))
    result = _run(repo)
    large = [f for f in result.findings if f.rule_id == "large-file"]
    assert large and large[0].severity is Severity.HIGH


def test_small_file_not_reported(repo):
    write(repo, "small.txt", "hello")
    result = _run(repo)
    assert not [f for f in result.findings if f.rule_id == "large-file"]


def test_binary_artifact_reported(repo):
    write(repo, "app.zip", b"PK\x03\x04" + b"0" * 100)
    result = _run(repo)
    assert any(f.rule_id == "malware-artifact-archive" for f in result.findings)


def test_model_weights_reported(repo):
    write(repo, "model.onnx", b"0" * 100)
    result = _run(repo)
    assert any(f.rule_id == "malware-artifact-model" for f in result.findings)


def test_threshold_configurable(repo):
    cfg = Config()
    cfg.large_file_warn_bytes = 100
    cfg.large_file_error_bytes = 200
    write(repo, "small.txt", "x" * 300)
    result = _run(repo, cfg)
    assert any(f.rule_id == "large-file" for f in result.findings)
