"""缓存数据与构建产物检测。"""

from __future__ import annotations

from pathlib import Path

from code_review_mcp.models import Category
from code_review_mcp.pipeline import ScanRequest, run_scan

from .conftest import write


def _run(root: Path):
    return run_scan(ScanRequest(root=root, categories={Category.CACHE}))


def test_detects_pycache_dir(repo):
    write(repo, "src/__pycache__/mod.cpython-312.pyc", "x")
    result = _run(repo)
    ids = {f.rule_id for f in result.findings}
    assert any(i.startswith("cache-dir-__pycache__") for i in ids)


def test_detects_pyc_file(repo):
    write(repo, "mod.pyc", "not really bytecode")
    result = _run(repo)
    ids = {f.rule_id for f in result.findings}
    assert "cache-python-bytecode" in ids


def test_detects_log_file(repo):
    write(repo, "app.log", "some log output")
    result = _run(repo)
    ids = {f.rule_id for f in result.findings}
    assert "cache-log-file" in ids


def test_detects_minified_line(repo):
    write(repo, "bundle.js", "var a=1;" * 800)
    result = _run(repo)
    ids = {f.rule_id for f in result.findings}
    assert "cache-minified-line" in ids


def test_detects_embedded_blob(repo):
    write(repo, "data.py", 'BLOB = "' + "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=" * 40 + '"')
    result = _run(repo)
    ids = {f.rule_id for f in result.findings}
    assert "cache-embedded-blob" in ids


def test_clean_repo_has_no_cache_findings(repo):
    write(repo, "main.py", "print('hello')\n")
    write(repo, "README.md", "# 项目\n")
    result = _run(repo)
    assert not result.findings


def test_node_modules_probed_even_if_excluded(repo):
    (repo / "node_modules" / "left-pad").mkdir(parents=True)
    (repo / "node_modules" / "left-pad" / "index.js").write_text("x", encoding="utf-8")
    result = _run(repo)
    ids = {f.rule_id for f in result.findings}
    assert "cache-dir-node_modules" in ids
