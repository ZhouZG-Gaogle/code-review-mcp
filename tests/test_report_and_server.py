"""报告渲染与服务工具的冒烟测试。"""

from __future__ import annotations

import json
from pathlib import Path

from code_review_mcp.models import Category, Severity
from code_review_mcp.pipeline import ScanRequest, run_scan
from code_review_mcp.report import render_json, render_markdown, render_summary
from code_review_mcp.server import (
    list_rules,
    review_code,
    review_code_snippet,
    review_malware,
    review_sensitive_data,
)

from . import fixtures
from .conftest import write


def test_markdown_contains_overview(repo):
    write(repo, "config.py", f'AWS = "{fixtures.aws_access_key()}"\n')
    result = run_scan(ScanRequest(root=repo, categories=set(Category)))
    md = render_markdown(result)
    assert "## 概览" in md
    assert "AKIA" in md
    assert "已脱敏" in md


def test_json_report_is_serialisable(repo):
    write(repo, "config.py", f'AWS = "{fixtures.aws_access_key()}"\n')
    result = run_scan(ScanRequest(root=repo, categories=set(Category)))
    data = json.loads(render_json(result))
    assert data["counts_by_severity"]["critical"] >= 1
    assert isinstance(data["findings"], list)


def test_summary_line(repo):
    write(repo, "config.py", f'AWS = "{fixtures.aws_access_key()}"\n')
    result = run_scan(ScanRequest(root=repo, categories=set(Category)))
    summary = render_summary(result)
    assert "发现" in summary


def test_tool_sensitive_data(repo):
    write(repo, "config.py", f'AWS = "{fixtures.aws_access_key()}"\n')
    out = review_sensitive_data(str(repo))
    assert "aws-access-key-id" in out


def test_tool_malware(repo):
    write(repo, "bad.sh", fixtures.curl_pipe_shell() + "\n")
    out = review_malware(str(repo))
    assert "malware-curl-pipe-shell" in out


def test_tool_review_code(repo):
    write(repo, "bad.sh", fixtures.curl_pipe_shell() + "\n")
    out = review_code(str(repo))
    assert "代码审查报告" in out


def test_tool_snippet():
    out = review_code_snippet(f'key = "{fixtures.aws_access_key()}"\n', "python")
    assert "aws-access-key-id" in out


def test_tool_list_rules():
    out = list_rules()
    assert "敏感信息" in out
    assert "malware" in out


def test_tool_rejects_bad_path(tmp_path):
    out = review_sensitive_data(str(tmp_path / "nope"))
    assert out.startswith("❌")


def test_severity_filter(repo):
    write(repo, "config.py", f'AWS = "{fixtures.aws_access_key()}"\n')
    result = run_scan(ScanRequest(root=repo, categories=set(Category), severity_min=Severity.CRITICAL))
    assert all(f.severity is Severity.CRITICAL for f in result.findings)


def test_transport_stdio_by_default(monkeypatch):
    """默认走 stdio —— 绝大多数 MCP 客户端用这个。"""
    from code_review_mcp import server

    calls: list[dict] = []
    monkeypatch.setattr(server.mcp, "run", lambda **kw: calls.append(kw))
    server.main([])
    assert calls == [{"transport": "stdio"}]


def test_transport_http_option(monkeypatch):
    """--transport http 走 streamable-http，供只支持 HTTP 的客户端 / 远程部署使用。"""
    from code_review_mcp import server

    calls: list[dict] = []
    monkeypatch.setattr(server.mcp, "run", lambda **kw: calls.append(kw))
    server.main(["--transport", "http", "--host", "0.0.0.0", "--port", "9000"])
    assert calls == [{"transport": "streamable-http"}]
    assert server.mcp.settings.host == "0.0.0.0"
    assert server.mcp.settings.port == 9000


def test_tool_descriptions_are_bilingual():
    """工具描述同时提供中英文，方便不同语言的 agent 正确选型。"""
    from code_review_mcp import server

    for tool in server.mcp._tool_manager.list_tools():
        doc = tool.description or ""
        assert any("一" <= ch <= "鿿" for ch in doc), f"{tool.name} 缺少中文说明"
        assert any("a" <= ch.lower() <= "z" for ch in doc), f"{tool.name} 缺少英文说明"
