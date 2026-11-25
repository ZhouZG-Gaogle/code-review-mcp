"""子进程调用安全性。

MCP stdio 服务把 stdin 当作 JSON-RPC 管道。任何子进程如果继承了它，
就可能阻塞等待输入，把整条协议流挂死（表现为工具调用超时）。
因此所有子进程都必须显式切断 stdin。
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from code_review_mcp.gitdiff import _git, is_git_repo, tracked_files
from code_review_mcp.scanners import defender


def _capture_run(monkeypatch):
    calls: list[dict] = []

    def fake_run(args, **kwargs):
        calls.append({"args": args, "kwargs": kwargs})
        raise FileNotFoundError("stub")

    monkeypatch.setattr(subprocess, "run", fake_run)
    return calls


def test_git_uses_devnull_stdin(monkeypatch, tmp_path):
    calls = _capture_run(monkeypatch)
    _git(tmp_path, ["rev-parse", "--is-inside-work-tree"])
    assert calls
    assert calls[0]["kwargs"].get("stdin") is subprocess.DEVNULL


def test_powershell_uses_devnull_stdin(monkeypatch):
    calls = _capture_run(monkeypatch)
    defender._run_powershell("Get-Date")
    assert calls
    assert calls[0]["kwargs"].get("stdin") is subprocess.DEVNULL


def test_defender_scan_uses_devnull_stdin(monkeypatch, tmp_path):
    calls = _capture_run(monkeypatch)
    monkeypatch.setattr(defender, "_find_mpcmdrun", lambda: "MpCmdRun.exe")
    defender.scan_paths([str(tmp_path)], defender.DefenderConfig())
    assert calls
    assert calls[0]["kwargs"].get("stdin") is subprocess.DEVNULL


def test_git_helpers_degrade_gracefully(monkeypatch, tmp_path):
    """git 不可用时不能抛异常，应退化成「无 Git 状态」。"""
    _capture_run(monkeypatch)
    assert is_git_repo(tmp_path) is False
    assert tracked_files(tmp_path) is None
