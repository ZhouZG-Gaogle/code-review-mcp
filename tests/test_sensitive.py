"""敏感信息检测。"""

from __future__ import annotations

from pathlib import Path

from code_review_mcp.models import Category, Severity
from code_review_mcp.pipeline import ScanRequest, run_scan

from . import fixtures
from .conftest import write


def _secret_code() -> str:
    return "\n".join([
        "import os",
        "",
        f'AWS_KEY = "{fixtures.aws_access_key()}"',
        f'GITHUB = "{fixtures.github_token()}"',
        f'SLACK = "{fixtures.slack_token()}"',
        "",
        f'conn = "{fixtures.db_url()}"',
        "",
        "PRIVATE = \"\"\"" + fixtures.private_key_block() + "\"\"\"",
        "",
    ])


def _run(root: Path):
    return run_scan(ScanRequest(root=root, categories={Category.SENSITIVE}))


def test_detects_common_secrets(repo):
    write(repo, "config.py", _secret_code())
    result = _run(repo)
    rule_ids = {f.rule_id for f in result.findings}
    assert "aws-access-key-id" in rule_ids
    assert "github-token" in rule_ids
    assert "slack-token" in rule_ids
    assert "connection-string-password" in rule_ids
    assert "private-key-block" in rule_ids


def test_secrets_are_redacted(repo):
    write(repo, "config.py", _secret_code())
    result = _run(repo)
    evidence = " ".join(f.evidence for f in result.findings)
    assert fixtures.aws_access_key() not in evidence
    assert "AKIA" in evidence  # 保留前缀便于确认类型
    assert fixtures.github_token() not in evidence


def test_severity_is_critical_for_keys(repo):
    write(repo, "config.py", _secret_code())
    result = _run(repo)
    aws = [f for f in result.findings if f.rule_id == "aws-access-key-id"]
    assert aws and aws[0].severity is Severity.CRITICAL


def test_line_numbers_reported(repo):
    write(repo, "a.py", f'\n\n\nAWS_KEY = "{fixtures.aws_access_key()}"\n')
    result = _run(repo)
    aws = [f for f in result.findings if f.rule_id == "aws-access-key-id"]
    assert aws and aws[0].line == 4


def test_placeholders_ignored(repo):
    write(repo, "settings.py", 'API_KEY = "your-api-key-here"\nPASSWORD = "<your-password>"\n')
    result = _run(repo)
    assert not [f for f in result.findings if f.rule_id == "generic-credential-assignment"]


def test_env_example_not_flagged_as_secret_file(repo):
    write(repo, ".env.example", "API_KEY=xxxx\n")
    result = _run(repo)
    ids = {f.rule_id for f in result.findings}
    assert "sensitive-dotenv" not in ids


def test_env_file_flagged(repo):
    write(repo, ".env", f'API_KEY={fixtures.aws_access_key()}\n')
    result = _run(repo)
    ids = {f.rule_id for f in result.findings}
    assert "sensitive-dotenv" in ids


def test_private_key_file_flagged(repo):
    write(repo, "id_rsa", "-----BEGIN OPENSSH " + "PRIVATE KEY-----\n")
    result = _run(repo)
    ids = {f.rule_id for f in result.findings}
    assert "sensitive-private-key-file" in ids


def test_tracked_secret_is_escalated(repo):
    """已被提交进 Git 的凭据，严重级别应高于只躺在工作区的。"""
    import subprocess

    subprocess.run(["git", "init", "-q"], cwd=repo, check=True, capture_output=True)
    write(repo, ".env", f'API_KEY={fixtures.aws_access_key()}\n')
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True)

    result = _run(repo)
    dotenv = [f for f in result.findings if f.rule_id == "sensitive-dotenv"]
    assert dotenv
    assert dotenv[0].severity is Severity.CRITICAL
    assert "已被提交到 Git" in dotenv[0].message


def test_untracked_secret_is_not_escalated(repo):
    """未被跟踪的凭据不应被拔高到最高级别。"""
    import subprocess

    subprocess.run(["git", "init", "-q"], cwd=repo, check=True, capture_output=True)
    write(repo, ".env", f'API_KEY={fixtures.aws_access_key()}\n')

    result = _run(repo)
    dotenv = [f for f in result.findings if f.rule_id == "sensitive-dotenv"]
    assert dotenv
    assert dotenv[0].severity is Severity.HIGH
