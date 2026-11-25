"""原始 JSON-RPC 探针：绕过 MCP 客户端，直接把协议报文喂给服务进程。

用于定位「工具调用时服务进程直接退出」这类问题。
    uv run python scripts/raw_probe.py
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
SERVER = PROJECT / ".venv" / "Scripts" / "code-review-mcp.exe"
TARGET = PROJECT / ".tmp-e2e"


def main() -> int:
    TARGET.mkdir(exist_ok=True)
    # 分片拼接，避免源码里出现连续的凭据字面量
    aws_key = "AKIA" + "IOSFODNN7" + "EXAMPLE"
    phone = "138" + "12345678"
    (TARGET / "app.py").write_text(
        f"AWS_KEY = '{aws_key}'\nphone = '{phone}'\n",
        encoding="utf-8",
    )

    messages = [
        {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "probe", "version": "1.0"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {
                "name": "review_sensitive_data",
                "arguments": {"path": str(TARGET)},
            },
        },
    ]
    payload = "\n".join(json.dumps(m, ensure_ascii=False) for m in messages) + "\n"

    proc = subprocess.run(
        [str(SERVER)],
        input=payload.encode("utf-8"),
        capture_output=True,
        timeout=120,
    )
    print(f"--- returncode={proc.returncode} ---")
    print("--- stdout ---")
    print(proc.stdout.decode("utf-8", "replace")[:4000])
    print("--- stderr ---")
    print(proc.stderr.decode("utf-8", "replace")[:6000])
    return proc.returncode


if __name__ == "__main__":
    sys.exit(main())
