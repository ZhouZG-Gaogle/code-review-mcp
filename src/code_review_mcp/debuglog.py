"""调试日志：设置环境变量 CODE_REVIEW_MCP_DEBUG=1 后，扫描各阶段会打到 stderr。

stderr 在 MCP stdio 协议里是安全的（协议只占用 stdout），不会污染 JSON-RPC 报文。
"""

from __future__ import annotations

import os
import sys
import time

_START = time.time()


def enabled() -> bool:
    return os.environ.get("CODE_REVIEW_MCP_DEBUG", "").strip().lower() in {"1", "true", "yes", "on"}


def log(message: str) -> None:
    if not enabled():
        return
    elapsed = time.time() - _START
    print(f"[code-review-mcp +{elapsed:7.2f}s] {message}", file=sys.stderr, flush=True)
