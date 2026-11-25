"""模拟其它平台跑测试：在 pytest 启动前改写 platform.system()。

用来在 Windows 上验证「非 Windows 分支」的用例是否也能通过，
避免每次都要靠 CI 才发现平台相关问题。

    uv run python scripts/platform_probe.py Linux
"""

from __future__ import annotations

import platform
import sys

import pytest


def main() -> int:
    fake = sys.argv[1] if len(sys.argv) > 1 else "Linux"
    platform.system = lambda: fake  # type: ignore[assignment]
    print(f"[platform_probe] platform.system() -> {fake}")
    return int(pytest.main(["-q", "--tb=short"]))


if __name__ == "__main__":
    raise SystemExit(main())
