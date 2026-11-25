"""Windows Defender 联动（可选）。

仅在 Windows 且 Defender 可用时生效；扫描使用 ``-DisableRemediation``，
只做检测不做隔离 / 删除，避免审查工具擅自改动用户文件。
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..config import DefenderConfig


@dataclass
class DefenderDetection:
    threat_id: str
    resources: list[str]
    severity: str = "未知"

    def to_dict(self) -> dict[str, Any]:
        return {"threat_id": self.threat_id, "resources": self.resources, "severity": self.severity}


def _find_mpcmdrun() -> str | None:
    candidates: list[Path] = []
    for env in ("ProgramFiles", "ProgramFiles(x86)"):
        base = os.environ.get(env)
        if base:
            candidates.append(Path(base) / "Windows Defender" / "MpCmdRun.exe")
    platform_dir = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "Microsoft" / "Windows Defender" / "Platform"
    if platform_dir.is_dir():
        versions = sorted((p for p in platform_dir.iterdir() if p.is_dir()), key=lambda p: p.name)
        for v in reversed(versions):
            candidates.append(v / "MpCmdRun.exe")
    for c in candidates:
        if c.is_file():
            return str(c)
    found = shutil.which("MpCmdRun.exe")
    return found


def _run_powershell(script: str, timeout: int = 60) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
            # 切断 stdin：避免子进程碰到 MCP 的 JSON-RPC 管道
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return -1, "", str(exc)
    return proc.returncode, proc.stdout or "", proc.stderr or ""


def defender_status() -> dict[str, Any]:
    """返回 Defender 可用性状态。"""
    status: dict[str, Any] = {
        "platform": platform.system(),
        "available": False,
        "antivirus_enabled": False,
        "real_time_protection": False,
        "mpcmdrun": None,
        "detail": "",
    }
    if platform.system() != "Windows":
        status["detail"] = "非 Windows 平台，跳过 Defender 联动。"
        return status

    mpcmdrun = _find_mpcmdrun()
    status["mpcmdrun"] = mpcmdrun
    if not mpcmdrun:
        status["detail"] = "未找到 MpCmdRun.exe，Defender 联动不可用。"
        return status

    code, out, err = _run_powershell(
        "Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled "
        "| ConvertTo-Json -Compress"
    )
    if code == 0 and out.strip():
        try:
            data = json.loads(out.strip())
            status["antivirus_enabled"] = bool(data.get("AntivirusEnabled"))
            status["real_time_protection"] = bool(data.get("RealTimeProtectionEnabled"))
        except json.JSONDecodeError:
            pass
    else:
        status["detail"] = (err or out).strip()[:300]

    status["available"] = bool(status["antivirus_enabled"])
    if not status["available"]:
        status["detail"] = status["detail"] or "Windows Defender 未启用实时保护，无法联动扫描。"
    return status


def scan_paths(
    paths: list[str],
    cfg: DefenderConfig,
    *,
    platform_name: str | None = None,
) -> tuple[list[DefenderDetection], list[str]]:
    """用 Defender 扫描给定路径，返回 (命中列表, 错误/提示)。

    ``platform_name`` 仅供测试注入，默认用真实平台；非 Windows 直接跳过。
    """
    notes: list[str] = []
    if (platform_name or platform.system()) != "Windows":
        return [], ["非 Windows 平台，跳过 Defender 联动扫描。"]

    mpcmdrun = _find_mpcmdrun()
    if not mpcmdrun:
        return [], ["未找到 MpCmdRun.exe，跳过 Defender 联动扫描。"]

    if not paths:
        return [], ["没有可交给 Defender 扫描的路径。"]

    started = time.time()
    try:
        proc = subprocess.run(
            [mpcmdrun, "-Scan", "-ScanType", "3", "-File", paths[0], "-DisableRemediation"],
            capture_output=True,
            text=True,
            timeout=cfg.timeout_seconds,
            encoding="utf-8",
            errors="replace",
            stdin=subprocess.DEVNULL,
        )
        output = (proc.stdout or "") + (proc.stderr or "")
    except subprocess.TimeoutExpired:
        return [], [f"Defender 扫描超时（>{cfg.timeout_seconds}s）。"]
    except OSError as exc:
        return [], [f"调用 Defender 失败: {exc}"]

    for line in output.splitlines():
        if "Threats Detected" in line and ":" in line:
            notes.append(line.strip())

    detections = _collect_detections(since=started - 5)
    if not detections:
        notes.append("Defender 未报告任何威胁。")
    return detections, notes


def _collect_detections(since: float) -> list[DefenderDetection]:
    script = (
        "Get-MpThreatDetection | "
        "Select-Object ThreatID,InitialDetectionTime,Resources,ActionSuccess | "
        "ConvertTo-Json -Depth 4 -Compress"
    )
    code, out, _err = _run_powershell(script, timeout=120)
    if code != 0 or not out.strip():
        return []
    try:
        raw = json.loads(out.strip())
    except json.JSONDecodeError:
        return []
    if isinstance(raw, dict):
        raw = [raw]

    detections: list[DefenderDetection] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        stamp = item.get("InitialDetectionTime")
        try:
            if stamp is not None:
                epoch = stamp.timestamp() if hasattr(stamp, "timestamp") else None
                if epoch is not None and epoch < since:
                    continue
        except (ValueError, OSError, OverflowError):
            pass
        resources = item.get("Resources")
        if isinstance(resources, str):
            resources = [r.strip() for r in resources.split(";") if r.strip()]
        elif not isinstance(resources, list):
            resources = []
        detections.append(DefenderDetection(
            threat_id=str(item.get("ThreatID", "")),
            resources=[str(r) for r in resources],
        ))
    return detections
