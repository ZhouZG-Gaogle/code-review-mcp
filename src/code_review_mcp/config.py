"""配置加载：默认值 → 用户级配置 → 项目级配置。

优先级：项目 `.code-review-mcp.yaml` > 用户 `~/.code-review-mcp/config.yaml` > 内置默认值。
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

import yaml

DEFAULT_EXCLUDE_DIRS: set[str] = {
    ".git", ".hg", ".svn",
    "node_modules", "bower_components", "jspm_packages",
    ".venv", "venv", "env", "site-packages", ".tox", ".nox",
    ".m2", ".gradle", ".nuget", ".cargo", ".rustup",
    "Pods", "vendor", ".terraform", ".serverless",
    # 注意：__pycache__ / .pytest_cache 等缓存目录默认「不排除」，
    # 否则缓存检测根本走不到这些目录（它们正是要报告的对象）。
}

DEFAULT_EXCLUDE_FILE_PATTERNS: tuple[str, ...] = (
    r"(?i)(^|[/\\])\.DS_Store$",
    r"(?i)(^|[/\\])Thumbs\.db$",
    r"(?i)(^|[/\\])desktop\.ini$",
    r"(?i)\.min\.(js|css)$",
)

USER_CONFIG_PATH = Path.home() / ".code-review-mcp" / "config.yaml"
PROJECT_CONFIG_NAME = ".code-review-mcp.yaml"


@dataclass
class DefenderConfig:
    enabled: bool = False
    timeout_seconds: int = 600
    scan_type: str = "custom"


@dataclass
class Config:
    exclude_dirs: set[str] = field(default_factory=lambda: set(DEFAULT_EXCLUDE_DIRS))
    exclude_file_patterns: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDE_FILE_PATTERNS))
    max_content_scan_bytes: int = 1_048_576          # 超过此大小只做体积/类型检查，不做内容匹配
    max_files: int = 20_000
    large_file_warn_bytes: int = 1_048_576            # 1 MiB
    large_file_error_bytes: int = 5_242_880           # 5 MiB
    entropy_threshold: float = 7.2                   # 代码文件熵值高于此值视为可疑混淆
    report_placeholders: bool = False
    scan_hidden_files: bool = True
    defender: DefenderConfig = field(default_factory=DefenderConfig)
    source: Path | None = None

    # ---------- 加载 ----------

    @classmethod
    def load(cls, project_root: Path | None = None) -> "Config":
        cfg = cls()
        for path in (USER_CONFIG_PATH,):
            if path.is_file():
                cfg = cfg.merged_with(_read_yaml(path))
        if project_root is not None:
            p = project_root / PROJECT_CONFIG_NAME
            if p.is_file():
                cfg = cfg.merged_with(_read_yaml(p))
        return cfg

    def merged_with(self, data: dict[str, Any]) -> "Config":
        if not data:
            return self
        cfg = replace(self)
        if "exclude_dirs" in data:
            cfg.exclude_dirs = set(data["exclude_dirs"] or [])
        if "exclude_file_patterns" in data:
            cfg.exclude_file_patterns = list(data["exclude_file_patterns"] or [])
        for key in (
            "max_content_scan_bytes",
            "max_files",
            "large_file_warn_bytes",
            "large_file_error_bytes",
        ):
            if key in data and data[key] is not None:
                setattr(cfg, key, int(data[key]))
        if "entropy_threshold" in data and data["entropy_threshold"] is not None:
            cfg.entropy_threshold = float(data["entropy_threshold"])
        if "report_placeholders" in data and data["report_placeholders"] is not None:
            cfg.report_placeholders = bool(data["report_placeholders"])
        if "scan_hidden_files" in data and data["scan_hidden_files"] is not None:
            cfg.scan_hidden_files = bool(data["scan_hidden_files"])
        if isinstance(data.get("defender"), dict):
            d = data["defender"]
            cfg.defender = DefenderConfig(
                enabled=bool(d.get("enabled", cfg.defender.enabled)),
                timeout_seconds=int(d.get("timeout_seconds", cfg.defender.timeout_seconds)),
                scan_type=str(d.get("scan_type", cfg.defender.scan_type)),
            )
        if data.get("source"):
            cfg.source = Path(data["source"])
        return cfg

    def is_excluded_dir(self, name: str) -> bool:
        if not self.scan_hidden_files and name.startswith("."):
            return True
        return name.lower() in {d.lower() for d in self.exclude_dirs}


def _read_yaml(path: Path) -> dict[str, Any]:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return {}
    return raw if isinstance(raw, dict) else {}


def config_path_hint() -> str:
    env = os.environ.get("CODE_REVIEW_MCP_CONFIG")
    if env:
        return env
    return str(USER_CONFIG_PATH)
