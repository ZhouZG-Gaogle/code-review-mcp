"""缓存数据 / 构建产物扫描。"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Iterator

from ..config import Config
from ..gitdiff import GitContext
from ..models import Category, Finding, Severity
from ..rules import RuleSet
from ..walker import FileEntry
from .content import load_text, scan_rules

# 即使被默认排除（出于性能），也要在根目录探测一下的缓存目录
PROBE_DIRS: tuple[str, ...] = (
    "node_modules", "__pycache__", ".venv", "venv", "dist", "build",
    ".next", ".nuxt", "coverage", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    ".gradle", ".m2", "target", "out", ".tox", ".idea", ".vs", "Pods",
    ".terraform", ".cache", ".parcel-cache", ".turbo", ".dart_tool", ".serverless",
    ".nyc_output", "htmlcov", ".eggs", "logs",
)


def scan_cache(
    entries: list[FileEntry],
    rs: RuleSet,
    cfg: Config,
    root: Path,
    git: GitContext | None = None,
) -> Iterator[Finding]:
    """扫描缓存目录、缓存文件与内嵌缓存内容。"""
    dir_rules = [r for r in rs.file_rules_for(Category.CACHE) if r.kind == "dir"]
    file_rules = [r for r in rs.file_rules_for(Category.CACHE) if r.kind == "file"]
    content_rules = rs.by_category(Category.CACHE)

    dir_names = {r.pattern.lower() for r in dir_rules}

    # ---- 缓存目录：按目录聚合，避免一个目录刷屏 ----
    dir_counts: Counter[str] = Counter()
    dir_sample: dict[str, str] = {}
    for entry in entries:
        parts = entry.rel_path.split("/")[:-1]
        for depth, part in enumerate(parts):
            key = "/".join(parts[: depth + 1])
            if part.lower() in dir_names:
                dir_counts[key] += 1
                dir_sample.setdefault(key, entry.rel_path)

    for key, count in sorted(dir_counts.items(), key=lambda kv: -kv[1]):
        name = key.split("/")[-1]
        rule = next((r for r in dir_rules if r.pattern.lower() == name.lower()), None)
        tracked = bool(git and git.dir_has_tracked(key))
        severity = rule.severity if rule else Severity.LOW
        message = f"目录 {key} 中包含 {count} 个文件，疑似缓存或构建产物。"
        if tracked:
            severity = Severity.MEDIUM
            message += " 该目录下的文件已被提交到 Git。"
        yield Finding(
            category=Category.CACHE,
            rule_id=f"cache-dir-{name}",
            severity=severity,
            description=f"缓存 / 构建目录 {name}",
            path=key,
            message=message,
            recommendation=(rule.recommendation if rule else
                            "确认该目录未被提交到版本库，建议加入 .gitignore。"),
            extra={"file_count": count, "sample_file": dir_sample.get(key, ""), "git_tracked": tracked},
        )

    # ---- 根目录探测：被排除掉的重目录也报告一下 ----
    probed = set(dir_counts)
    for name in PROBE_DIRS:
        candidate = root / name
        if not candidate.is_dir():
            continue
        rel = name
        if rel in probed:
            continue
        probed.add(rel)
        tracked = bool(git and git.dir_has_tracked(rel))
        severity = Severity.MEDIUM if tracked else Severity.LOW
        message = f"仓库根目录存在 {name}，通常属于依赖或缓存目录，不应提交到版本库。"
        if tracked:
            message += " 该目录下的文件已被提交到 Git。"
        yield Finding(
            category=Category.CACHE,
            rule_id=f"cache-dir-{name}",
            severity=severity,
            description=f"缓存 / 依赖目录 {name}",
            path=rel,
            message=message,
            recommendation="确认该目录已被 .gitignore 忽略。" if not tracked
                         else "把该目录移出版本库并加入 .gitignore。",
            extra={"git_tracked": tracked},
        )

    # ---- 缓存文件（已落在缓存目录里的不再重复报告） ----
    cache_dir_paths = set(dir_counts)
    for entry in entries:
        if _inside_cache_dir(entry.rel_path, cache_dir_paths):
            continue
        for rule in file_rules:
            try:
                if not rule.compile().search(entry.name):
                    continue
            except ValueError:
                continue
            if rule.min_size and entry.size < rule.min_size:
                continue
            yield Finding(
                category=Category.CACHE,
                rule_id=rule.id,
                severity=rule.severity,
                description=rule.description,
                path=entry.rel_path,
                message=f"文件命中规则 {rule.id}（{entry.size} 字节）",
                recommendation=rule.recommendation,
                extra={"size_bytes": entry.size},
            )

    # ---- 内容特征（压缩代码、内嵌 blob） ----
    for entry in entries:
        loaded = load_text(entry, cfg)
        if loaded is None:
            continue
        yield from scan_rules(loaded, content_rules, cfg)


def _inside_cache_dir(rel_path: str, cache_dirs: set[str]) -> bool:
    """判断文件是否位于某个已识别的缓存目录内。"""
    parts = rel_path.split("/")[:-1]
    for depth in range(len(parts)):
        if "/".join(parts[: depth + 1]) in cache_dirs:
            return True
    return False
