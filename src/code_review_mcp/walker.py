"""文件遍历：按配置排除目录，产出待审查文件。"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from .config import Config


@dataclass(slots=True)
class FileEntry:
    path: Path
    rel_path: str
    size: int

    @property
    def suffix(self) -> str:
        return self.path.suffix.lower()

    @property
    def name(self) -> str:
        return self.path.name


def _rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def iter_files(root: Path, cfg: Config) -> Iterator[FileEntry]:
    """递归产出 root 下的文件（不含被排除的目录）。"""
    exclude_patterns = [
        re.compile(p) for p in cfg.exclude_file_patterns if p
    ]
    count = 0
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        current = Path(dirpath)
        # 原地裁剪，避免进入不需要的目录
        dirnames[:] = [
            d for d in dirnames
            if not cfg.is_excluded_dir(d)
            and not (current / d).is_symlink()
        ]
        for name in filenames:
            fp = current / name
            rel = _rel(fp, root)
            if any(p.search(rel) for p in exclude_patterns):
                continue
            try:
                size = fp.stat().st_size
            except OSError:
                continue
            if fp.is_symlink():
                continue
            count += 1
            if count > cfg.max_files:
                return
            yield FileEntry(path=fp, rel_path=rel, size=size)


def collect_files(root: Path, cfg: Config) -> tuple[list[FileEntry], list[str]]:
    """一次性收集文件，返回 (文件列表, 错误列表)。"""
    files: list[FileEntry] = []
    errors: list[str] = []
    try:
        for entry in iter_files(root, cfg):
            files.append(entry)
    except OSError as exc:
        errors.append(f"遍历 {root} 失败: {exc}")
    return files, errors


def directory_size(path: Path) -> int:
    """目录占用总字节数（尽力而为，失败返回 0）。"""
    total = 0
    try:
        for dirpath, _dirnames, filenames in os.walk(path, followlinks=False):
            for name in filenames:
                try:
                    total += (Path(dirpath) / name).stat().st_size
                except OSError:
                    continue
    except OSError:
        pass
    return total
