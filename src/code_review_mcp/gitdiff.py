"""Git 增量审查：解析出本次变更涉及的文件。"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

MODE_WORKTREE = "worktree"
MODE_STAGED = "staged"
MODE_BASE = "base"


@dataclass
class GitChange:
    files: list[str]
    errors: list[str]


def _git(repo: Path, args: list[str], timeout: int = 60) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
            # 必须切断 stdin：MCP stdio 服务的 stdin 是 JSON-RPC 管道，
            # 子进程继承它会阻塞等待输入，把整条协议流挂死。
            stdin=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        return -1, "", "未找到 git 可执行文件。"
    except subprocess.TimeoutExpired:
        return -1, "", "git 命令执行超时。"
    except OSError as exc:
        return -1, "", f"git 调用失败: {exc}"
    return proc.returncode, proc.stdout or "", proc.stderr or ""


def is_git_repo(path: Path) -> bool:
    code, out, _ = _git(path, ["rev-parse", "--is-inside-work-tree"])
    return code == 0 and out.strip() == "true"


def list_changed_files(
    repo: Path,
    mode: str = MODE_WORKTREE,
    base: str | None = None,
) -> GitChange:
    """列出变更文件。

    mode:
      - worktree: 工作区所有改动（含未跟踪文件），默认
      - staged:   已暂存的改动
      - base:     相对 base 的差异（``git diff base...HEAD``）
    """
    errors: list[str] = []
    if not repo.exists():
        return GitChange([], [f"路径不存在: {repo}"])
    if not is_git_repo(repo):
        return GitChange([], [f"{repo} 不是 Git 仓库。"])

    files: list[str] = []

    if mode == MODE_BASE:
        if not base:
            return GitChange([], ["base 模式下必须提供 base（例如 origin/main 或 HEAD~1）。"])
        code, out, err = _git(repo, ["diff", "--name-only", f"{base}...HEAD"])
        if code != 0:
            return GitChange([], [f"git diff {base}...HEAD 失败: {err.strip() or out.strip()}"])
        files = [line.strip() for line in out.splitlines() if line.strip()]

    elif mode == MODE_STAGED:
        code, out, err = _git(repo, ["diff", "--name-only", "--cached"])
        if code != 0:
            return GitChange([], [f"git diff --cached 失败: {err.strip() or out.strip()}"])
        files = [line.strip() for line in out.splitlines() if line.strip()]

    else:  # worktree
        code, out, err = _git(repo, ["status", "--porcelain", "-z"])
        if code != 0:
            return GitChange([], [f"git status 失败: {err.strip() or out.strip()}"])
        files = _parse_porcelain_z(out)

    # 去重并保持顺序
    seen: set[str] = set()
    unique: list[str] = []
    for f in files:
        norm = f.replace("\\", "/")
        if norm not in seen:
            seen.add(norm)
            unique.append(norm)
    return GitChange(unique, errors)


def _parse_porcelain_z(raw: str) -> list[str]:
    """解析 ``git status --porcelain -z`` 的 NUL 分隔输出。"""
    entries = raw.split("\0")
    files: list[str] = []
    i = 0
    while i < len(entries):
        item = entries[i]
        i += 1
        if not item:
            continue
        if len(item) < 4:
            continue
        status = item[:2]
        path = item[3:]
        if "R" in status or "C" in status:
            # 重命名 / 复制：NUL 分隔的下一个字段是旧路径，跳过
            if i < len(entries):
                i += 1
        files.append(path)
    return files


def tracked_files(repo: Path) -> set[str] | None:
    """返回仓库中已被 Git 跟踪的文件集合（非 Git 仓库返回 None）。

    「文件躺在工作区」和「文件已经被提交进版本库」是两种完全不同的事：
    前者只是本地习惯问题，后者是安全事故。
    """
    if not repo.is_dir() or not is_git_repo(repo):
        return None
    code, out, _ = _git(repo, ["ls-files", "-z"], timeout=120)
    if code != 0:
        return None
    return {p.replace("\\", "/") for p in out.split("\0") if p}


class GitContext:
    """跟踪状态查询。"""

    def __init__(self, tracked: set[str] | None = None):
        self.tracked = tracked

    @property
    def available(self) -> bool:
        return self.tracked is not None

    def is_tracked(self, rel_path: str) -> bool:
        if self.tracked is None:
            return False
        return rel_path.replace("\\", "/") in self.tracked

    def dir_has_tracked(self, dir_path: str) -> bool:
        """目录下是否有已被跟踪的文件。"""
        if self.tracked is None:
            return False
        prefix = dir_path.replace("\\", "/").rstrip("/") + "/"
        return any(p.startswith(prefix) for p in self.tracked)

    @classmethod
    def for_repo(cls, repo: Path) -> "GitContext":
        return cls(tracked_files(repo))
