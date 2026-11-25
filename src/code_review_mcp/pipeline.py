"""扫描流水线：把各扫描器串起来，产出统一的 ScanResult。"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .config import Config
from .debuglog import log as debuglog
from .gitdiff import GitContext
from .models import Category, Finding, ScanResult, Severity
from .rules import RuleSet, load_rules
from .scanners import cache as cache_scanner
from .scanners import defender as defender_scanner
from .scanners import large_files as large_files_scanner
from .scanners import malware as malware_scanner
from .scanners import sensitive as sensitive_scanner
from .scanners.content import LoadedFile, scan_rules
from .walker import FileEntry, collect_files


@dataclass
class ScanRequest:
    """一次扫描请求。"""

    root: Path
    categories: set[Category] = field(default_factory=lambda: set(Category))
    only_files: list[str] | None = None      # 限定审查的文件（相对路径）
    severity_min: Severity = Severity.INFO
    use_defender: bool = False
    config: Config | None = None
    rules: RuleSet | None = None


def _filter_entries(entries: list[FileEntry], only: list[str] | None) -> list[FileEntry]:
    if not only:
        return entries
    wanted = {p.replace("\\", "/") for p in only}
    return [e for e in entries if e.rel_path in wanted]


def run_scan(req: ScanRequest) -> ScanResult:
    """执行扫描。"""
    root = req.root.expanduser().resolve()
    result = ScanResult(root=str(root), scope="directory")

    if not root.exists():
        result.errors.append(f"路径不存在: {root}")
        return result
    if not root.is_dir():
        result.errors.append(f"不是目录: {root}")
        return result

    cfg = req.config or Config.load(project_root=root)
    rs = req.rules or load_rules(project_root=root)
    debuglog(f"配置与规则加载完成 ({root})")

    entries, errors = collect_files(root, cfg)
    result.errors.extend(errors)
    entries = _filter_entries(entries, req.only_files)
    result.files_scanned = len(entries)
    result.bytes_scanned = sum(e.size for e in entries)
    debuglog(f"文件遍历完成: {result.files_scanned} 个文件")

    # Git 跟踪状态：决定「只是躺在工作区」还是「已经被提交进版本库」
    git = GitContext.for_repo(root)
    debuglog(f"Git 状态查询完成: available={git.available}")
    if git.available:
        result.notes.append(
            f"Git 仓库：已跟踪文件 {len(git.tracked or [])} 个，提交状态已参与严重级别判定。"
        )
    else:
        result.notes.append("非 Git 目录（或无法读取 Git 状态），未做「是否已提交」判定。")

    categories = req.categories or set(Category)

    # ---- 敏感信息 / 个人信息 ----
    if Category.SENSITIVE in categories or Category.PII in categories:
        wanted = {Category.SENSITIVE, Category.PII} & categories
        sub = RuleSet(
            content_rules=[r for r in rs.content_rules if r.category in wanted],
            file_rules=[r for r in rs.file_rules if r.category in wanted],
        )
        result.extend(sensitive_scanner.scan_sensitive(entries, sub, cfg, git))

    # ---- 缓存数据 ----
    if Category.CACHE in categories:
        sub = RuleSet(
            content_rules=[r for r in rs.content_rules if r.category is Category.CACHE],
            file_rules=[r for r in rs.file_rules if r.category is Category.CACHE],
        )
        result.extend(cache_scanner.scan_cache(entries, sub, cfg, root, git))

    # ---- 大文件 ----
    if Category.LARGE_FILE in categories:
        sub = RuleSet(extension_rules=[r for r in rs.extension_rules if r.category is Category.LARGE_FILE])
        result.extend(large_files_scanner.scan_large_files(entries, sub, cfg, git))

    # ---- 病毒文件 ----
    if Category.MALWARE in categories:
        sub = RuleSet(
            content_rules=[r for r in rs.content_rules if r.category is Category.MALWARE],
            file_rules=[r for r in rs.file_rules if r.category is Category.MALWARE],
            extension_rules=[r for r in rs.extension_rules if r.category is Category.MALWARE],
        )
        result.extend(malware_scanner.scan_malware(entries, sub, cfg))

        if req.use_defender:
            result.extend(_defender_findings(root, cfg))

    # ---- 汇总提示 ----
    _add_summary_notes(result, entries, cfg)
    debuglog(f"扫描完成: {len(result.findings)} 条发现")

    # ---- 严重级别过滤 ----
    if req.severity_min is not Severity.INFO:
        rank = {
            Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
            Severity.LOW: 3, Severity.INFO: 4,
        }
        limit = rank[req.severity_min]
        result.findings = [f for f in result.findings if rank[f.severity] <= limit]

    return result


def _defender_findings(root: Path, cfg: Config) -> list[Finding]:
    status = defender_scanner.defender_status()
    if not status.get("available"):
        return []

    detections, _notes = defender_scanner.scan_paths([str(root)], cfg.defender)
    findings: list[Finding] = []
    for det in detections:
        for resource in det.resources:
            try:
                rel = Path(resource).relative_to(root).as_posix()
            except ValueError:
                rel = resource
            findings.append(Finding(
                category=Category.MALWARE,
                rule_id="defender-detection",
                severity=Severity.CRITICAL,
                description="Windows Defender 检出威胁",
                path=rel,
                message=f"Defender 检出威胁 {det.threat_id}。",
                recommendation="立即隔离该文件，确认来源与影响范围。",
                extra={"threat_id": det.threat_id, "source": "windows defender"},
            ))
    return findings


def _add_summary_notes(result: ScanResult, entries: list[FileEntry], cfg: Config) -> None:
    if entries:
        top = sorted(entries, key=lambda e: e.size, reverse=True)[:5]
        listing = "、".join(f"{e.rel_path} ({large_files_scanner.human_size(e.size)})" for e in top)
        result.notes.append(f"体积最大的文件: {listing}")
    result.notes.append(
        f"已扫描 {result.files_scanned} 个文件 / "
        f"{large_files_scanner.human_size(result.bytes_scanned)}，"
        f"内容匹配上限 {large_files_scanner.human_size(cfg.max_content_scan_bytes)}。"
    )


def scan_snippet(code: str, language: str = "", rules: RuleSet | None = None) -> ScanResult:
    """审查一段代码片段（不落盘）。"""
    rs = rules or load_rules()
    suffix = {
        "python": ".py", "py": ".py", "javascript": ".js", "js": ".js",
        "typescript": ".ts", "ts": ".ts", "java": ".java", "go": ".go",
        "rust": ".rs", "c": ".c", "cpp": ".cpp", "csharp": ".cs", "php": ".php",
        "ruby": ".rb", "shell": ".sh", "bash": ".sh", "sql": ".sql",
        "yaml": ".yaml", "json": ".json", "html": ".html", "css": ".css",
    }.get(language.lower().strip(), ".txt")

    entry = FileEntry(path=Path(f"snippet{suffix}"), rel_path=f"snippet{suffix}", size=len(code.encode("utf-8")))
    line_starts = [0]
    for idx, ch in enumerate(code):
        if ch == "\n":
            line_starts.append(idx + 1)
    loaded = LoadedFile(entry=entry, text=code, line_starts=line_starts)

    result = ScanResult(root="<片段>", scope="snippet", files_scanned=1)
    result.bytes_scanned = entry.size

    for category in (Category.SENSITIVE, Category.PII, Category.MALWARE):
        content_rules = rs.by_category(category)
        if content_rules:
            result.extend(scan_rules(loaded, content_rules, Config(), category))
    return result
