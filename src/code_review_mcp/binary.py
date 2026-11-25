"""二进制识别、魔数识别与熵计算。"""

from __future__ import annotations

import math
from collections import Counter
from pathlib import Path

# 常见文件魔数，用于「扩展名与真实类型不符」这类强恶意信号。
MAGIC_SIGNATURES: list[tuple[bytes, str, str]] = [
    (b"MZ", "pe", "Windows PE 可执行文件"),
    (b"\x7fELF", "elf", "Linux ELF 可执行文件"),
    (b"\xca\xfe\xba\xbe", "macho-fat", "Mach-O 可执行文件"),
    (b"\xcf\xfa\xed\xfe", "macho", "Mach-O 可执行文件"),
    (b"PK\x03\x04", "zip", "ZIP 压缩包"),
    (b"PK\x05\x06", "zip-empty", "ZIP 压缩包"),
    (b"Rar!\x1a\x07", "rar", "RAR 压缩包"),
    (b"7z\xbc\xaf\x27\x1c", "7z", "7-Zip 压缩包"),
    (b"\x1f\x8b", "gzip", "GZIP 压缩包"),
    (b"BZh", "bzip2", "BZIP2 压缩包"),
    (b"\xfd7zXZ\x00", "xz", "XZ 压缩包"),
    (b"%PDF", "pdf", "PDF 文档"),
    (b"\x89PNG\r\n\x1a\n", "png", "PNG 图片"),
    (b"\xff\xd8\xff", "jpeg", "JPEG 图片"),
    (b"GIF8", "gif", "GIF 图片"),
    (b"BM", "bmp", "BMP 图片"),
    (b"II*\x00", "tiff", "TIFF 图片"),
    (b"MM\x00*", "tiff", "TIFF 图片"),
    (b"OggS", "ogg", "Ogg 媒体"),
    (b"ID3", "mp3", "MP3 音频"),
    (b"SQLite format 3\x00", "sqlite", "SQLite 数据库"),
    (b"\xca\xfe\xba\xbe", "java-class", "Java class 文件"),
    (b"\x00asm", "wasm", "WebAssembly 模块"),
    (b"dex\n", "dex", "Android DEX 文件"),
    (b"\x04\x03\x4b\x18", "apk", "Android APK"),
    (b"UPX!", "upx", "UPX 加壳可执行文件"),
]

# 扩展名 -> 期望的魔数类型（用于检测扩展名伪装）
EXTENSION_EXPECTATION: dict[str, set[str]] = {
    ".png": {"png"},
    ".jpg": {"jpeg"},
    ".jpeg": {"jpeg"},
    ".gif": {"gif"},
    ".bmp": {"bmp"},
    ".webp": {"webp"},
    ".pdf": {"pdf"},
    ".zip": {"zip", "zip-empty"},
    ".gz": {"gzip"},
    ".bz2": {"bzip2"},
    ".xz": {"xz"},
    ".7z": {"7z"},
    ".rar": {"rar"},
    ".exe": {"pe"},
    ".dll": {"pe"},
    ".so": {"elf"},
    ".sqlite": {"sqlite"},
    ".db": {"sqlite"},
    ".wasm": {"wasm"},
    ".apk": {"apk", "zip"},
    ".mp3": {"mp3"},
}

# 这些扩展名里出现 PE/ELF/DEX 魔数，一定是伪装。
EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".scr", ".com", ".pif", ".cpl", ".msi", ".msp", ".hta",
    ".jar", ".class", ".apk", ".deb", ".rpm", ".dylib", ".so", ".bin", ".run",
}

TEXT_LIKE_EXTENSIONS = {
    ".js", ".ts", ".jsx", ".tsx", ".py", ".rb", ".go", ".rs", ".java", ".c", ".h",
    ".cpp", ".hpp", ".cs", ".php", ".sh", ".bash", ".ps1", ".bat", ".cmd", ".vbs",
    ".txt", ".md", ".json", ".yaml", ".yml", ".xml", ".html", ".css", ".scss", ".sql",
    ".env", ".ini", ".toml", ".cfg", ".conf", ".log", ".pyc", ".lua", ".pl", ".r",
}


def detect_magic(data: bytes) -> tuple[str, str] | None:
    """返回 (类型标识, 中文描述)，无法识别时返回 None。"""
    for magic, kind, desc in MAGIC_SIGNATURES:
        if data.startswith(magic):
            return kind, desc
    return None


def is_binary(data: bytes, sample_size: int = 8192) -> bool:
    """粗略判断是否为二进制内容（只看 NUL 字节）。

    不要在这里用「可打印字节比例」下结论：UTF-8 中文、日文等文本的
    多字节序列会被算成非可打印，导致整个非 ASCII 代码库被当成二进制跳过。
    真正的文本判定见 :func:`decode_text`。
    """
    if not data:
        return False
    return b"\x00" in data[:sample_size]


# 常见文本编码，按「越常见越靠前」排列
TEXT_ENCODINGS: tuple[str, ...] = (
    "utf-8-sig",
    "utf-8",
    "gb18030",     # 中文 Windows 常见的 GBK 超集
    "big5",        # 繁体中文
    "shift_jis",   # 日文
    "utf-16",
)


def _control_ratio(text: str, sample_size: int = 8192) -> float:
    """控制字符占比：二进制数据解码后这个值会明显偏高。"""
    sample = text[:sample_size]
    if not sample:
        return 0.0
    bad = sum(1 for ch in sample if (ord(ch) < 32 and ch not in "\t\n\r\f") or ord(ch) == 127)
    return bad / len(sample)


def _detect_utf16_without_bom(data: bytes) -> str | None:
    """探测没有 BOM 的 UTF-16：ASCII 文本编码成 UTF-16 后每隔一个字节就是 0。"""
    sample = data[:4096]
    n = len(sample) // 2
    if n < 8:
        return None
    le_zeros = sum(1 for i in range(1, n * 2, 2) if sample[i] == 0)
    be_zeros = sum(1 for i in range(0, n * 2, 2) if sample[i] == 0)
    if le_zeros / n > 0.3:
        return "utf-16-le"
    if be_zeros / n > 0.3:
        return "utf-16-be"
    return None


def decode_text(data: bytes) -> str | None:
    """尽力把字节解码成文本；确实是二进制时返回 None。

    关键点：判定必须在**解码之后**做。按字节统计可打印字符会把
    UTF-8 中文、日文等内容整体判成二进制，导致整个中文代码库被跳过。
    """
    if not data:
        return ""

    # 带 BOM 的 UTF-16
    if data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
        try:
            text = data.decode("utf-16")
        except UnicodeDecodeError:
            text = None
        if text is not None and _control_ratio(text) <= 0.02:
            return text

    if b"\x00" in data[:8192]:
        # 含 NUL：可能是无 BOM 的 UTF-16，也可能是真二进制
        encoding = _detect_utf16_without_bom(data)
        if encoding:
            try:
                text = data.decode(encoding)
            except UnicodeDecodeError:
                return None
            return text if _control_ratio(text) <= 0.02 else None
        return None

    for encoding in TEXT_ENCODINGS:
        try:
            text = data.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
        if encoding == "utf-16" and "\x00" in text[:512]:
            continue
        if _control_ratio(text) > 0.02:
            continue
        return text

    # 兜底：latin-1 一定能解，再判一次控制字符比例
    text = data.decode("latin-1", errors="replace")
    return text if _control_ratio(text) <= 0.05 else None


def shannon_entropy(data: bytes) -> float:
    """香农熵（0-8），用于识别加壳 / 高强度混淆 / 随机密钥。"""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def read_head(path: Path, size: int = 8192) -> bytes:
    try:
        with path.open("rb") as fh:
            return fh.read(size)
    except OSError:
        return b""

