"""Telling encryption from everyday work: broken file headers, encrypted-looking content, unknown
extensions, ransom notes, canary files touched - and the file-event handler that counts them."""
import math
import os
import re
import threading
import time
from collections import Counter, deque
from pathlib import Path

from . import canary, config
from .config import log, tr
from .winapi import norm


# Headers of common file formats (encryption almost always breaks them); (offset, bytes) = header not at the start
_OLE = [b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"]
_ZIP = [b"PK\x03\x04"]
_OOXML = _ZIP + _OLE  # password-protected Office files are OLE containers, not ZIP
_RIFF = [b"RIFF", b"RF64", b"BW64"]
_MP4 = [(4, b"ftyp"), (4, b"moov"), (4, b"mdat"), (4, b"wide"), (4, b"free"), (4, b"skip"),
        (4, b"styp"), (4, b"sidx"), (4, b"pnot"), (4, b"uuid")]
_MKV = [b"\x1a\x45\xdf\xa3"]
MAGIC = {
    ".docx": _OOXML, ".xlsx": _OOXML, ".pptx": _OOXML, ".odt": _ZIP, ".ods": _ZIP,
    ".odp": _ZIP, ".epub": _ZIP, ".docm": _OOXML, ".xlsm": _OOXML, ".pptm": _OOXML,
    ".vsdx": _ZIP, ".zip": _ZIP + [b"PK\x05\x06", b"PK\x07\x08"],
    ".doc": _OLE, ".xls": _OLE, ".ppt": _OLE,
    ".pdf": [b"%PDF"],
    ".jpg": [b"\xff\xd8\xff"], ".jpeg": [b"\xff\xd8\xff"],
    ".png": [b"\x89PNG\r\n\x1a\n"],
    ".gif": [b"GIF87a", b"GIF89a"],
    ".bmp": [b"BM"],
    ".tif": [b"II*\x00", b"MM\x00*"], ".tiff": [b"II*\x00", b"MM\x00*"],
    ".psd": [b"8BPS"],
    ".webp": _RIFF, ".wav": _RIFF, ".avi": _RIFF,
    ".mp4": _MP4, ".m4v": _MP4, ".m4a": _MP4, ".mov": _MP4, ".heic": _MP4,
    ".mkv": _MKV, ".webm": _MKV,
    ".wmv": [b"\x30\x26\xb2\x75\x8e\x66\xcf\x11"],
    ".flac": [b"fLaC", b"ID3"], ".ogg": [b"OggS"],
    ".rar": [b"Rar!\x1a\x07"],
    ".7z": [b"7z\xbc\xaf\x27\x1c"],
    ".gz": [b"\x1f\x8b"],
    ".sqlite": [b"SQLite format 3\x00"],
}
# Every known header: a file whose header belongs to *some* real format was misnamed, not encrypted
# (e.g. a WebP image downloaded as .jpg)
KNOWN_SIGS = sorted({s for sigs in MAGIC.values() for s in sigs}, key=repr)
TEXT_EXTS = {
    ".txt", ".csv", ".md", ".py", ".c", ".cpp", ".h", ".hpp", ".java", ".js",
    ".ts", ".html", ".htm", ".css", ".json", ".xml", ".tex", ".log", ".ini",
    ".cfg", ".yaml", ".yml", ".sql", ".r", ".m", ".ipynb", ".rtf", ".svg",
    ".bat", ".ps1", ".bib",
}
OTHER_COMMON_EXTS = {
    ".mp4", ".mov", ".avi", ".mkv", ".wmv", ".mp3", ".wav", ".flac", ".m4a",
    ".aac", ".heic", ".webp", ".bmp", ".tif", ".tiff", ".raw", ".psd", ".ai",
    ".hwp", ".key", ".pages", ".numbers", ".gz", ".tar", ".bz2", ".xz",
    ".tmp", ".bak", ".old", ".lnk", ".url", ".exe", ".msi", ".iso", ".dll",
    ".crdownload", ".part", ".download", ".partial", ".torrent",
    ".xmp", ".aae", ".srt", ".ass", ".sig", ".asc", ".ico", ".ttf", ".otf",
    ".db", ".sqlite", ".pkl", ".npy", ".mat", ".xlsm", ".docm", ".pptm",
    ".odg", ".vsdx", ".drawio", ".apk", ".jar", ".class", ".o", ".obj",
    # extensions tools add on top of a real one: source maps, unfinished torrent/downloader files,
    # patch leftovers, editor swap files, test snapshots, checksums, extra compression
    ".map", ".!qb", ".!ut", ".!bt", ".aria2", ".opdownload", ".orig", ".rej", ".swp", ".swo", ".swx",
    ".snap", ".sha1", ".sha256", ".sha512", ".md5", ".zst", ".lz4", ".br", ".asd", ".wbk",
}
COMMON_EXTS = set(MAGIC) | TEXT_EXTS | OTHER_COMMON_EXTS
# split archives and numbered copies: .001, .002, .r00, .z01, .1 ...
_NUMBERED_EXT = re.compile(r"\.[a-z]?\d{1,3}")
# extensions ransom notes use; a "decrypt.py" or "Encrypt_Decrypt_Lab.pdf" is not a ransom note
NOTE_EXTS = {"", ".txt", ".html", ".htm", ".hta", ".mht", ".mhtml", ".rtf", ".url",
             ".png", ".jpg", ".jpeg", ".bmp"}
IGNORE_EXTS = {".tmp", ".crdownload", ".part", ".download", ".partial"}

# Ransom note file names (ransomware drops a note with the same name into every folder)
_S = r"[\W_]*"
NOTE_PATTERN = re.compile(
    r"decrypt|ransom|解密|贖金|赎金|勒索"
    rf"|(recover|restore|unlock|return|get{_S}back){_S}(all{_S})?(my|your|the)?{_S}files"
    rf"|files{_S}(are{_S}|were{_S}|have{_S}been{_S})?(encrypted|locked)"
    rf"|how{_S}to{_S}(recover|restore|decrypt|unlock|back)"
    rf"|(恢復|恢复|還原|还原){_S}(您的|你的)?(檔案|文件)|(檔案|文件){_S}(已經|已经|已)?(被)?加密",
    re.IGNORECASE)


def entropy(data: bytes) -> float:
    n = len(data)
    if n == 0:
        return 0.0
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def periodic_check(handler, canaries):
    """Check canary files periodically: file events can be missed (full buffer, file locked while read)."""
    if handler.triggered_at is not None:
        return
    reason = canary.check_canaries(canaries)
    if reason:
        handler.fire(reason + tr("（定期檢查發現）", " (found by periodic check)"))


# Cloud files (OneDrive etc.) not downloaded yet: reading one starts a download, so leave them alone
_CLOUD_ATTRS = 0x1000 | 0x40000 | 0x400000  # OFFLINE | RECALL_ON_OPEN | RECALL_ON_DATA_ACCESS
# Bytes read from the start of a file. Encrypted data still measures ~7.99 bits/byte over this much (far
# above ENTROPY_LIMIT), and counting byte values is the slowest step of handling an event: 4x faster than 64 KB
SAMPLE_SIZE = 16384
# A file whose size and modification time haven't changed is not read again within this many seconds.
# Kept short, so even ransomware that restores the modification time can't hide behind it for long.
RECHECK_SEC = 2.0


def checkable(path: str) -> bool:
    """broken_reason() can judge files with this extension."""
    ext = Path(path).suffix.lower()
    return ext in MAGIC or ext in TEXT_EXTS


def _magic_ok(data: bytes, sigs) -> bool:
    for s in sigs:
        off, sig = s if isinstance(s, tuple) else (0, s)
        if data[off:off + len(sig)] == sig:
            return True
    return False


def broken_reason(path: str, st=None):
    """Why the file looks encrypted, or None. st: its os.stat() result, if the caller already has it."""
    if not checkable(path):
        return None
    ext = Path(path).suffix.lower()
    try:
        st = st or os.stat(path)
        if getattr(st, "st_file_attributes", 0) & _CLOUD_ATTRS:
            return None
        size = st.st_size
        with open(path, "rb") as f:
            data = f.read(SAMPLE_SIZE)
    except OSError:
        return None
    if len(data) < 8:  # empty, or still being written
        return None
    if not data.strip(b"\0"):  # all zeros: a downloader reserved the space but hasn't written yet
        return None
    if ext in MAGIC:
        ok = (b"%PDF" in data[:1024]) if ext == ".pdf" else _magic_ok(data, MAGIC[ext])
        if (ok or len(data) < 256  # too small to judge (e.g. a Git LFS pointer)
                or _magic_ok(data, KNOWN_SIGS) or b"%PDF" in data[:1024]  # a real file with the wrong extension
                or entropy(data) < 7.0):  # text such as an HTML/CSV "spreadsheet"; encrypted data is ~8
            return None
        return tr("檔頭不符", "bad file header")
    if ext == ".ts" and data[0] == 0x47 and (len(data) <= 188 or data[188] == 0x47):
        return None  # an MPEG-TS video (same extension), not TypeScript
    if size >= config.ENTROPY_MIN_SIZE:
        h = entropy(data)
        if h > config.ENTROPY_LIMIT:
            return tr(f"亂度 {h:.2f}", f"entropy {h:.2f}")
    return None


def _known_ext(ext: str) -> bool:
    return ext in COMMON_EXTS or bool(_NUMBERED_EXT.fullmatch(ext))


def suspicious_ext(event_type: str, src: str, dest: str) -> bool:
    if event_type == "moved":
        s, d = Path(src).suffix.lower(), Path(dest).suffix.lower()
        # a tool that keeps the old extension and adds a separated suffix is fine (photo.jpg ->
        # photo.jpg_original, exiftool); appending letters straight onto it is not (photo.jpg -> photo.jpgcrypt)
        return (s in COMMON_EXTS and not _known_ext(d) and d != "" and s != d
                and not (d.startswith(s) and not d[len(s):len(s) + 1].isalnum()))
    if event_type == "created":
        sfx = [x.lower() for x in Path(src).suffixes]
        return (len(sfx) >= 2 and not _known_ext(sfx[-1])
                and any(x in COMMON_EXTS for x in sfx[:-1]))
    return False


def ignorable(path: str) -> bool:
    name = os.path.basename(path)
    return name.startswith("~") or Path(name).suffix.lower() in IGNORE_EXTS


def is_ransom_note(name: str) -> bool:
    p = Path(name)
    if p.suffix.lower() not in NOTE_EXTS:
        return False
    # drop our own name first: "RansomGuard.exe", "RansomGuard.lnk" etc. contain "ransom"
    return bool(NOTE_PATTERN.search(re.sub(r"ransom[\W_]*guard", "", p.stem, flags=re.IGNORECASE)))


def make_handler(canaries, on_trigger, dry_run, on_new_file=None):
    """on_new_file(path) is told about every file that is created or renamed (for DownloadScanner)."""
    from watchdog.events import FileSystemEventHandler

    class Guard(FileSystemEventHandler):
        def __init__(self):
            self.canaries = {norm(p) for p in canaries}
            self.broken = deque()   # (time, path)
            self.extchg = deque()
            self.notes = deque()    # (time, folder)
            self.checked = {}       # path -> ((size, mtime), monotonic time it was last checked)
            self.lock = threading.Lock()
            self.triggered_at = None

        def fire(self, reason):
            with self.lock:
                now = time.time()
                if self.triggered_at is not None:
                    # normal mode triggers only once; test mode can trigger again after 10 s
                    if not dry_run or now - self.triggered_at < 10:
                        return
                self.triggered_at = now
                self.broken.clear()
                self.extchg.clear()
                self.notes.clear()
            on_trigger(reason)

        def _count(self, q, key, threshold, label, example):
            now = time.time()
            with self.lock:
                q.append((now, norm(key)))
                while q and now - q[0][0] > config.WINDOW_SEC:
                    q.popleft()
                n = len({k for _, k in q})
            if n >= threshold:
                self.fire(tr(f"{config.WINDOW_SEC} 秒內有 {n} 個{label}（例如 {example}）",
                             f"{n} {label} within {config.WINDOW_SEC} seconds (e.g. {example})"))

        def on_any_event(self, event):
            if event.is_directory:
                return
            try:
                self._handle(event)
            except Exception:
                log.exception(tr("處理事件時發生錯誤", "Error while handling a file event"))

        def _handle(self, e):
            t = e.event_type
            if t not in ("created", "modified", "moved", "deleted", "closed"):
                return
            src = e.src_path
            dest = getattr(e, "dest_path", "") or ""
            src = src.decode() if isinstance(src, bytes) else src
            dest = dest.decode() if isinstance(dest, bytes) else dest

            # 1. Canary files
            if norm(src) in self.canaries:
                if t == "deleted":
                    return self.fire(tr(f"誘餌檔被刪除：{src}", f"Canary file was deleted: {src}"))
                if t == "moved":
                    return self.fire(tr(f"誘餌檔被改名或移動：{src} → {dest}",
                                        f"Canary file was renamed or moved: {src} → {dest}"))
                try:
                    if not canary.canary_intact(src, Path(src).read_bytes()):
                        return self.fire(tr(f"誘餌檔內容被修改：{src}", f"Canary file was modified: {src}"))
                except OSError:
                    pass
                return
            if dest and norm(dest) in self.canaries:
                return self.fire(tr(f"有檔案覆蓋了誘餌檔：{src} → {dest}",
                                    f"A file overwrote a canary file: {src} → {dest}"))
            path = dest if t == "moved" else src  # the file as it is now
            if on_new_file and t in ("created", "moved"):
                on_new_file(path)

            # 3. Renamed to unknown extensions
            if suspicious_ext(t, src, dest):
                self._count(self.extchg, path, config.EXT_CHANGE_THRESHOLD,
                            tr("檔案被改成陌生副檔名", "files renamed to unknown extensions"), path)

            # 4. Ransom notes
            if t in ("created", "moved") and is_ransom_note(os.path.basename(path)):
                log.warning(tr("出現疑似勒索訊息檔：%s", "Possible ransom note: %s"), path)
                self._count(self.notes, os.path.dirname(path), config.NOTE_DIR_THRESHOLD,
                            tr("資料夾出現勒索訊息檔", "folders with ransom notes"), path)

            # 2. Broken file content
            if t != "deleted" and not ignorable(path) and checkable(path):
                reason = self._broken(path)
                if reason:
                    log.info(tr("疑似被加密的檔案（%s）：%s", "File looks encrypted (%s): %s"), reason, path)
                    self._count(self.broken, path, config.BROKEN_THRESHOLD,
                                tr("檔案疑似被加密", "files that look encrypted"), path)

        def _broken(self, path):
            """broken_reason(), skipped when the file hasn't changed since it was checked moments ago:
            saving a file usually reports it two or three times in a row."""
            try:
                st = os.stat(path)
            except OSError:
                return None
            key, sig, now = norm(path), (st.st_size, st.st_mtime_ns), time.monotonic()
            prev = self.checked.get(key)
            if prev and prev[0] == sig and now - prev[1] < RECHECK_SEC:
                return None
            if len(self.checked) >= 4096:
                self.checked = {k: v for k, v in self.checked.items() if now - v[1] < RECHECK_SEC}
            self.checked[key] = (sig, now)
            return broken_reason(path, st)

    return Guard()
