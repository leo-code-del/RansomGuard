"""Telling encryption from everyday work: broken file headers, destroyed file ends (partial encryption),
encrypted-looking content, encrypted copies replacing deleted originals, unknown extensions, ransom notes,
canary files touched - and the file-event handler that counts them."""
import heapq
import math
import os
import re
import struct
import threading
import time
from collections import Counter, deque
from pathlib import Path

from . import canary, config, winapi
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
_TIFF = [b"II*\x00", b"MM\x00*"]  # also most camera RAW formats
_ASF = [b"\x30\x26\xb2\x75\x8e\x66\xcf\x11"]
MAGIC = {
    ".docx": _OOXML, ".xlsx": _OOXML, ".pptx": _OOXML, ".odt": _ZIP, ".ods": _ZIP,
    ".odp": _ZIP, ".odg": _ZIP, ".epub": _ZIP, ".docm": _OOXML, ".xlsm": _OOXML, ".pptm": _OOXML,
    ".xlsb": _OOXML, ".dotx": _OOXML, ".xltx": _OOXML, ".potx": _OOXML, ".ppsx": _OOXML,
    ".vsdx": _ZIP, ".zip": _ZIP + [b"PK\x05\x06", b"PK\x07\x08"],
    ".doc": _OLE, ".xls": _OLE, ".ppt": _OLE, ".msg": _OLE, ".vsd": _OLE, ".pub": _OLE,
    ".pdf": [b"%PDF"],
    ".jpg": [b"\xff\xd8\xff"], ".jpeg": [b"\xff\xd8\xff"],
    ".png": [b"\x89PNG\r\n\x1a\n"],
    ".gif": [b"GIF87a", b"GIF89a"],
    ".bmp": [b"BM"],
    ".tif": _TIFF, ".tiff": _TIFF,
    # camera RAW photos
    ".cr2": _TIFF, ".nef": _TIFF, ".arw": _TIFF, ".dng": _TIFF, ".pef": _TIFF, ".srw": _TIFF,
    ".orf": [b"IIRO", b"IIRS", b"MMOR"], ".rw2": [b"IIU\x00"], ".raf": [b"FUJIFILMCCD-RAW"],
    ".psd": [b"8BPS"],
    ".webp": _RIFF, ".wav": _RIFF, ".avi": _RIFF,
    ".mp4": _MP4, ".m4v": _MP4, ".m4a": _MP4, ".mov": _MP4, ".heic": _MP4, ".avif": _MP4, ".3gp": _MP4,
    ".cr3": _MP4,
    ".mkv": _MKV, ".webm": _MKV,
    ".wmv": _ASF, ".wma": _ASF,
    ".flac": [b"fLaC", b"ID3"], ".ogg": [b"OggS"], ".opus": [b"OggS"], ".aif": [b"FORM"], ".aiff": [b"FORM"],
    ".rar": [b"Rar!\x1a\x07"],
    ".7z": [b"7z\xbc\xaf\x27\x1c"],
    ".gz": [b"\x1f\x8b"],
    ".sqlite": [b"SQLite format 3\x00"],
    # mailboxes, password databases, Access databases, drawings
    ".pst": [b"!BDN"], ".ost": [b"!BDN"],
    ".kdbx": [b"\x03\xd9\xa2\x9a"],
    ".accdb": [(4, b"Standard ACE DB")], ".mdb": [(4, b"Standard Jet DB"), (4, b"Standard ACE DB")],
    ".dwg": [b"AC10"],
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
    # program and font files developer tools unpack by the thousand (npm, pip, NuGet)
    ".wasm", ".node", ".woff", ".woff2", ".eot", ".pyd", ".so", ".dylib", ".pdb", ".whl", ".nupkg",
    ".vsix", ".cab", ".msix", ".appx",
}
# headers of other formats that look random inside (programs, fonts, zlib streams such as Git objects): a new file
# that starts with one is not an encrypted copy
_OTHER_SIGS = [b"MZ", b"\x7fELF", b"\0asm", b"wOFF", b"wOF2", b"\x78\x01", b"\x78\x5e", b"\x78\x9c", b"\x78\xda",
               b"\x28\xb5\x2f\xfd", b"BZh", b"\xfd7zXZ\0", b"MSCF", (257, b"ustar")]
COMMON_EXTS = set(MAGIC) | TEXT_EXTS | OTHER_COMMON_EXTS
# files judged by their end as well (see SETTLE_SEC)
END_CHECKED_EXTS = {e for e, sigs in MAGIC.items() if b"PK\x03\x04" in sigs} | {".pdf"}
# what people keep (documents, photos, media, archives): ransomware that writes an encrypted copy under another
# name deletes these; settings and code files are deleted and rewritten by programs all the time
ORIGINAL_EXTS = set(MAGIC) | {".txt", ".csv", ".md", ".rtf", ".tex", ".bib", ".svg", ".htm", ".html"}
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
# Some ransomware leaves the start of a file alone and encrypts the rest, or only parts of it: it is faster and gets
# past header checks. ZIP-based files (Office, OpenDocument, zip) and PDF keep a structure at their end, which that
# destroys; text files are judged by their end as well as their start. A file is judged by its end only once
# nobody writes it any more (a file being copied or downloaded has no end yet), SETTLE_SEC after its last change.
SETTLE_SEC = 2.0
TAIL_SIZE = 4096
_ZIP_EOCD = b"PK\x05\x06"  # end of central directory: in the last 22 bytes, or before a comment of up to 64 KB
# Ransomware that writes an encrypted copy deletes the original right after it; a deleted file and a new one are
# paired only this close together (seconds)
PAIR_SEC = 5.0


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
            data, tail = f.read(SAMPLE_SIZE), b""
            if ext in TEXT_EXTS and size > SAMPLE_SIZE:  # its end too: encryption may leave the start alone
                f.seek(size - TAIL_SIZE)
                tail = f.read(TAIL_SIZE)
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
        for part in (data, tail):
            h = entropy(part)
            if h > config.ENTROPY_LIMIT:
                return tr(f"亂度 {h:.2f}", f"entropy {h:.2f}")
    return None


def _random_end(tail: bytes) -> bool:
    """The end of a file looks encrypted: not zeros (space a downloader reserved), random-looking."""
    return len(tail) >= 1024 and bool(tail.strip(b"\0")) and entropy(tail[-TAIL_SIZE:]) > config.ENTROPY_LIMIT


def _zip_entries_broken(f, cd: bytes, entries: int, size: int) -> bool:
    """The central directory, or the local header of a file it lists, isn't what it should be. Encryption in
    blocks spread over the file (intermittent encryption) hits some of them: an Office file has a dozen parts and
    more, each with its header."""
    pos = 0
    for _ in range(min(entries, 1000)):
        if pos + 46 > len(cd):
            return len(cd) < 1 << 20  # cut short, unless only the first megabyte was read
        if cd[pos:pos + 4] != b"PK\x01\x02":
            return True
        name, extra, comment = struct.unpack_from("<HHH", cd, pos + 28)
        offset = struct.unpack_from("<I", cd, pos + 42)[0]
        if offset != 0xFFFFFFFF:  # (ZIP64: the offset is elsewhere)
            if offset >= size:
                return True
            f.seek(offset)
            if f.read(4) != b"PK\x03\x04":
                return True
        pos += 46 + name + extra + comment
    return False


def damaged_end(path: str):
    """Why a ZIP-based or PDF file whose header is intact looks encrypted further in, or None (also for other
    files). Call it only for a file nobody is writing: see SETTLE_SEC."""
    destroyed = tr("檔案結尾的結構被破壞", "file structure at the end destroyed")
    try:
        with open(path, "rb") as f:
            head = f.read(1024)
            size = f.seek(0, os.SEEK_END)
            f.seek(max(0, size - TAIL_SIZE))
            tail = f.read()
            if head.startswith(b"PK\x03\x04"):
                i = tail.rfind(_ZIP_EOCD)
                if i < 0 and size > TAIL_SIZE:  # an archive comment after it
                    f.seek(max(0, size - 65536 - 22))
                    tail = f.read()
                    i = tail.rfind(_ZIP_EOCD)
                if i < 0:
                    return destroyed if _random_end(tail) else None
                eocd = tail[i:i + 22]
                if len(eocd) < 22 or eocd[4:8] != b"\0\0\0\0":  # cut short, or a multi-part archive
                    return None
                entries, cd_size, cd_offset = struct.unpack_from("<HII", eocd, 10)
                if cd_offset == 0xFFFFFFFF or entries == 0xFFFF:  # ZIP64 keeps the real numbers elsewhere
                    return None
                if cd_offset >= size:
                    return destroyed
                f.seek(cd_offset)  # the central directory, where the end record says it starts
                return destroyed if _zip_entries_broken(f, f.read(min(cd_size, 1 << 20)), entries, size) else None
            if b"%PDF" in head and Path(path).suffix.lower() == ".pdf":
                return None if b"%%EOF" in tail or not _random_end(tail) else destroyed
    except OSError:
        pass
    return None


def looks_encrypted(path: str, st=None) -> bool:
    """A file of a type this program doesn't know whose content looks random: no known header, not zeros, at
    least 1 KB (encrypted data, or a compressed format of its own)."""
    try:
        st = st or os.stat(path)
        if getattr(st, "st_file_attributes", 0) & _CLOUD_ATTRS or st.st_size < 1024:
            return False
        with open(path, "rb") as f:
            data = f.read(SAMPLE_SIZE)
    except OSError:
        return False
    if (len(data) < 1024 or not data.strip(b"\0") or _magic_ok(data, KNOWN_SIGS) or _magic_ok(data, _OTHER_SIGS)
            or b"%PDF" in data[:1024]):
        return False
    return entropy(data) > config.ENTROPY_LIMIT


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
            self.settling = {}      # path -> (path, (size, mtime), monotonic time to judge it, tries): see SETTLE_SEC
            self.settle_due = []    # heap of (time to judge, path); entries replaced in `settling` are skipped
            self.settle_cv = threading.Condition()
            self.settler = None
            self.deleted = {}       # folder -> deque of (time, None): files people keep that were deleted there
            self.unknown = {}       # folder -> deque of (time, path): new files of a type this program doesn't know

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
            if t in ("moved", "deleted"):
                self._uncount(src)

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
                    self._encrypted(path, reason)

            # 5. Encrypted copies: ransomware that writes an encrypted copy under another name (photo.jpg ->
            # a8Fk2.b3c1) and deletes the original. Each file people keep that is deleted is paired with a new
            # file of an unknown type in the same folder, which is then read: it counts if it looks encrypted.
            if t == "deleted":
                if Path(src).suffix.lower() in ORIGINAL_EXTS and not ignorable(src):
                    self._pair(os.path.dirname(src))
            elif not ignorable(path) and not _known_ext(Path(path).suffix.lower()):
                try:
                    if os.stat(path).st_size >= 1024:  # an empty one just created is reported again once written
                        self._pair(os.path.dirname(path), path)
                except OSError:
                    pass

        def _uncount(self, path):
            """A file counted for its unknown extension that is renamed or deleted soon after was the temporary
            file of a save: editors and tools write "notes.md.tmp.1724.4af6f2" (or "package.json.2348927342") and
            rename it onto "notes.md" at once. Ransomware leaves its files under their new names."""
            key = norm(path)
            with self.lock:
                keep = [item for item in self.extchg if item[1] != key]
                if len(keep) != len(self.extchg):
                    self.extchg.clear()
                    self.extchg.extend(keep)

        def _encrypted(self, path, reason):
            log.info(tr("疑似被加密的檔案（%s）：%s", "File looks encrypted (%s): %s"), reason, path)
            self._count(self.broken, path, config.BROKEN_THRESHOLD,
                        tr("檔案疑似被加密", "files that look encrypted"), path)

        def _broken(self, path):
            """broken_reason(), skipped when the file hasn't changed since it was checked moments ago:
            saving a file usually reports it two or three times in a row. A file that may be judged by its end
            too is looked at again once nobody writes it."""
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
            reason = broken_reason(path, st)
            if (reason is None and Path(path).suffix.lower() in END_CHECKED_EXTS
                    and not getattr(st, "st_file_attributes", 0) & _CLOUD_ATTRS):  # reading it would download it
                self._settle(path, sig)
            return reason

        def _settle(self, path, sig, tries=0):
            with self.settle_cv:
                if len(self.settling) >= 10000:  # far more than any real work produces at once
                    return
                key, due = norm(path), time.monotonic() + SETTLE_SEC
                self.settling[key] = (path, sig, due, tries)
                heapq.heappush(self.settle_due, (due, key))
                if self.settler is None:
                    self.settler = threading.Thread(target=self._settle_loop, daemon=True)
                    self.settler.start()
                if self.settle_due[0] == (due, key):  # due before all the others: wake the loop to wait for it
                    self.settle_cv.notify()        # (waking it for every file costs a thread switch each)

        def _settle_loop(self):
            while True:
                with self.settle_cv:
                    while not self.settle_due:
                        self.settle_cv.wait()
                    due, key = self.settle_due[0]
                    entry = self.settling.get(key)
                    if entry is None or entry[2] != due:  # replaced by a later change of the same file
                        heapq.heappop(self.settle_due)
                        continue
                    if due > time.monotonic():
                        self.settle_cv.wait(due - time.monotonic())
                        continue
                    heapq.heappop(self.settle_due)
                    path, sig, _, tries = self.settling.pop(key)
                try:
                    self._settled(path, sig, tries)
                except Exception:
                    log.exception(tr("處理事件時發生錯誤", "Error while handling a file event"))

        def _settled(self, path, sig, tries):
            try:
                st = os.stat(path)
            except OSError:
                return
            if (st.st_size, st.st_mtime_ns) != sig:
                return  # changed again: that change is reported and waited for in turn
            if winapi.being_written(path):
                if tries < 30:  # being copied or downloaded: wait for the end (up to about a minute)
                    self._settle(path, sig, tries + 1)
                return
            reason = damaged_end(path)
            if reason:
                self._encrypted(path, reason)

        def _pair(self, folder, new=None):
            key, now = norm(folder), time.time()
            with self.lock:
                if new is not None and any(k == norm(new) for _, k in self.broken):
                    return  # counted already
                if len(self.deleted) + len(self.unknown) > 512:  # folders with nothing recent: forget them
                    for d in (self.deleted, self.unknown):
                        for k in [k for k, q in d.items() if not q or now - q[-1][0] > PAIR_SEC]:
                            del d[k]
                gone, made = self.deleted.setdefault(key, deque()), self.unknown.setdefault(key, deque())
                for q in (gone, made):
                    while q and now - q[0][0] > PAIR_SEC:
                        q.popleft()
                if new is None:
                    gone.append((now, None))
                else:  # timed by its latest write: a big file takes a while to write before its original goes
                    for item in [item for item in made if norm(item[1]) == norm(new)]:
                        made.remove(item)
                    made.append((now, new))
                pairs = []
                while gone and made:
                    gone.popleft()
                    pairs.append(made.popleft()[1])
            for p in pairs:
                if looks_encrypted(p):
                    self._encrypted(p, tr("加密的副本取代了被刪除的原檔", "an encrypted copy replaced a deleted original"))

    return Guard()
