#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RansomGuard - detects ransomware-like encryption activity and cuts off the network when it triggers.

Detection (any one of these triggers it):
  1. A canary file is modified, moved or deleted (also checked periodically, in case events are missed)
  2. Within a short time, several files get "broken": .docx/.pdf/.jpg/.mp4 headers no longer match,
     or plain-text files (.txt/.py/.cpp...) turn into high-entropy content (looks encrypted)
  3. Within a short time, many files are renamed to unknown extensions (e.g. report.docx -> report.docx.locked)
  4. Within a short time, ransom notes appear in several folders (e.g. HOW_TO_DECRYPT.txt)
  5. A process runs a destructive command commonly used by ransomware/intruders: deleting restore
     points (vssadmin, wmic), disabling boot recovery (bcdedit), deleting backups (wbadmin), clearing
     event logs, disabling Defender (in normal mode that process is terminated immediately, and the program
     that started it is paused)

When triggered: pause the programs writing the most data (Microsoft Defender then scans them)
        -> disable every network adapter (fall back to a firewall block) -> write the log
        -> full-screen red warning (all screens, steady red, alarm sound); adapters re-enabled while the
           warning is open are disabled again
        (optional: HIBERNATE_ON_TRIGGER = True hibernates right away so encryption stops)

Also: new programs, scripts and archives in Downloads or on the Desktop are scanned by Microsoft Defender
      once they finish downloading, and the user is told if it finds a threat.
      A separate health check (scheduled task, no RansomGuard.exe needed) warns at sign-in and daily when
      background protection is gone (e.g. removed by Defender by mistake) or not running.

Usage (Windows; normal mode needs administrator rights):
  python ransom_guard.py             monitor (the packaged .exe opens the control panel when run without options)
  python ransom_guard.py --monitor   monitor (used by the scheduled task)
  python ransom_guard.py --gui       control panel: install, restore network, preview warning, uninstall
  python ransom_guard.py --dry-run   test mode: log and show alerts only, never cut the network
  python ransom_guard.py --restore   restore the network and restart background monitoring
  python ransom_guard.py --install   install / update background monitoring (the .exe is copied to Program Files)
  python ransom_guard.py --update    open the control panel and update to the latest release right away
  python ransom_guard.py --test-alert  preview the full-screen warning (no detection, no network cut)
  python ransom_guard.py --watch D:\\Data --watch E:\\Backup   watch custom folders
  python ransom_guard.py --lang en   English interface (zh = Traditional Chinese; defaults to the Windows
                                     display language and can be switched in the control panel)

Requires: pip install watchdog
Log file: %LOCALAPPDATA%\\RansomGuard\\guard.log

Build a single executable: run build.bat (output dist\\RansomGuard.exe, with icon.ico from make_icon.py
packed inside; without it the window, taskbar and shortcut show PyInstaller's default icon)

Download and update: https://github.com/leo-code-del/RansomGuard/releases
  Download the new RansomGuard.exe -> run it -> click "Install / update and start monitoring"
"""

import argparse
import base64
import ctypes
import functools
import hashlib
import io
import json
import logging
import math
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.request  # imported up front: the update must not depend on loading modules later
import uuid
import zipfile
from collections import Counter, deque
from logging.handlers import RotatingFileHandler
from pathlib import Path

VERSION = "1.7.0"  # bump this for a new release and create the matching GitHub Release (v1.7.0)
IS_WINDOWS = os.name == "nt"
FROZEN = bool(getattr(sys, "frozen", False))  # running as an .exe packaged by PyInstaller
TASK_NAME = "RansomGuard"
INSTALL_DIR = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "RansomGuard"
INSTALL_EXE = INSTALL_DIR / "RansomGuard.exe"
UPDATE_API = "https://api.github.com/repos/leo-code-del/RansomGuard/releases/latest"
UPDATED_TO = None  # version install() just downloaded from GitHub, if any

# =============== Settings you can tune ===============
WINDOW_SEC = 30              # counting window (seconds)
BROKEN_THRESHOLD = 8         # trigger when this many files "break" within the window
EXT_CHANGE_THRESHOLD = 10    # trigger when this many files get unknown extensions within the window
ENTROPY_LIMIT = 7.5          # max entropy for text files (bits/byte; encrypted data is ~7.9-8.0)
ENTROPY_MIN_SIZE = 4096      # skip the entropy check below this size (too little data to judge)
NOTE_DIR_THRESHOLD = 3       # trigger when ransom notes appear in this many folders within the window
PROCESS_MONITOR = True       # watch new processes and stop destructive commands (deleting restore points...)
CHECK_INTERVAL = 15          # seconds between periodic checks of canary files and monitor health
HIBERNATE_ON_TRIGGER = False  # True: hibernate right after cutting the network so encryption stops
PAUSE_ON_TRIGGER = True      # pause the programs writing the most data, and the one behind a destructive command
DEFENDER_SCAN_ON_TRIGGER = True  # have Microsoft Defender scan the paused programs and run a quick scan
DEFENDER_SCAN_DOWNLOADS = True   # have Defender scan new programs, scripts and archives in Downloads / on the Desktop
# ============================================

CANARY_NAMES = ["!!!_canary_do_not_delete.docx", "!!!_canary_do_not_delete.xlsx", "zzz_canary_do_not_delete.docx"]
# names used before v1.3.0; the monitor deletes them when it starts
LEGACY_CANARY_NAMES = ["!!!_canary_勿刪.docx", "!!!_canary_勿刪.xlsx", "zzz_canary_勿刪.docx"]
# what canary files contained before v1.6.1 (plain text, so Word and Excel called them corrupt); still
# accepted as intact, and replaced by the current content when the monitor starts
LEGACY_CANARY_BYTES = ((
    "This is a ransomware canary file (RansomGuard). Do not open, modify, move or delete it.\n"
    "這是防勒索病毒的誘餌檔（RansomGuard），請勿開啟、修改、移動或刪除。\n"
) * 200).encode("utf-8")

# Canary files are real Word / Excel files: opening one explains what it is, and Word and Excel suggest
# opening it read-only. Stored uncompressed with fixed timestamps, so every version writes the same bytes.
# (heading?, text); the text must not contain & < >
_CANARY_TEXT = [
    (True, "RansomGuard 誘餌檔：請直接關閉，不要修改"),
    (True, "RansomGuard canary file: please close it without changes"),
    (False, "這個檔案用來偵測勒索病毒。修改、儲存、移動或刪除它，RansomGuard 會以為電腦中了勒索病毒，並自動切斷網路。"),
    (False, "This file detects ransomware. If it is modified, saved, moved or deleted, RansomGuard assumes the "
            "computer has ransomware and cuts off the network."),
    (False, "如果不小心觸發了：開啟桌面上的「RansomGuard」，按「恢復網路並重新開啟監控」。"),
    (False, "If that happens by mistake: open \"RansomGuard\" on the desktop and click \"Restore network and "
            "restart monitoring\"."),
]
_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_RELS_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
_CT_NS = "http://schemas.openxmlformats.org/package/2006/content-types"
_OOXML_CT = "application/vnd.openxmlformats-officedocument."


def _ooxml(main: str, parts: dict) -> bytes:
    """A minimal Office Open XML package. main: path of the main part; parts: {path: (content type, xml)}."""
    types = "".join(f'<Override PartName="/{n}" ContentType="{_OOXML_CT}{ct}"/>'
                    for n, (ct, _) in parts.items() if ct)  # .rels parts are covered by the Default
    files = {
        "[Content_Types].xml": f'<Types xmlns="{_CT_NS}"><Default Extension="rels" ContentType='
                               f'"application/vnd.openxmlformats-package.relationships+xml"/>'
                               f'<Default Extension="xml" ContentType="application/xml"/>{types}</Types>',
        "_rels/.rels": f'<Relationships xmlns="{_RELS_NS}"><Relationship Id="rId1" '
                       f'Type="{_REL}/officeDocument" Target="{main}"/></Relationships>',
        **{n: xml for n, (_, xml) in parts.items()},
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        for name, xml in files.items():
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 0  # otherwise it depends on the system that built the program
            z.writestr(info, ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n' + xml).encode("utf-8"))
    return buf.getvalue()


def _rels(*rels) -> str:
    return f'<Relationships xmlns="{_RELS_NS}">' + "".join(
        f'<Relationship Id="rId{i}" Type="{_REL}/{t}" Target="{target}"/>'
        for i, (t, target) in enumerate(rels, 1)) + "</Relationships>"


def _docx_par(head: bool, text: str) -> str:
    size = ('<w:b/><w:color w:val="C00000"/><w:sz w:val="40"/><w:szCs w:val="40"/>' if head else
            '<w:sz w:val="28"/><w:szCs w:val="28"/>')
    return f"<w:p><w:r><w:rPr>{size}</w:rPr><w:t>{text}</w:t></w:r></w:p>"


def _xlsx_row(i: int, head: bool, text: str) -> str:
    style = ' s="1"' if head else ""  # cell format 1 = the bold red font in styles.xml
    return f'<row r="{i}"><c r="A{i}" t="inlineStr"{style}><is><t>{text}</t></is></c></row>'


_WML = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
_SML = 'xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
CANARY_DOCX = _ooxml("word/document.xml", {
    "word/document.xml": ("wordprocessingml.document.main+xml", f"<w:document {_WML}><w:body>"
                          + "".join(_docx_par(*t) for t in _CANARY_TEXT) + "</w:body></w:document>"),
    "word/_rels/document.xml.rels": ("", _rels(("settings", "settings.xml"))),
    "word/settings.xml": ("wordprocessingml.settings+xml",
                          f'<w:settings {_WML}><w:writeProtection w:recommended="1"/></w:settings>'),
})
CANARY_XLSX = _ooxml("xl/workbook.xml", {
    "xl/workbook.xml": ("spreadsheetml.sheet.main+xml",
                        f'<workbook {_SML} xmlns:r="{_REL}"><fileSharing readOnlyRecommended="1"/>'
                        '<sheets><sheet name="RansomGuard" sheetId="1" r:id="rId1"/></sheets></workbook>'),
    "xl/_rels/workbook.xml.rels": ("", _rels(("worksheet", "worksheets/sheet1.xml"), ("styles", "styles.xml"))),
    "xl/worksheets/sheet1.xml": ("spreadsheetml.worksheet+xml",
                                 f'<worksheet {_SML}><cols><col min="1" max="1" width="120" customWidth="1"/></cols>'
                                 "<sheetData>" + "".join(_xlsx_row(i, *t) for i, t in enumerate(_CANARY_TEXT, 1))
                                 + "</sheetData></worksheet>"),
    "xl/styles.xml": ("spreadsheetml.styles+xml",
                      f'<styleSheet {_SML}><fonts count="2"><font><sz val="11"/><name val="Calibri"/></font>'
                      '<font><b/><sz val="16"/><color rgb="FFC00000"/><name val="Calibri"/></font></fonts>'
                      '<fills count="2"><fill><patternFill patternType="none"/></fill>'
                      '<fill><patternFill patternType="gray125"/></fill></fills>'
                      '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
                      '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
                      '<cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
                      '<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/></cellXfs>'
                      '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>'
                      "</styleSheet>"),
})


def canary_bytes(path) -> bytes:
    """What the canary file at `path` contains."""
    return CANARY_XLSX if Path(path).suffix.lower() == ".xlsx" else CANARY_DOCX


def canary_intact(path, data: bytes) -> bool:
    return data == canary_bytes(path) or data == LEGACY_CANARY_BYTES


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

# Destructive commands commonly used by ransomware/intruders (matched against the lower-cased command line)
_SHADOW = ("刪除系統還原點", "deleting restore points")
_BOOT = ("關閉 Windows 開機修復", "disabling Windows boot recovery")
_DANGEROUS_CMDS = [
    (r"vssadmin(\.exe)?\W.*\bdelete\s+shadows", *_SHADOW),
    (r"vssadmin(\.exe)?\W.*\bresize\s+shadowstorage", "縮小還原點空間（等於刪除還原點）",
     "shrinking restore point storage (same as deleting them)"),
    (r"\bshadowcopy\b.*\bdelete\b", *_SHADOW),
    (r"win32_shadowcopy.*(\.delete\(|remove-(cim|wmi)\w*)", *_SHADOW),
    (r"bcdedit(\.exe)?\W.*recoveryenabled\s+(no|off|false|0)\b", *_BOOT),
    (r"bcdedit(\.exe)?\W.*bootstatuspolicy\s+ignoreallfailures", *_BOOT),
    (r"wbadmin(\.exe)?\W.*\bdelete\s+(catalog|systemstatebackup|backup)", "刪除 Windows 備份",
     "deleting Windows backups"),
    (r"wevtutil(\.exe)?\W+(cl|clear-log)\s", "清除事件紀錄", "clearing event logs"),
    (r"set-mppreference\b.*-disable(realtimemonitoring|behaviormonitoring|ioavprotection"
     r"|scriptscanning|blockatfirstseen)\s+(\$true|1)\b", "關閉 Windows Defender 防護",
     "disabling Windows Defender protection"),
]
DANGEROUS_CMDS = [(re.compile(p), zh, en) for p, zh, en in _DANGEROUS_CMDS]
# Programs that actually run those commands. Any other program whose command line contains them
# (git commit -m "...", grep, an editor opening a file) only mentions them; matching those once cut
# the network during a git commit.
COMMAND_HOSTS = {"vssadmin.exe", "wmic.exe", "bcdedit.exe", "wbadmin.exe", "wevtutil.exe", "diskshadow.exe",
                 "cmd.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe", "wscript.exe", "cscript.exe",
                 "mshta.exe"}
_PS_ENCODED = re.compile(r"(?:^|\s)[-/]e(?:c|nc?\w*)?\s+([A-Za-z0-9+/=]{12,})", re.IGNORECASE)

log = logging.getLogger("RansomGuard")
LANG = "zh"      # interface language: zh / en, set by init_lang()
_LANG_ARG = None  # language given with --lang on the command line


def tr(zh: str, en: str) -> str:
    """Return the Chinese or English text for the interface language."""
    return en if LANG == "en" else zh


# ---------------- Basic helpers ----------------
def app_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") if IS_WINDOWS else None
    d = Path(base) / "RansomGuard" if base else Path.home() / ".ransom_guard"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _system32() -> Path:
    """Absolute path of the system folder. External programs always run by absolute path, so a fake
    powershell.exe planted in the current folder can't run with this program's administrator rights."""
    if IS_WINDOWS:
        buf = ctypes.create_unicode_buffer(260)
        if ctypes.windll.kernel32.GetSystemDirectoryW(buf, 260):
            return Path(buf.value)
    return Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"


SYS32 = _system32()
POWERSHELL = str(SYS32 / "WindowsPowerShell" / "v1.0" / "powershell.exe")


def sys_exe(name: str) -> str:
    return str(SYS32 / name) if IS_WINDOWS else name


def fix_console_encoding():
    # When output goes to a file or pipe (not a console), the default encoding may not support Chinese and print crashes
    for s in (sys.stdout, sys.stderr):
        reconfigure = getattr(s, "reconfigure", None)
        if reconfigure is not None and not s.isatty():
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except ValueError:
                pass


def setup_logging():
    log.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    fh = RotatingFileHandler(app_dir() / "guard.log", maxBytes=1_000_000,
                             backupCount=3, encoding="utf-8")
    fh.setFormatter(fmt)
    log.addHandler(fh)
    if sys.stderr is not None:  # no console when run with pythonw
        sh = logging.StreamHandler()
        sh.setFormatter(fmt)
        log.addHandler(sh)


def _load_json(name: str) -> dict:
    """Read a JSON object from the app folder; a missing, damaged or non-object file counts as empty."""
    try:
        data = json.loads((app_dir() / name).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def load_state() -> dict:
    return _load_json("state.json")


def save_state(st: dict):
    (app_dir() / "state.json").write_text(
        json.dumps(st, ensure_ascii=False, indent=2), encoding="utf-8")


def load_settings() -> dict:
    return _load_json("settings.json")


def saved_lang():
    """Language chosen in the control panel; None if none (or an unknown one) was saved."""
    lang = load_settings().get("lang")
    return lang if lang in ("zh", "en") else None


def system_lang() -> str:
    """Chinese if the Windows display language is Chinese, English for any other language."""
    if IS_WINDOWS:
        try:
            return "zh" if ctypes.windll.kernel32.GetUserDefaultUILanguage() & 0x3FF == 0x04 else "en"
        except Exception:
            pass
    return "zh" if os.environ.get("LANG", "").lower().startswith("zh") else "en"


def init_lang(arg=None):
    """Interface language: --lang on the command line > language chosen in the control panel > Windows
    display language. Called again when the monitor triggers, to pick up a newly chosen language."""
    global LANG, _LANG_ARG
    if arg:
        _LANG_ARG = arg
    LANG = _LANG_ARG or saved_lang() or system_lang()


def set_lang(lang: str):
    global LANG
    LANG = lang
    st = load_settings()
    st["lang"] = lang
    (app_dir() / "settings.json").write_text(
        json.dumps(st, ensure_ascii=False, indent=2), encoding="utf-8")


def is_admin() -> bool:
    if not IS_WINDOWS:
        return getattr(os, "geteuid", lambda: -1)() == 0
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


class _PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", ctypes.c_uint32), ("cntUsage", ctypes.c_uint32),
                ("th32ProcessID", ctypes.c_uint32), ("th32DefaultHeapID", ctypes.c_size_t),
                ("th32ModuleID", ctypes.c_uint32), ("cntThreads", ctypes.c_uint32),
                ("th32ParentProcessID", ctypes.c_uint32), ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", ctypes.c_uint32), ("szExeFile", ctypes.c_wchar * 260)]


@functools.lru_cache(maxsize=None)
def kernel32():
    """kernel32 with the signatures this program uses. Handles are pointer-sized: without a restype ctypes
    would cut them to 32 bits."""
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    H, D, B, S = ctypes.c_void_p, ctypes.c_uint32, ctypes.c_bool, ctypes.c_wchar_p
    for name, res, args in (
            ("OpenProcess", H, [D, B, D]),
            ("CloseHandle", B, [H]),
            ("CreateJobObjectW", H, [H, S]),
            ("SetInformationJobObject", B, [H, ctypes.c_int, H, D]),
            ("AssignProcessToJobObject", B, [H, H]),
            ("CreateMutexW", H, [H, B, S]),
            ("WaitForSingleObject", D, [H, D]),
            ("QueryFullProcessImageNameW", B, [H, D, S, ctypes.POINTER(D)]),
            ("CreateToolhelp32Snapshot", H, [D, D]),
            ("Process32FirstW", B, [H, ctypes.POINTER(_PROCESSENTRY32W)]),
            ("Process32NextW", B, [H, ctypes.POINTER(_PROCESSENTRY32W)]),
            ("GetProcessIoCounters", B, [H, ctypes.POINTER(ctypes.c_uint64 * 6)]),
            ("GetProcessTimes", B, [H] + [ctypes.POINTER(ctypes.c_uint64)] * 4),
            ("MoveFileExW", B, [S, S, D])):
        fn = getattr(k32, name)
        fn.restype, fn.argtypes = res, args
    return k32


def process_path(pid: int) -> str:
    """Full path of a process's program file ("" if it can't be read or has exited)."""
    k32 = kernel32()
    h = k32.OpenProcess(0x1000, False, pid)  # QUERY_LIMITED_INFORMATION
    if not h:
        return ""
    buf = ctypes.create_unicode_buffer(1024)
    n = ctypes.c_uint32(len(buf))
    ok = k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(n))
    k32.CloseHandle(h)
    return buf.value if ok else ""


def delete_at_restart(path):
    kernel32().MoveFileExW(str(path), None, 4)  # MOVEFILE_DELAY_UNTIL_REBOOT


_JOB = None
_MUTEX = None


def kill_with_me(proc):
    """Put a child process in a Job Object: it exits when this program exits (even when killed),
    so no orphaned PowerShell is left running in the background."""
    global _JOB
    if not IS_WINDOWS:
        return
    k32 = kernel32()
    if _JOB is None:
        class BASIC(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64),
                        ("PerJobUserTimeLimit", ctypes.c_int64),
                        ("LimitFlags", ctypes.c_uint32),
                        ("MinimumWorkingSetSize", ctypes.c_size_t),
                        ("MaximumWorkingSetSize", ctypes.c_size_t),
                        ("ActiveProcessLimit", ctypes.c_uint32),
                        ("Affinity", ctypes.c_size_t),
                        ("PriorityClass", ctypes.c_uint32),
                        ("SchedulingClass", ctypes.c_uint32)]

        class EXTENDED(ctypes.Structure):
            _fields_ = [("BasicLimitInformation", BASIC),
                        ("IoInfo", ctypes.c_uint64 * 6),
                        ("ProcessMemoryLimit", ctypes.c_size_t),
                        ("JobMemoryLimit", ctypes.c_size_t),
                        ("PeakProcessMemoryUsed", ctypes.c_size_t),
                        ("PeakJobMemoryUsed", ctypes.c_size_t)]
        job = k32.CreateJobObjectW(None, None)
        info = EXTENDED()
        info.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        # 9 = JobObjectExtendedLimitInformation
        if not job or not k32.SetInformationJobObject(job, 9, ctypes.byref(info),
                                                      ctypes.sizeof(info)):
            log.warning(tr("無法建立 Job Object（錯誤 %d）", "Could not create Job Object (error %d)"),
                        ctypes.get_last_error())
            return
        _JOB = job
    h = k32.OpenProcess(0x0100 | 0x0001, False, proc.pid)  # SET_QUOTA | TERMINATE
    if not h or not k32.AssignProcessToJobObject(_JOB, h):
        log.warning(tr("無法把子程序 %s 放進 Job Object（錯誤 %d）",
                       "Could not add child process %s to Job Object (error %d)"),
                    proc.pid, ctypes.get_last_error())
    if h:
        k32.CloseHandle(h)


def restart_if_borrowed_files() -> bool:
    """A one-file exe normally runs as the child of its own unpacker, which names the unpacked folder
    _MEI<its PID><digit>. If another program started this exe with its own environment (control panels
    before 1.5.2 did when reopening after an update), this process runs on that program's unpacked
    files, which vanish when it exits. Start again as a fresh program in that case (only once);
    returns True if this process should exit."""
    if not (IS_WINDOWS and FROZEN) or os.environ.get("RG_FRESH_START"):
        return False
    name = os.path.basename(getattr(sys, "_MEIPASS", ""))
    if not re.fullmatch(r"_MEI\d+", name) or re.fullmatch(rf"_MEI{os.getppid()}\d", name):
        return False  # not a folder name we understand, or unpacked by our own parent: fine
    env = fresh_env()
    env["RG_FRESH_START"] = "1"
    subprocess.Popen([sys.executable, *sys.argv[1:]], env=env)
    return True


def fresh_env() -> dict:
    """This environment without PyInstaller's unpacking variables, so a one-file exe started with it
    unpacks its own files instead of reusing (and later losing) ours."""
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("_PYI_") and k not in ("_MEIPASS2", "RG_FRESH_START")}
    env["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
    return env


def exit_with_launcher():
    """A one-file .exe is really two processes: the outer one unpacks, the inner one is this program. Task
    Scheduler only ends the outer one, so exit together with it; otherwise the monitor becomes an
    orphan that can't be stopped."""
    if not (IS_WINDOWS and FROZEN):
        return
    parent = process_path(os.getppid())
    if not parent or norm(parent) != norm(sys.executable):
        return  # parent is not this program (e.g. a onedir build); nothing to do
    k32 = kernel32()
    h = k32.OpenProcess(0x00100000, False, os.getppid())  # SYNCHRONIZE
    if not h:
        return

    def wait():
        k32.WaitForSingleObject(h, 0xFFFFFFFF)
        log.info(tr("外層程序已結束，監控跟著結束", "Launcher process exited, so monitoring exits too"))
        os._exit(0)
    threading.Thread(target=wait, daemon=True).start()


def single_instance() -> bool:
    """Allow only one real monitor at a time; return False if one is already running."""
    global _MUTEX
    if not IS_WINDOWS:
        return True
    _MUTEX = kernel32().CreateMutexW(None, False, "Global\\RansomGuardMonitor")
    return ctypes.get_last_error() != 183  # ERROR_ALREADY_EXISTS


def alert(title: str, msg: str):
    """Show a topmost alert box (without blocking the monitor)."""
    if not IS_WINDOWS:
        log.info(tr("[警告視窗] %s：%s", "[Alert] %s: %s"), title, msg.replace("\n", " "))
        return

    def _box():
        # MB_ICONERROR | MB_SYSTEMMODAL | MB_TOPMOST
        ctypes.windll.user32.MessageBoxW(None, msg, title, 0x10 | 0x1000 | 0x40000)
    threading.Thread(target=_box).start()


# Full-screen warning drawn with PowerShell + WinForms: covers every screen in steady red (no flashing, which
# strains the eyes) and plays an alarm.
# (The script goes on the command line and the data in an environment variable; neither is written to
#  a file, so nothing can swap them before they run as administrator. The data stays off the command
#  line because a detection reason may contain commands like vssadmin delete shadows, and Defender
#  would then block the whole warning.)
ALERT_PS1 = r'''
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

$info = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:RG_ALERT_INFO)) | ConvertFrom-Json
$isTest = ($info.status -eq 'test')
$t = $info.t  # on-screen text (prepared by Python in the chosen language)

$script:ack = $false
$script:forms = New-Object System.Collections.ArrayList
$script:tick = 0
$script:bright = [System.Drawing.Color]::FromArgb(205, 0, 0)
$script:dark   = [System.Drawing.Color]::FromArgb(105, 0, 0)
$yellow = [System.Drawing.Color]::FromArgb(255, 225, 0)
$white  = [System.Drawing.Color]::White
$fontName = $t.font

function Close-All {
    $script:ack = $true
    foreach ($f in @($script:forms)) { $f.Close() }
}

function Add-Text($form, [string]$text, [double]$size, [bool]$bold, $color, [int]$y, [int]$x, [int]$w, [string]$align) {
    $style = if ($bold) { [System.Drawing.FontStyle]::Bold } else { [System.Drawing.FontStyle]::Regular }
    $fnt = New-Object System.Drawing.Font($fontName, [single]$size, $style)
    $flags = [System.Windows.Forms.TextFormatFlags]::WordBreak
    $sz = [System.Windows.Forms.TextRenderer]::MeasureText($text, $fnt, (New-Object System.Drawing.Size($w, 10000)), $flags)
    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Font = $fnt
    $lbl.Text = $text
    $lbl.ForeColor = $color
    $lbl.TextAlign = $align
    $lbl.SetBounds($x, $y, $w, $sz.Height + 12)
    $form.Controls.Add($lbl)
    return ($y + $sz.Height + 12)
}

foreach ($scr in [System.Windows.Forms.Screen]::AllScreens) {
    $f = New-Object System.Windows.Forms.Form
    $f.FormBorderStyle = 'None'
    $f.StartPosition = 'Manual'
    $f.Bounds = $scr.Bounds
    $f.TopMost = $true
    $f.ShowInTaskbar = $true
    $f.Text = $t.window
    $f.BackColor = $script:bright
    $W = $scr.Bounds.Width
    $H = $scr.Bounds.Height
    $k = $H / 1080.0

    $y = [int](60 * $k)
    $y = Add-Text $f $t.title (50 * $k) $true $white $y 40 ($W - 80) 'MiddleCenter'
    $y = Add-Text $f $t.net (30 * $k) $true $yellow $y 40 ($W - 80) 'MiddleCenter'
    $y += [int](20 * $k)
    $y = Add-Text $f $t.detail (15 * $k) $false $white $y 80 ($W - 160) 'MiddleCenter'
    $y += [int](25 * $k)
    $y = Add-Text $f $t.next (22 * $k) $true $yellow $y ([int]($W * 0.16)) ([int]($W * 0.68)) 'MiddleLeft'
    $y = Add-Text $f $t.steps (20 * $k) $false $white $y ([int]($W * 0.16)) ([int]($W * 0.68)) 'MiddleLeft'
    $y += [int](20 * $k)
    $y = Add-Text $f $t.hint (16 * $k) $false $white $y 80 ($W - 160) 'MiddleCenter'

    $btnFont = New-Object System.Drawing.Font($fontName, [single](18 * $k), [System.Drawing.FontStyle]::Bold)
    $bw = [int](460 * $k); $bh = [int](72 * $k); $gap = [int](40 * $k)
    $by = [Math]::Min($y + [int](30 * $k), $H - $bh - [int](30 * $k))
    $count = if ($isTest) { 1 } else { 2 }
    $bx = [int](($W - ($count * $bw + ($count - 1) * $gap)) / 2)

    $ok = New-Object System.Windows.Forms.Button
    $ok.Text = $t.ok
    $ok.Font = $btnFont
    $ok.FlatStyle = 'Flat'
    $ok.BackColor = $white
    $ok.ForeColor = $script:dark
    $ok.SetBounds($bx, $by, $bw, $bh)
    $ok.add_Click({ Close-All })
    $f.Controls.Add($ok)

    if (-not $isTest) {
        $sd = New-Object System.Windows.Forms.Button
        $sd.Text = $t.shutdown
        $sd.Font = $btnFont
        $sd.FlatStyle = 'Flat'
        $sd.BackColor = [System.Drawing.Color]::Black
        $sd.ForeColor = $yellow
        $sd.SetBounds($bx + $bw + $gap, $by, $bw, $bh)
        $sd.add_Click({
            $r = [System.Windows.Forms.MessageBox]::Show($this.FindForm(), $t.confirm, 'RansomGuard', [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
            if ($r -eq 'Yes') { Stop-Computer -Force }
        })
        $f.Controls.Add($sd)
    }

    $f.add_FormClosing({
        if (-not $script:ack -and $_.CloseReason -eq [System.Windows.Forms.CloseReason]::UserClosing) { $_.Cancel = $true }
    })
    $f.add_Shown({ $this.Activate(); $this.BringToFront() })
    [void]$script:forms.Add($f)
}

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 700
$timer.add_Tick({
    $script:tick++
    if ($script:tick -le 24 -and ($script:tick % 2)) { [System.Media.SystemSounds]::Hand.Play() }
    if (($script:tick % 4) -eq 0) { foreach ($f in $script:forms) { $f.TopMost = $true } }
})

for ($i = 1; $i -lt $script:forms.Count; $i++) { $script:forms[$i].Show() }
$timer.Start()
[System.Windows.Forms.Application]::Run($script:forms[0])
if (-not $script:ack) { exit 3 }  # not closed by the user's button (e.g. closed by another program): let Python show a regular alert
'''


def fullscreen_alert(reason: str, status: str, wait: bool = False, paused=()):
    """Full-screen warning. status: cut (network cut) / partial (cut may be incomplete) / test.
    paused: the programs pause_writers() found."""
    log.warning(tr("[全螢幕警告] %s（%s）", "[Full-screen warning] %s (%s)"), reason, status)
    if not IS_WINDOWS:
        return None
    try:
        reason = reason if len(reason) <= 160 else reason[:157] + "..."
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        detail = tr(f"偵測時間：{now}\n原因：{reason}", f"Detected at: {now}\nReason: {reason}")
        if paused:
            detail += "\n" + tr("可疑的程式：", "Suspicious programs: ") + tr("、", ", ").join(
                tr(f"{p['name']}（PID {p['pid']}，{p['result']}）", f"{p['name']} (PID {p['pid']}, {p['result']})")
                for p in paused)
        steps = [
            tr("1. 不要恢復網路，也不要插上備份硬碟或隨身碟",
               "1. Do not restore the network, and do not plug in backup drives or USB sticks"),
            tr("2. 如果檔案還在一個一個被改名、打不開，立刻按住電源鍵強制關機",
               "2. If files are still being renamed or becoming unreadable, hold the power button "
               "to force the computer off now"),
            tr("3. 用手機拍下桌面或資料夾裡出現的勒索訊息",
               "3. Take a photo of any ransom note on the desktop or in folders with your phone"),
            tr("4. 用手機（不要用這台電腦）更改 Email、銀行等重要帳號的密碼",
               "4. Using your phone (not this computer), change the passwords of important accounts "
               "such as email and banking"),
        ]
        info = json.dumps({"status": status, "t": {
            "window": tr("RansomGuard 警告", "RansomGuard warning"),
            "font": tr("Microsoft JhengHei UI", "Segoe UI"),
            "title": tr("！！ 偵測到疑似勒索病毒 ！！", "!! Possible ransomware detected !!"),
            "net": {"cut": tr("網路已自動切斷", "The network has been cut off automatically"),
                    "partial": tr("網路可能沒有完全切斷！請立刻拔掉網路線、關閉 Wi-Fi",
                                  "The network may not be fully cut off! Unplug the network "
                                  "cable and turn off Wi-Fi now")
                    }.get(status, tr("（測試模式：沒有切斷網路）", "(Test mode: the network was not cut off)")),
            "detail": detail,
            "next": tr("接下來請這樣做：", "What to do now:"),
            "steps": "\n".join(steps),
            "hint": (tr("這是測試，按下方按鈕關閉即可。", "This is a test. Click the button below to close it.")
                     if status == "test" else
                     tr(f"如果確認是誤判（例如是你自己動到誘餌檔）：關閉這個視窗後，{restore_hint()}。",
                        "If this is a false alarm (e.g. you touched a canary file yourself): "
                        f"close this window, then {restore_hint()}.")),
            "ok": tr("我知道了（關閉警告）", "I understand (close warning)"),
            "shutdown": tr("立即強制關機", "Force shut down now"),
            "confirm": tr("確定要立即強制關機嗎？\n尚未儲存的工作會遺失。",
                          "Force the computer to shut down now?\nUnsaved work will be lost."),
        }}, ensure_ascii=False)
        env = dict(os.environ, RG_ALERT_INFO=base64.b64encode(info.encode("utf-8")).decode("ascii"))
        proc = subprocess.Popen(
            ps_encoded_args(ALERT_PS1, "-STA", "-WindowStyle", "Hidden"),
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env,
            creationflags=CREATE_NO_WINDOW)
        assert proc.stderr is not None
        try:
            # exiting with an error within 4 s = the window never opened or another program closed it
            rc = proc.wait(timeout=4)
            if rc != 0:
                err = proc.stderr.read().decode("utf-8", "replace").strip()
                raise RuntimeError(tr(f"全螢幕警告啟動失敗（代碼 {rc}）：{err[:300]}",
                                      f"Full-screen warning failed to start (code {rc}): {err[:300]}"))
        except subprocess.TimeoutExpired:
            # still running = the warning is showing; keep draining stderr so a full pipe can't freeze the window
            threading.Thread(target=proc.stderr.read, daemon=True).start()
        if wait:
            proc.wait()
        return proc
    except Exception as ex:
        log.error(tr("%s；改用一般警告視窗", "%s; using a regular alert instead"), ex)
        alert(tr("RansomGuard：偵測到疑似勒索病毒", "RansomGuard: possible ransomware detected"),
              tr(f"{reason}\n\n狀態：{status}", f"{reason}\n\nStatus: {status}"))
        return None


def ps_encoded_args(script: str, *opts: str) -> list:
    """Run a PowerShell script with -EncodedCommand (no file needed)."""
    enc = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    return [POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", *opts,
            "-EncodedCommand", enc]


def entropy(data: bytes) -> float:
    n = len(data)
    if n == 0:
        return 0.0
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def norm(path) -> str:
    return os.path.normcase(os.path.abspath(str(path)))


# ---------------- Watched folders ----------------
_KNOWN_FOLDERS = {
    "Desktop":   "B4BFCC3A-DB2C-424C-B029-7FE99A87C641",
    "Documents": "FDD39AD0-238F-46AF-ADB4-6C85480369C7",
    "Pictures":  "33E28130-4E1E-4676-835A-98395C3BC3BB",
    "Downloads": "374DE290-123F-4565-9164-39C4925E467B",
    "Videos":    "18989B1D-99B5-455B-841C-AB7C74E4DDFC",
    "Music":     "4BD8D571-6D19-48D3-BE97-422220080E43",
}


def _known_folder(name: str):
    """Actual Windows path of Documents, Pictures etc. (including OneDrive redirection)."""
    if IS_WINDOWS:
        try:
            class GUID(ctypes.Structure):
                _fields_ = [("Data1", ctypes.c_ulong), ("Data2", ctypes.c_ushort),
                            ("Data3", ctypes.c_ushort), ("Data4", ctypes.c_ubyte * 8)]
            g = GUID.from_buffer_copy(uuid.UUID(_KNOWN_FOLDERS[name]).bytes_le)
            p = ctypes.c_wchar_p()
            if ctypes.windll.shell32.SHGetKnownFolderPath(ctypes.byref(g), 0, None,
                                                          ctypes.byref(p)) == 0 and p.value:
                path = Path(p.value)
                ctypes.windll.ole32.CoTaskMemFree(p)
                return path
        except Exception:
            pass
    return Path.home() / name


def default_watch_dirs():
    dirs = []
    for name in _KNOWN_FOLDERS:
        p = _known_folder(name)
        if p.is_dir() and norm(p) not in {norm(d) for d in dirs}:
            dirs.append(p)
    return dirs


def default_canary_dirs():
    return [p for p in (_known_folder("Documents"), _known_folder("Pictures")) if p.is_dir()]


def plant_canaries(dirs, upgrade=False):
    """Create missing canary files and reset changed ones. upgrade: also replace the plain-text canary files of
    versions before 1.6.1 (only when no other monitor can be watching them)."""
    paths = []
    for d in dirs:
        for name in CANARY_NAMES:
            p = Path(d) / name
            try:
                data = p.read_bytes() if p.exists() else None
                if data is not None and not canary_intact(p, data):
                    log.warning(tr("誘餌檔內容和預期不同（程式沒執行時被改過？）：%s",
                                   "Canary file content is not what was expected "
                                   "(changed while the program was not running?): %s"), p)
                    alert(tr("RansomGuard 注意", "RansomGuard notice"),
                          tr(f"誘餌檔在程式沒執行時被修改過：\n{p}\n\n請確認電腦是否異常。",
                             f"A canary file was modified while the program was not running:\n{p}\n\n"
                             "Please check whether something is wrong with this computer."))
                if data is None or not canary_intact(p, data) or (upgrade and data != canary_bytes(p)):
                    p.write_bytes(canary_bytes(p))
                paths.append(p)
            except OSError as ex:
                log.warning(tr("無法建立誘餌檔 %s：%s", "Could not create canary file %s: %s"), p, ex)
    return paths


def check_canaries(canaries):
    """Describe the first canary file that is not intact; None if all are fine."""
    for p in canaries:
        try:
            if not canary_intact(p, Path(p).read_bytes()):
                return tr(f"誘餌檔內容被修改：{p}", f"Canary file was modified: {p}")
        except FileNotFoundError:
            if not Path(p).parent.is_dir():
                continue  # the whole folder is gone (e.g. OneDrive was unlinked), not an attack on the file
            return tr(f"誘餌檔不見了：{p}", f"Canary file is missing: {p}")
        except OSError:
            pass  # temporarily locked (e.g. antivirus is scanning); check again next time
    return None


def periodic_check(handler, canaries):
    """Check canary files periodically: file events can be missed (full buffer, file locked while read)."""
    if handler.triggered_at is not None:
        return
    reason = check_canaries(canaries)
    if reason:
        handler.fire(reason + tr("（定期檢查發現）", " (found by periodic check)"))


# ---------------- Is a file "broken"? ----------------
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
    if size >= ENTROPY_MIN_SIZE:
        h = entropy(data)
        if h > ENTROPY_LIMIT:
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


def dangerous_command(cmdline: str):
    """Describe the command if it is a destructive command commonly used by ransomware, else None.
    PowerShell -EncodedCommand payloads are decoded before matching."""
    if not cmdline:
        return None
    texts = [cmdline]
    for m in _PS_ENCODED.finditer(cmdline):
        try:
            texts.append(base64.b64decode(m.group(1)).decode("utf-16-le", "ignore"))
        except ValueError:
            pass
    for text in texts:
        low = text.lower()
        for pat, zh, en in DANGEROUS_CMDS:
            if pat.search(low):
                return tr(zh, en)
    return None


def dangerous_process(name: str, cmdline: str):
    """dangerous_command() for a new process, but only for programs that can run such commands."""
    if (name or "").lower() not in COMMAND_HOSTS:
        return None
    return dangerous_command(cmdline)


# ---------------- Event handling ----------------
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
                while q and now - q[0][0] > WINDOW_SEC:
                    q.popleft()
                n = len({k for _, k in q})
            if n >= threshold:
                self.fire(tr(f"{WINDOW_SEC} 秒內有 {n} 個{label}（例如 {example}）",
                             f"{n} {label} within {WINDOW_SEC} seconds (e.g. {example})"))

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
                    if not canary_intact(src, Path(src).read_bytes()):
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
                self._count(self.extchg, path, EXT_CHANGE_THRESHOLD,
                            tr("檔案被改成陌生副檔名", "files renamed to unknown extensions"), path)

            # 4. Ransom notes
            if t in ("created", "moved") and is_ransom_note(os.path.basename(path)):
                log.warning(tr("出現疑似勒索訊息檔：%s", "Possible ransom note: %s"), path)
                self._count(self.notes, os.path.dirname(path), NOTE_DIR_THRESHOLD,
                            tr("資料夾出現勒索訊息檔", "folders with ransom notes"), path)

            # 2. Broken file content
            if t != "deleted" and not ignorable(path) and checkable(path):
                reason = self._broken(path)
                if reason:
                    log.info(tr("疑似被加密的檔案（%s）：%s", "File looks encrypted (%s): %s"), reason, path)
                    self._count(self.broken, path, BROKEN_THRESHOLD,
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


# ---------------- Process monitor (Windows) ----------------
# Get every new process's command line through WMI, one per line: PID <tab> parent PID <tab> name <tab> command line.
# WMI polling misses processes that exit between two polls: every 0.5 s catches those living ~0.25 s or
# longer (every 1 s needed ~1 s) for about 2% more of one CPU core. The kernel start trace (administrator
# only) is watched too and sometimes catches even shorter ones; for those, only COMMAND_HOSTS are looked up.
PROC_PS1 = r'''
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$hosts = @(__HOSTS__)
$q = "SELECT * FROM __InstanceCreationEvent WITHIN 0.5 WHERE TargetInstance ISA 'Win32_Process'"
Register-CimIndicationEvent -Query $q -SourceIdentifier RGProc -ErrorAction Stop
$trace = $true
try { Register-CimIndicationEvent -ClassName Win32_ProcessStartTrace -SourceIdentifier RGTrace -ErrorAction Stop }
catch { $trace = $false }
[Console]::Out.WriteLine("READY`t$trace"); [Console]::Out.Flush()
while ($true) {
    $e = Wait-Event
    $n = $e.SourceEventArgs.NewEvent
    Remove-Event -EventIdentifier $e.EventIdentifier
    if ($e.SourceIdentifier -eq 'RGTrace') {
        if ($hosts -notcontains "$($n.ProcessName)") { continue }
        $p = Get-CimInstance Win32_Process -Filter "ProcessId=$($n.ProcessID)" -ErrorAction SilentlyContinue
        if (-not $p) { continue }
    } else {
        $p = $n.TargetInstance
    }
    $line = '{0}{4}{1}{4}{2}{4}{3}' -f $p.ProcessId, $p.ParentProcessId, $p.Name, $p.CommandLine, "`t"
    [Console]::Out.WriteLine(($line -replace "[\r\n]", ' ')); [Console]::Out.Flush()
}
'''.replace("__HOSTS__", ", ".join(f"'{h}'" for h in sorted(COMMAND_HOSTS)))


class ProcessMonitor:
    """Watch new processes; terminate any running a destructive ransomware command (deleting restore points
    etc.) and trigger."""

    def __init__(self, on_hit, kill: bool):
        self.on_hit = on_hit
        self.kill = kill
        self.proc = None
        self.recent = deque(maxlen=256)  # PIDs already checked (both WMI sources can report a process)

    def start(self):
        self.proc = subprocess.Popen(
            ps_encoded_args(PROC_PS1, "-NonInteractive"),
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            creationflags=CREATE_NO_WINDOW)
        kill_with_me(self.proc)
        threading.Thread(target=self._read, args=(self.proc,), daemon=True).start()

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def stop(self):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.kill()

    def _read(self, proc):
        for raw in proc.stdout or ():
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            if line.startswith("READY"):
                log.info(tr("程序監控已啟動（即時追蹤：%s）", "Process monitor started (real-time trace: %s)"),
                         line.endswith("True"))
                continue
            parts = line.split("\t", 3)
            if len(parts) != 4:
                continue
            try:
                self._check(int(parts[0]), int(parts[1] or 0), parts[2], parts[3])
            except Exception:
                log.exception(tr("檢查程序時發生錯誤", "Error while checking a process"))

    def _check(self, pid, ppid, name, cmdline):
        if ppid == os.getpid() and name.lower() == "powershell.exe":  # started by this program itself
            return
        what = dangerous_process(name, cmdline)
        if not what or pid in self.recent:
            return
        self.recent.append(pid)
        if self.kill:
            try:
                os.kill(pid, signal.SIGTERM)  # TerminateProcess on Windows
                result = tr("已強制終止", "terminated")
            except OSError as ex:  # WinError 87: it already exited before it could be stopped
                result = (tr("已經結束", "already exited") if getattr(ex, "winerror", None) == 87 else
                          tr(f"無法終止：{ex}", f"could not terminate: {ex}"))
        else:
            result = tr("測試模式：未終止", "test mode: not terminated")
        if PAUSE_ON_TRIGGER:
            early = pause_ancestors(ppid, dry_run=not self.kill)
            record_paused(early)  # right away: after a first trigger no respond() follows to record them
            _early_paused.extend(early)
        log.critical(tr("可疑指令（%s）%s PID %s，父程序 PID %s，%s：%s",
                        "Suspicious command (%s) %s PID %s, parent PID %s, %s: %s"),
                     what, name, pid, ppid, result, cmdline)
        self.on_hit(tr(f"有程序在{what}：{name}（PID {pid}，{result}）{cmdline[:120]}",
                       f"A process is {what}: {name} (PID {pid}, {result}) {cmdline[:120]}"))


# ---------------- Pausing the encrypting program (Windows) ----------------
# File events don't say which program wrote a file, but a program that is encrypting writes far more than
# anything else. So on a trigger every process's write counters are read twice, PAUSE_SAMPLE_SEC apart, and
# the heaviest writers are paused (suspended, not killed: restoring the network after a false alarm lets
# them run again). Defender then scans their program files and removes what it recognises; on its own it
# often recognises new ransomware only some time after the encryption has begun.
PAUSE_SAMPLE_SEC = 1.0
PAUSE_MIN_WRITES = 20         # a program is paused if it wrote at least this many times during the sample...
PAUSE_MIN_BYTES = 256 * 1024  # ...and at least this much data
PAUSE_MAX = 5  # editors, browsers and cloud sync write ~1-2 MB/s even when idle; leave room for the real one
# Windows itself, Defender and the desktop are never paused, as long as they run from their own folder
# (malware can borrow a name, not the folder)
PAUSE_SAFE = {"registry", "memory compression", "secure system", "smss.exe", "csrss.exe", "wininit.exe",
              "winlogon.exe", "services.exe", "lsass.exe", "lsaiso.exe", "svchost.exe", "dwm.exe",
              "fontdrvhost.exe", "explorer.exe", "sihost.exe", "taskhostw.exe", "conhost.exe", "audiodg.exe",
              "spoolsv.exe", "wmiprvse.exe", "searchindexer.exe", "trustedinstaller.exe", "tiworker.exe",
              "msmpeng.exe", "nissrv.exe", "mpdefendercoreservice.exe", "securityhealthservice.exe",
              "mpcmdrun.exe"}
MPCMDRUN = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Windows Defender" / "MpCmdRun.exe"


def process_list() -> list:
    """[(pid, parent pid, program name)] of every running process."""
    k32 = kernel32()
    snap = k32.CreateToolhelp32Snapshot(0x2, 0)  # TH32CS_SNAPPROCESS
    if not snap or snap == ctypes.c_void_p(-1).value:
        return []
    procs = []
    e = _PROCESSENTRY32W(dwSize=ctypes.sizeof(_PROCESSENTRY32W))
    ok = k32.Process32FirstW(snap, ctypes.byref(e))
    while ok:
        procs.append((e.th32ProcessID, e.th32ParentProcessID, e.szExeFile))
        ok = k32.Process32NextW(snap, ctypes.byref(e))
    k32.CloseHandle(snap)
    return procs


def process_started(pid: int):
    """When a process started (a FILETIME number), or None if it can't be read."""
    k32 = kernel32()
    h = k32.OpenProcess(0x1000, False, pid)  # QUERY_LIMITED_INFORMATION
    if not h:
        return None
    t = [ctypes.c_uint64() for _ in range(4)]  # creation, exit, kernel, user
    ok = k32.GetProcessTimes(h, *(ctypes.byref(x) for x in t))
    k32.CloseHandle(h)
    return t[0].value if ok else None


def write_counters() -> dict:
    """{pid: (name, write operations, bytes written)} of every readable process except this program and its
    children."""
    k32 = kernel32()
    me, out, io = os.getpid(), {}, (ctypes.c_uint64 * 6)()
    for pid, ppid, name in process_list():
        if pid in (0, 4, me) or ppid == me:
            continue
        h = k32.OpenProcess(0x1000, False, pid)  # QUERY_LIMITED_INFORMATION
        if not h:
            continue
        if k32.GetProcessIoCounters(h, ctypes.byref(io)):
            out[pid] = (name, io[1], io[4])  # WriteOperationCount, WriteTransferCount
        k32.CloseHandle(h)
    return out


def heaviest_writers(before: dict, after: dict) -> list:
    """[(pid, name, writes, bytes)] of the processes that wrote enough between two write_counters(), most data
    first. A process that started in between (or whose PID was reused) counts everything it wrote."""
    rows = []
    for pid, (name, writes, size) in after.items():
        prev = before.get(pid)
        w0, s0 = prev[1:] if prev and prev[0] == name else (0, 0)
        if writes - w0 >= PAUSE_MIN_WRITES and size - s0 >= PAUSE_MIN_BYTES:
            rows.append((pid, name, writes - w0, size - s0))
    return sorted(rows, key=lambda r: r[3], reverse=True)


def trusted_process(name: str, path: str) -> bool:
    """A Windows, Defender or desktop process running from its own folder."""
    if name.lower() not in PAUSE_SAFE:
        return False
    if not path:  # Windows' minimal and protected processes can't be read (nor paused); a borrowed name can
        return True
    roots = [os.environ.get("SystemRoot", r"C:\Windows"),
             os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "Windows Defender"),
             os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "Microsoft", "Windows Defender")]
    p = norm(path)
    return any(p.startswith(norm(r) + os.sep) for r in roots)


def set_paused(pid: int, paused: bool) -> bool:
    """Suspend (paused=True) or resume every thread of a process."""
    k32 = kernel32()
    ntdll = ctypes.WinDLL("ntdll")
    fn = ntdll.NtSuspendProcess if paused else ntdll.NtResumeProcess
    fn.argtypes = [ctypes.c_void_p]
    fn.restype = ctypes.c_long
    h = k32.OpenProcess(0x0800, False, pid)  # PROCESS_SUSPEND_RESUME
    if not h:
        return False
    ok = fn(h) == 0  # STATUS_SUCCESS
    k32.CloseHandle(h)
    return ok


def pause_writers(dry_run: bool) -> list:
    """Pause the programs writing the most right now (test mode: only report them).
    Returns [{"pid", "name", "path", "paused", "result"}]."""
    try:
        before = write_counters()
        time.sleep(PAUSE_SAMPLE_SEC)
        rows = heaviest_writers(before, write_counters())
    except Exception:
        log.exception(tr("讀取程序寫入量失敗", "Failed to read how much processes write"))
        return []
    found = []
    for pid, name, writes, size in rows:
        path = process_path(pid)
        if trusted_process(name, path):
            continue
        p = _pause(pid, name, path, dry_run)
        log.critical(tr("大量寫入的程式 %s（PID %s，%d 次寫入、%d KB），%s：%s",
                        "Program writing heavily %s (PID %s, %d writes, %d KB), %s: %s"),
                     name, pid, writes, size // 1024, p["result"], path)
        found.append(p)
        if len(found) >= PAUSE_MAX:
            break
    if not found:
        log.info(tr("沒有找到正在大量寫入的程式", "No program is writing heavily right now"))
    return found


def record_paused(entries):
    """Remember the programs that were paused, so restore_network() resumes them if the user calls it a false
    alarm. Never raises: nothing may stop the network from being cut."""
    new = [p for p in entries if p["paused"]]
    if not new:
        return
    try:
        st = load_state()
        known = {p.get("pid") for p in st.get("paused", [])}
        st["paused"] = st.get("paused", []) + [p for p in new if p["pid"] not in known]
        save_state(st)
    except OSError:
        log.exception(tr("無法記錄被暫停的程式", "Could not record the paused programs"))


def _pause(pid, name, path, dry_run) -> dict:
    """Pause one process (test mode: don't); the entry pause_writers() and pause_ancestors() return for it."""
    if dry_run:
        paused, result = False, tr("測試模式：未暫停", "test mode: not paused")
    else:
        paused = set_paused(pid, True)
        result = tr("已暫停", "paused") if paused else tr("無法暫停", "could not pause")
    return {"pid": pid, "name": name, "path": path, "paused": paused, "result": result}


# Ransomware usually deletes restore points and backups *before* it encrypts anything, by starting
# vssadmin, wmic etc. ProcessMonitor stops that command, but the program that started it is not writing
# yet, so pause_writers() would not find it: its parent, grandparent... are paused right away instead.
ANCESTOR_LEVELS = 3
_early_paused = []  # what pause_ancestors() paused before the trigger; respond() reports it


def pause_ancestors(ppid: int, dry_run: bool) -> list:
    """Pause the process that started a destructive command and the ones above it, up to ANCESTOR_LEVELS,
    stopping at Windows itself (e.g. explorer.exe, which runs what the user double-clicks) and at this
    program. Each one must have started before the one below it, so a reused PID is never taken for a
    parent that has exited."""
    try:
        parents = {pid: (parent, name) for pid, parent, name in process_list()}
    except Exception:
        log.exception(tr("讀取程序清單失敗", "Failed to list processes"))
        return []
    found, pid, below = [], ppid, None
    for _ in range(ANCESTOR_LEVELS):
        if pid in (0, 4, os.getpid()) or pid not in parents:
            break
        started = process_started(pid)
        if below is not None and (started is None or started >= below):
            break
        name, path = parents[pid][1], process_path(pid)
        if trusted_process(name, path):
            break
        p = _pause(pid, name, path, dry_run)
        log.critical(tr("下達危險指令的程式 %s（PID %s），%s：%s",
                        "Program that started the destructive command %s (PID %s), %s: %s"),
                     name, pid, p["result"], path)
        found.append(p)
        pid, below = parents[pid][0], started
    return found


def defender_scan(path=None, timeout=600):
    """Scan one file (or run a quick scan) with Microsoft Defender, which removes what it finds.
    Returns MpCmdRun's exit code (0 = no threats, 2 = threat found), or None if it could not scan."""
    if not MPCMDRUN.is_file():
        return None
    args = ([str(MPCMDRUN), "-Scan", "-ScanType", "3", "-File", path] if path else
            [str(MPCMDRUN), "-Scan", "-ScanType", "1"])
    try:
        r = subprocess.run(args, capture_output=True, timeout=timeout, creationflags=CREATE_NO_WINDOW)
    except Exception as ex:
        log.error(tr("Defender 掃描失敗：%s", "Defender scan failed: %s"), ex)
        return None
    if r.returncode == 2 and b"CmdTool: Failed" in r.stdout + r.stderr:
        return None  # MpCmdRun also exits with 2 when it can't scan at all, e.g. the file is already gone
    return r.returncode


def scan_result(rc) -> str:
    return {0: tr("沒有發現威脅", "no threats found"),
            2: tr("發現威脅，由 Defender 處理", "threat found, Defender is handling it"),
            None: tr("Defender 無法掃描", "Defender could not scan it")}.get(
        rc, tr(f"結束代碼 {rc}", f"exit code {rc}"))


def ask_defender(paths):
    """After a trigger: Defender scans the files of the programs that were writing heavily, then runs a quick
    scan. (The network is cut by then, so only the signatures already on this computer are used.)"""
    for p in paths:
        log.warning(tr("Defender 掃描 %s：%s", "Defender scan of %s: %s"), p, scan_result(defender_scan(p)))
    log.warning(tr("Defender 快速掃描：%s", "Defender quick scan: %s"), scan_result(defender_scan(timeout=3600)))


def resume_paused(paused, report):
    """Restoring the network means the user called it a false alarm: let the programs paused at the trigger
    run again, but only the ones Defender still finds clean (with the network back it can ask its cloud)."""
    report(tr("恢復被暫停的程式...", "Resuming paused programs..."))
    for p in paused:
        pid, path = p.get("pid"), p.get("path") or ""
        label = f"{p.get('name')} (PID {pid})"
        now = process_path(pid) if isinstance(pid, int) else ""
        if not path or not now or norm(now) != norm(path):
            report(tr(f"  {label} 已經結束", f"  {label} has already exited") if path else
                   tr(f"  {label} 無法確認是哪個程式，維持暫停；重新開機會結束它",
                      f"  {label} could not be identified, so it stays paused; restarting the computer ends it"))
            continue
        rc = defender_scan(path)
        if rc != 0:
            log.warning(tr("%s 維持暫停（Defender：%s）", "%s stays paused (Defender: %s)"), label, scan_result(rc))
            report(tr(f"  {label} 維持暫停（Defender：{scan_result(rc)}）。重新開機會結束它",
                      f"  {label} stays paused (Defender: {scan_result(rc)}). Restarting the computer ends it"))
            continue
        ok = set_paused(pid, False)
        log.info(tr("恢復被暫停的程式 %s：%s", "Resuming paused program %s: %s"), label, ok)
        report(tr(f"  已恢復 {label}", f"  Resumed {label}") if ok else
               tr(f"  無法恢復 {label}；重新開機會結束它", f"  Could not resume {label}; restarting the computer ends it"))


# Programs, scripts and archives that arrive in Downloads (any subfolder) or directly on the Desktop are
# scanned once they are complete. Defender's real-time protection checks them as well; this scans each
# finished file once more and tells the user plainly when Defender finds something.
SCAN_EXTS = {".exe", ".msi", ".scr", ".com", ".pif", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse",
             ".wsf", ".hta", ".jar", ".dll", ".lnk", ".zip", ".rar", ".7z", ".iso", ".img"}
SCAN_QUEUE_MAX = 50  # more files than this waiting (e.g. a whole folder unpacked): the rest are skipped


def wait_until_written(path, settle=2.0, limit=120.0) -> bool:
    """Wait until a file stops changing (a download or copy has finished); False if it vanishes, stays busy
    or ends up empty (e.g. the placeholder Firefox creates before renaming the finished download onto it)."""
    last, end = None, time.time() + limit
    while time.time() < end:
        try:
            st = os.stat(path)
        except OSError:
            return False
        now = (st.st_size, st.st_mtime_ns)
        if now == last:
            return st.st_size > 0
        last = now
        time.sleep(settle)
    return False


class DownloadScanner:
    """Scan new programs, scripts and archives in Downloads / on the Desktop with Defender, one at a time."""

    def __init__(self, notify=None):
        self.notify = notify or self._alert
        self.roots = [(norm(_known_folder("Downloads")), True), (norm(_known_folder("Desktop")), False)]
        self.pending = deque()
        self.cond = threading.Condition()

    def wanted(self, path) -> bool:
        if Path(path).suffix.lower() not in SCAN_EXTS:
            return False
        p = norm(path)
        return any(os.path.dirname(p) == root or (deep and p.startswith(root + os.sep))
                   for root, deep in self.roots)

    def add(self, path):
        if not self.wanted(path):
            return
        with self.cond:
            if any(norm(q) == norm(path) for q in self.pending):
                return
            if len(self.pending) >= SCAN_QUEUE_MAX:
                log.warning(tr("等待掃描的檔案太多，略過：%s", "Too many files waiting to be scanned; skipping %s"), path)
                return
            self.pending.append(path)
            self.cond.notify()

    def start(self):
        threading.Thread(target=self._work, daemon=True).start()

    def _work(self):
        while True:
            with self.cond:
                while not self.pending:
                    self.cond.wait()
                path = self.pending.popleft()
            try:
                self.scan(path)
            except Exception:
                log.exception(tr("掃描新檔案時發生錯誤", "Error while scanning a new file"))

    def scan(self, path):
        if not wait_until_written(path):
            return  # gone again (perhaps already removed by Defender's real-time protection), never finished or empty
        rc = defender_scan(path, 300)
        log.info(tr("Defender 掃描新檔案 %s：%s", "Defender scan of new file %s: %s"), path, scan_result(rc))
        if rc == 2:
            self.notify(path)

    @staticmethod
    def _alert(path):
        alert(tr("RansomGuard：Defender 發現威脅", "RansomGuard: Defender found a threat"),
              tr(f"新檔案含有威脅：\n{path}\n\nMicrosoft Defender 正在處理（通常會隔離或刪除）。請不要開啟這個檔案。",
                 f"A new file contains a threat:\n{path}\n\nMicrosoft Defender is handling it (it usually "
                 "quarantines or deletes it). Do not open this file."))


# ---------------- Network control (Windows) ----------------
CREATE_NO_WINDOW = 0x08000000


def _ps(cmd: str, timeout=60):
    full = "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; " + cmd
    r = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-Command", full],
        capture_output=True, timeout=timeout, creationflags=CREATE_NO_WINDOW)
    return (r.returncode, r.stdout.decode("utf-8", "replace").strip(),
            r.stderr.decode("utf-8", "replace").strip())


def _run(args):
    try:
        subprocess.run(args, capture_output=True, timeout=30,
                       creationflags=CREATE_NO_WINDOW if IS_WINDOWS else 0)
    except Exception as ex:
        log.error(tr("執行 %s 失敗：%s", "Failed to run %s: %s"), args, ex)


def disconnect_network() -> bool:
    if not IS_WINDOWS:
        log.error(tr("目前只支援 Windows 斷網", "Cutting the network is only supported on Windows"))
        return False
    st = load_state()
    try:
        _, out, _ = _ps("Get-NetAdapter | Where-Object {$_.Status -ne 'Disabled'} "
                        "| ForEach-Object {$_.Name}")
        names = [line.strip() for line in out.splitlines() if line.strip()]
        st["disabled_adapters"] = sorted(set(st.get("disabled_adapters", []) + names))
        st["triggered_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        save_state(st)
        rc, _, err = _ps("Get-NetAdapter | Where-Object {$_.Status -ne 'Disabled'} "
                         "| Disable-NetAdapter -Confirm:$false")
        if rc != 0:
            log.error(tr("停用網路卡時出現錯誤：%s", "Error while disabling network adapters: %s"), err)
    except Exception:
        log.exception(tr("停用網路卡失敗", "Failed to disable network adapters"))

    up = adapters_up()
    if up == "0":
        log.critical(tr("已停用所有網路卡：%s", "All network adapters disabled: %s"),
                     ", ".join(st.get("disabled_adapters", [])))
        return True
    log.error(tr("仍有網路卡在線上（%s），改用防火牆封鎖與備援方式斷線",
                 "Network adapters still up (%s); falling back to firewall block and disconnect"), up)
    block_firewall()
    _run([sys_exe("ipconfig.exe"), "/release"])
    _run([sys_exe("netsh.exe"), "wlan", "disconnect"])
    return False


def adapters_up() -> str:
    """Number of connected network adapters (as a string); "?" if the query fails."""
    try:
        return _ps("@(Get-NetAdapter | Where-Object {$_.Status -eq 'Up'}).Count")[1]
    except Exception:
        return "?"


def block_firewall():
    """Fallback when disabling adapters fails: block all traffic in every firewall profile (the original
    settings are saved in state.json)."""
    st = load_state()
    try:
        if "firewall" not in st:
            _, out, _ = _ps(
                "@(Get-NetFirewallProfile | ForEach-Object { [pscustomobject]@{"
                "Name=$_.Name; Enabled=\"$($_.Enabled)\"; "
                "In=\"$($_.DefaultInboundAction)\"; Out=\"$($_.DefaultOutboundAction)\"} })"
                " | ConvertTo-Json -Compress")
            saved = json.loads(out)
            st["firewall"] = saved if isinstance(saved, list) else [saved]
            save_state(st)
        rc, _, err = _ps("Set-NetFirewallProfile -All -Enabled True "
                         "-DefaultInboundAction Block -DefaultOutboundAction Block")
        if rc == 0:
            log.critical(tr("已用防火牆封鎖所有進出連線", "Firewall now blocks all inbound and outbound connections"))
        else:
            log.error(tr("防火牆封鎖失敗：%s", "Firewall block failed: %s"), err)
    except Exception:
        log.exception(tr("防火牆封鎖失敗", "Firewall block failed"))


def keep_offline(proc):
    """While the warning is open, disable any network adapter that gets re-enabled (e.g. by malware)."""
    while proc.poll() is None:
        time.sleep(10)
        if proc.poll() is None and adapters_up() not in ("0", "?"):
            log.warning(tr("偵測到網路卡被重新啟用，再次切斷網路",
                           "A network adapter was re-enabled; cutting the network again"))
            disconnect_network()


def _ps_quote(s: str) -> str:
    return "'" + str(s).replace("'", "''") + "'"


def network_cut(st: dict) -> bool:
    return bool(st.get("triggered_at") or st.get("disabled_adapters") or st.get("firewall"))


def restore_network(report=print) -> bool:
    """Restore network adapters and firewall settings, reset canary files, then restart background monitoring."""
    if IS_WINDOWS and not is_admin():
        report(tr("需要以系統管理員身分執行才能恢復網路。",
                  "Administrator rights are needed to restore the network."))
        return False
    st = load_state()
    if st.get("triggered_at"):
        report(tr(f"RansomGuard 在 {st['triggered_at']} 切斷了網路。",
                  f"RansomGuard cut off the network at {st['triggered_at']}."))
    installed = bool(task_state())
    report(tr("停止監控（避免重設誘餌檔時又觸發）...",
              "Stopping monitoring (so resetting canary files doesn't trigger it again)..."))
    stop_monitor()

    ok = True
    names = st.get("disabled_adapters") or []
    if names:
        report(tr("重新啟用網路卡...", "Re-enabling network adapters..."))
        # enable them one by one, so a missing adapter (e.g. an unplugged USB one) doesn't stop the others
        _, out, err = _ps(
            f"$t = @(Get-NetAdapter -Name @({','.join(_ps_quote(n) for n in names)}) "
            "-ErrorAction SilentlyContinue | Where-Object {$_.Status -eq 'Disabled'}); "
            "foreach ($a in $t) { try { Enable-NetAdapter -Name $a.Name -Confirm:$false "
            "-ErrorAction Stop; \"OK`t$($a.Name)\" } "
            "catch { \"FAIL`t$($a.Name)`t$($_.Exception.Message)\" } }")
        lines = [line.split("\t") for line in out.splitlines() if line.strip()]
        for r in lines:
            if r[0] == "OK":
                log.info(tr("已重新啟用網路卡：%s", "Network adapter re-enabled: %s"), r[1])
                report(tr(f"  已啟用 {r[1]}", f"  Enabled {r[1]}"))
            else:
                ok = False
                log.error(tr("無法啟用網路卡 %s：%s", "Could not enable network adapter %s: %s"), r[1], r[-1])
                report(tr(f"  無法啟用 {r[1]}：{r[-1]}", f"  Could not enable {r[1]}: {r[-1]}"))
        if not lines:
            report(tr("  網路卡都已經是啟用狀態", "  All network adapters are already enabled")
                   + (f" ({err})" if err else ""))
    else:
        report(tr("沒有被本程式停用的網路卡。", "No network adapters were disabled by this program."))
    for p in st.get("firewall") or []:
        r = _ps(f"Set-NetFirewallProfile -Name {_ps_quote(p['Name'])} "
                f"-Enabled {_ps_quote(p['Enabled'])} -DefaultInboundAction {_ps_quote(p['In'])} "
                f"-DefaultOutboundAction {_ps_quote(p['Out'])}")
        if r[0] == 0:
            log.info(tr("已還原防火牆設定：%s", "Firewall settings restored: %s"), p["Name"])
            report(tr(f"  已還原防火牆設定 {p['Name']}", f"  Restored firewall settings for {p['Name']}"))
        else:
            ok = False
            log.error(tr("還原防火牆設定失敗（%s）：%s", "Failed to restore firewall settings (%s): %s"),
                      p["Name"], r[2])
            report(tr(f"  還原防火牆設定失敗（{p['Name']}）：{r[2]}",
                      f"  Failed to restore firewall settings ({p['Name']}): {r[2]}"))
    if network_cut(st):
        time.sleep(3)
        _run([sys_exe("ipconfig.exe"), "/renew"])
    if st.get("paused"):
        resume_paused(st["paused"], report)
    if ok:
        save_state({})
    else:
        report(tr("部分設定沒有還原成功，請按 Win+R 輸入 ncpa.cpl 手動啟用網路卡。",
                  "Some settings were not restored. Press Win+R, type ncpa.cpl and enable "
                  "the network adapters manually."))

    report(tr("重設誘餌檔...", "Resetting canary files..."))
    remove_canaries()
    if installed:
        report(tr("重新開啟監控...", "Restarting monitoring..."))
        report(tr("  監控已重新啟動", "  Monitoring restarted") if start_monitor() else
               tr("  監控沒有正常啟動，請按「安裝／更新並開始監控」，或查看紀錄檔",
                  "  Monitoring did not start. Click \"Install / update and start monitoring\" "
                  "or check the log"))
    else:
        report(tr("尚未安裝背景監控（排程工作），所以沒有重新開啟監控。",
                  "Background monitoring (scheduled task) is not installed, so it was not restarted."))
    up = adapters_up()
    report(tr(f"完成。目前連線中的網路卡：{up} 張", f"Done. Network adapters connected now: {up}") + (
        tr("（Wi-Fi 可能需要幾秒鐘重新連線）", " (Wi-Fi may take a few seconds to reconnect)")
        if up == "0" else ""))
    return ok


def remove_canaries(names=CANARY_NAMES + LEGACY_CANARY_NAMES):
    """Delete the canary files; the monitor creates fresh ones when it restarts (so they aren't
    mistaken for "changed while the program was not running")."""
    for d in default_canary_dirs():
        for name in names:
            try:
                (d / name).unlink(missing_ok=True)
            except OSError as ex:
                log.warning(tr("無法刪除誘餌檔 %s：%s", "Could not delete canary file %s: %s"), d / name, ex)


# ---------------- Background monitor (scheduled task) and install ----------------
# Background monitor processes: the .exe or ransom_guard.py with --monitor, older ransom_guard.py runs
# without options, and the process-monitor PowerShell they start (recognized by its encoded script)
_KILL_PS1 = r'''
$me = @(__ME__, $PID)
Get-CimInstance Win32_Process | Where-Object {
    $c = "$($_.CommandLine)"
    ($me -notcontains $_.ProcessId) -and (
        ($_.Name -match '^(RansomGuard|pythonw?)\.exe$' -and $c -match 'ransom_?guard' -and
         ($c -match '\s--monitor\b' -or $c -match 'ransom_guard\.py"?\s*$')) -or
        $c.Contains('__PROC__'))
} | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
'''


def task_state() -> str:
    """Scheduled task state (Running / Ready / Disabled...); empty string if not installed."""
    try:
        return _ps(f"(Get-ScheduledTask -TaskName {_ps_quote(TASK_NAME)} "
                   "-ErrorAction SilentlyContinue).State")[1]
    except Exception:
        return ""


def stop_monitor():
    _ps(f"Stop-ScheduledTask -TaskName {_ps_quote(TASK_NAME)} -ErrorAction SilentlyContinue")
    # the encoded opening line of PROC_PS1, the same in every version, so older monitors' scripts match too
    proc_enc = ps_encoded_args(PROC_PS1)[-1][:120]
    _ps(_KILL_PS1.replace("__ME__", f"{os.getpid()},{os.getppid()}")
        .replace("__PROC__", proc_enc))
    log.info(tr("已停止背景監控", "Background monitoring stopped"))


def start_monitor() -> bool:
    _ps(f"Start-ScheduledTask -TaskName {_ps_quote(TASK_NAME)} -ErrorAction Stop")
    time.sleep(5)  # a failed start (e.g. a missing package) exits within a few seconds
    return task_state() == "Running"


def launcher():
    """(executable, arguments) used to run this program."""
    if FROZEN:
        return str(INSTALL_EXE), ""
    pyw = Path(sys.executable).with_name("pythonw.exe")
    # -E ignores PYTHON* environment variables; -P doesn't load modules from the script folder (no fake json.py)
    flags = "-E -P" if sys.version_info >= (3, 11) else "-E"
    return str(pyw if pyw.exists() else sys.executable), f'{flags} "{os.path.abspath(__file__)}"'


def desktop_lnk() -> Path:
    return _known_folder("Desktop") / "RansomGuard.lnk"


def restore_hint() -> str:
    button = tr("「恢復網路並重新開啟監控」", "\"Restore network and restart monitoring\"")
    if desktop_lnk().exists():
        return tr(f"開啟桌面上的「RansomGuard」，按{button}",
                  f"open \"RansomGuard\" on the desktop and click {button}")
    if FROZEN:
        return tr(f"執行 {sys.executable}，按{button}", f"run {sys.executable} and click {button}")
    bat = Path(os.path.abspath(__file__)).parent / "restore_network.bat"
    return tr(f"雙擊 {bat} 恢復網路", f"double-click {bat} to restore the network")


def cleanup_old_files():
    """Remove what older versions left behind: exes replaced by an update (RansomGuard.old-*.exe)
    and the alert files very early versions wrote to the app folder."""
    for p in [*INSTALL_DIR.glob("RansomGuard.old-*.exe"), app_dir() / "alert.json", app_dir() / "alert.ps1"]:
        try:
            p.unlink(missing_ok=True)
        except OSError:  # still running (e.g. an open control panel); tried again next time
            pass


def version_tuple(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3])


def replace_install_exe(write):
    """Put a new INSTALL_EXE in place with write(). A running exe can't be overwritten but can be
    renamed, so the old one is moved aside first (and put back if writing fails)."""
    INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    old = None
    if INSTALL_EXE.exists():
        old = INSTALL_DIR / f"RansomGuard.old-{uuid.uuid4().hex[:8]}.exe"
        for i in range(10):
            try:
                os.replace(INSTALL_EXE, old)
                break
            except PermissionError:  # briefly locked, e.g. antivirus scanning the exe
                if i == 9:
                    raise
                time.sleep(1)
    try:
        write()
    except Exception:
        if old is not None:
            os.replace(old, INSTALL_EXE)
        raise
    if old is not None:
        try:
            old.unlink()
        except OSError:  # still running (e.g. this control panel): Windows deletes it at the next restart
            delete_at_restart(old)


def latest_release():
    """(version, RansomGuard.exe asset or None) of the newest release on GitHub."""
    req = urllib.request.Request(UPDATE_API, headers={"User-Agent": "RansomGuard",
                                                      "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        rel = json.load(r)
    return rel["tag_name"].lstrip("v"), next((a for a in rel["assets"] if a["name"] == "RansomGuard.exe"), None)


def check_for_update():
    """The newer version on GitHub, or None (up to date, not the packaged exe, or GitHub unreachable)."""
    if not FROZEN:
        return None
    try:
        latest, asset = latest_release()
    except Exception as ex:
        log.info(tr("無法檢查更新：%s", "Could not check for updates: %s"), ex)
        return None
    return latest if asset is not None and version_tuple(latest) > version_tuple(VERSION) else None


def fetch_update(report):
    """If GitHub has a newer release, download it, check its SHA-256 against the one GitHub publishes
    and install it as INSTALL_EXE. Returns the new version, or None (already latest / check failed)."""
    report(tr("檢查新版本...", "Checking for a new version..."))
    try:
        latest, asset = latest_release()
        if version_tuple(latest) <= version_tuple(VERSION):
            report(tr(f"  已經是最新版本（v{VERSION}）", f"  Already the latest version (v{VERSION})"))
            return None
        if asset is None:
            raise RuntimeError(tr("新版本沒有附上 RansomGuard.exe", "the new release has no RansomGuard.exe"))
        algo, _, want = (asset.get("digest") or "").partition(":")
        url = asset["browser_download_url"]
        if algo != "sha256" or not want or not url.startswith("https://github.com/"):
            raise RuntimeError(tr("GitHub 沒有提供可核對的 SHA-256", "GitHub gave no SHA-256 to check the file against"))
        report(tr(f"下載 v{latest}（{asset['size'] / 1048576:.1f} MB）...",
                  f"Downloading v{latest} ({asset['size'] / 1048576:.1f} MB)..."))
        # kept in memory until verified, so nothing can swap a temp file between the check and the install
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "RansomGuard"}),
                                    timeout=120) as r:
            data = r.read()
        if hashlib.sha256(data).hexdigest() != want.lower():
            raise RuntimeError(tr("下載的檔案和 GitHub 公布的 SHA-256 不符", "the download doesn't match GitHub's SHA-256"))
    except Exception as ex:
        log.warning(tr("無法更新：%s", "Could not update: %s"), ex)
        report(tr(f"  無法更新：{ex}（改為安裝目前這個版本）", f"  Could not update: {ex} (installing this version instead)"))
        return None
    replace_install_exe(lambda: INSTALL_EXE.write_bytes(data))
    log.info(tr("已從 GitHub 更新到 v%s", "Updated from GitHub to v%s"), latest)
    report(tr(f"  已更新到 v{latest}", f"  Updated to v{latest}"))
    return latest


def spawn_installed(*args):
    """Start the installed exe as a fresh program. A one-file PyInstaller exe started by another one
    inherits its environment and would reuse the starter's unpacked files (%TEMP%\\_MEI...), which are
    deleted when the starter exits; it then fails as soon as it loads another module."""
    return subprocess.Popen([str(INSTALL_EXE), *args], cwd=str(INSTALL_DIR), env=fresh_env())


def install(report=print) -> bool:
    """Update from GitHub if there is a newer release (otherwise copy this exe) into Program Files,
    create a scheduled task that runs elevated at sign-in and a desktop shortcut, then start monitoring.
    If anything fails, the monitoring that was installed before is started again."""
    report(tr("停止舊的監控...", "Stopping the old monitor..."))
    stop_monitor()
    try:
        return _install(report)
    except Exception:
        if task_state():  # don't leave the computer unprotected
            report(tr("安裝沒有完成，重新啟動原本的監控...", "Install did not finish; restarting the previous monitoring..."))
            report(tr("  監控已重新啟動", "  Monitoring restarted") if start_monitor() else
                   tr("  監控沒有啟動，請查看紀錄檔", "  Monitoring did not start; please check the log"))
        raise


# Health check, run by its own scheduled task through wscript.exe (so no window opens, not even briefly).
# It doesn't need RansomGuard.exe: when Defender removes that by mistake it also deletes the monitor's task,
# and protection would otherwise stop without a word. Saved as UTF-16 (Windows Script Host reads UTF-8 as ANSI).
HEALTH_TASK = "RansomGuard Health Check"
HEALTH_JS = r'''// RansomGuard health check: tells the user when background protection is gone or not running.
var TASK = "__TASK__";
var RELEASES = "https://github.com/leo-code-del/RansomGuard/releases/latest";
var sh = new ActiveXObject("WScript.Shell");
var fso = new ActiveXObject("Scripting.FileSystemObject");
var env = sh.Environment("PROCESS");
var test = env("RG_HEALTH_TEST") != "";  // tests: print the result instead of asking
if (test && env("RG_HEALTH_TASK") != "") TASK = env("RG_HEALTH_TASK");
var appDir = (test && env("RG_HEALTH_APPDIR") != "") ? env("RG_HEALTH_APPDIR") : env("LOCALAPPDATA") + "\\RansomGuard";

function readText(path) {
    try {
        var s = new ActiveXObject("ADODB.Stream");
        s.Type = 2; s.Charset = "utf-8"; s.Open(); s.LoadFromFile(path);
        var text = s.ReadText(); s.Close();
        return text;
    } catch (e) { return ""; }
}

// "removed", "stopped" or "" (fine, or unknown: then say nothing rather than raise a false alarm)
function check() {
    var task;
    try {
        var svc = new ActiveXObject("Schedule.Service");
        svc.Connect();
        task = svc.GetFolder("\\").GetTask(TASK);
    } catch (e) {
        return (e.number >>> 0) == 0x80070002 ? "removed" : "";  // 0x80070002: no such task
    }
    try {
        var exe = sh.ExpandEnvironmentStrings(task.Definition.Actions.Item(1).Path).replace(/"/g, "");
        if (!fso.FileExists(exe)) return "removed";
        if (task.State == 4) return "";  // running
    } catch (e) { return ""; }
    // after a trigger the monitor stops on purpose, until the network is restored
    if (/"triggered_at"\s*:\s*"[^"]/.test(readText(appDir + "\\state.json"))) return "";
    return "stopped";
}

var problem = check();
if (test) {
    WScript.Echo(problem || "ok");
    WScript.Quit(0);
}
if (problem) {
    var lang = (readText(appDir + "\\settings.json").match(/"lang"\s*:\s*"(zh|en)"/) || [])[1];
    if (!lang) {
        try { lang = /^zh/i.test(sh.RegRead("HKCU\\Control Panel\\International\\LocaleName")) ? "zh" : "en"; }
        catch (e) { lang = "en"; }
    }
    var zh = lang == "zh";
    var msg = problem == "removed" ?
        (zh ? "RansomGuard 的背景防護已經從這台電腦上消失了，最常見的原因是被 Microsoft Defender 誤判刪除。\n\n" +
              "要開啟下載頁面重新安裝嗎？\n（下載 RansomGuard.exe 後執行，按「安裝／更新並開始監控」）"
            : "RansomGuard's background protection is gone from this computer. Most often Microsoft Defender " +
              "removed it by mistake.\n\nOpen the download page to install it again?\n(Download RansomGuard.exe, " +
              "run it and click \"Install / update and start monitoring\".)") :
        (zh ? "RansomGuard 的背景監控沒有在執行，這台電腦目前沒有勒索病毒防護。\n\n" +
              "要開啟控制台嗎？（按「安裝／更新並開始監控」就會重新開始）"
            : "RansomGuard's background monitoring is not running, so this computer has no ransomware " +
              "protection right now.\n\nOpen the control panel? (Click \"Install / update and start " +
              "monitoring\" to start it again.)");
    // 4 = Yes/No, 48 = warning icon, 4096 = stays on top; 6 = Yes
    if (sh.Popup(msg, 0, "RansomGuard", 4 + 48 + 4096) == 6) {
        var lnk = sh.SpecialFolders("Desktop") + "\\RansomGuard.lnk";
        sh.Run(problem == "stopped" && fso.FileExists(lnk) ? "\"" + lnk + "\"" : RELEASES);
    }
}
'''.replace("__TASK__", TASK_NAME)


def install_health_check(report):
    """Save health_check.js next to the exe (only administrators can change it there) and run it at sign-in
    (after the monitor had time to start) and every day."""
    js = INSTALL_DIR / "health_check.js"
    INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    js.write_text(HEALTH_JS, encoding="utf-16")
    rc, _, err = _ps(
        r'$u = "$env:USERDOMAIN\$env:USERNAME"; '
        f"$a = New-ScheduledTaskAction -Execute {_ps_quote(sys_exe('wscript.exe'))} "
        f"-Argument {_ps_quote(f'//B //Nologo \"{js}\"')}; "
        "$t1 = New-ScheduledTaskTrigger -AtLogOn -User $u; $t1.Delay = 'PT5M'; "
        "$t2 = New-ScheduledTaskTrigger -Daily -At '12:00'; "
        "$p = New-ScheduledTaskPrincipal -UserId $u -LogonType Interactive -RunLevel Limited; "
        "$s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable "
        "-ExecutionTimeLimit (New-TimeSpan -Hours 1) -MultipleInstances IgnoreNew; "
        f"Register-ScheduledTask -TaskName {_ps_quote(HEALTH_TASK)} -Action $a -Trigger $t1, $t2 -Principal $p "
        f"-Settings $s -Description {_ps_quote(tr('背景防護不見或沒有執行時提醒', 'Warns when background protection is gone or not running'))} "  # noqa: E501
        "-Force -ErrorAction Stop | Out-Null")
    if rc == 0:
        report(tr("已建立防護狀態檢查（登入後與每天提醒防護是否還在）",
                  "Health check created (warns at sign-in and daily if protection is gone)"))
    else:  # not worth failing the install over
        log.warning(tr("建立防護狀態檢查失敗：%s", "Could not create the health check: %s"), err)
        report(tr(f"  無法建立防護狀態檢查：{err}", f"  Could not create the health check: {err}"))


def _install(report) -> bool:
    global UPDATED_TO
    UPDATED_TO = fetch_update(report) if FROZEN else None
    if FROZEN and UPDATED_TO is None and norm(sys.executable) != norm(INSTALL_EXE):
        # a program that runs as administrator must live in a folder only administrators can change
        report(tr(f"複製程式到 {INSTALL_DIR} ...", f"Copying the program to {INSTALL_DIR} ..."))
        replace_install_exe(lambda: shutil.copy2(sys.executable, str(INSTALL_EXE)))
    cleanup_old_files()
    exe, args = launcher()
    workdir = str(INSTALL_DIR if FROZEN else Path(os.path.abspath(__file__)).parent)
    report(tr("建立登入時自動執行的排程工作...", "Creating a scheduled task that runs at sign-in..."))
    rc, _, err = _ps(
        r'$u = "$env:USERDOMAIN\$env:USERNAME"; '
        f"$a = New-ScheduledTaskAction -Execute {_ps_quote(exe)} "
        f"-Argument {_ps_quote((args + ' --monitor').strip())} -WorkingDirectory {_ps_quote(workdir)}; "
        "$t = New-ScheduledTaskTrigger -AtLogOn -User $u; "
        "$p = New-ScheduledTaskPrincipal -UserId $u -LogonType Interactive -RunLevel Highest; "
        "$s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries "
        "-ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew "
        "-RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1); "
        f"Register-ScheduledTask -TaskName {_ps_quote(TASK_NAME)} -Action $a -Trigger $t "
        f"-Principal $p -Settings $s "
        f"-Description {_ps_quote(tr('偵測勒索病毒行為並自動切斷網路', 'Detects ransomware behavior and cuts off the network automatically'))} "  # noqa: E501
        "-Force -ErrorAction Stop | Out-Null")
    if rc != 0:
        raise RuntimeError(tr(f"建立排程工作失敗：{err}", f"Failed to create the scheduled task: {err}"))
    install_health_check(report)
    report(tr("建立桌面捷徑「RansomGuard」...", "Creating the \"RansomGuard\" desktop shortcut..."))
    # the shortcut names an icon file of its own, so it never shows a stale icon cached for the exe path
    icon = icon_file()
    if FROZEN and icon.endswith(".ico"):
        shutil.copy2(icon, str(INSTALL_DIR / "icon.ico"))
        icon = str(INSTALL_DIR / "icon.ico")
    _ps(f"$s = (New-Object -ComObject WScript.Shell).CreateShortcut({_ps_quote(str(desktop_lnk()))}); "
        f"$s.TargetPath = {_ps_quote(exe)}; $s.Arguments = {_ps_quote((args + ' --gui').strip() if args else '')}; "
        f"$s.WorkingDirectory = {_ps_quote(workdir)}; $s.IconLocation = {_ps_quote(icon + ',0')}; "
        f"$s.Description = {_ps_quote(tr('RansomGuard 控制台', 'RansomGuard control panel'))}; $s.Save()")
    # Windows caches icons per file path, and the installed path never changes: tell the shell the exe
    # changed and refresh the cache, so the shortcut doesn't keep showing an older version's icon
    if IS_WINDOWS:
        ctypes.windll.shell32.SHChangeNotify(0x2000, 0x0005, str(INSTALL_EXE), None)  # UPDATEITEM, PATHW
        ctypes.windll.shell32.SHChangeNotify(0x08000000, 0x1000, None, None)  # ASSOCCHANGED, FLUSH
        _run([sys_exe("ie4uinit.exe"), "-show"])
    report(tr("開始監控...", "Starting monitoring..."))
    ok = start_monitor()
    log.info(tr("已安裝背景監控：%s %s", "Background monitoring installed: %s %s"), exe, args)
    report(tr("完成！監控已在背景執行，之後每次登入 Windows 都會自動啟動。",
              "Done! Monitoring is running in the background and starts every time you sign in to Windows.")
           if ok else
           tr(f"排程工作已建立，但監控目前狀態是 {task_state() or '未知'}，請查看紀錄檔。",
              f"The scheduled task was created, but monitoring is {task_state() or 'unknown'}. "
              "Please check the log."))
    return ok


def uninstall(report=print) -> bool:
    report(tr("停止監控...", "Stopping monitoring..."))
    stop_monitor()
    _, _, err = _ps(f"Unregister-ScheduledTask -TaskName {_ps_quote(TASK_NAME)} "
                    "-Confirm:$false -ErrorAction SilentlyContinue")
    if task_state():
        report(tr(f"刪除排程工作失敗：{err}", f"Failed to delete the scheduled task: {err}"))
        return False
    _ps(f"Unregister-ScheduledTask -TaskName {_ps_quote(HEALTH_TASK)} -Confirm:$false -ErrorAction SilentlyContinue")
    report(tr("已刪除排程工作", "Scheduled task deleted"))
    desktop_lnk().unlink(missing_ok=True)
    remove_canaries()
    report(tr("已刪除桌面捷徑與誘餌檔", "Desktop shortcut and canary files deleted"))
    if INSTALL_DIR.is_dir():
        # the exe, its icon and exes left by updates; files still running are deleted at the next restart
        later = []
        for p in INSTALL_DIR.iterdir():
            try:
                p.unlink()
            except OSError:
                later.append(p)
        try:
            if later:
                raise OSError
            INSTALL_DIR.rmdir()
            report(tr(f"已刪除 {INSTALL_DIR}", f"Deleted {INSTALL_DIR}"))
        except OSError:
            for p in [*later, INSTALL_DIR]:
                delete_at_restart(p)
            report(tr(f"{INSTALL_DIR} 會在下次開機時刪除", f"{INSTALL_DIR} will be deleted at the next restart"))
    log.info(tr("已解除安裝背景監控", "Background monitoring uninstalled"))
    report(tr("解除安裝完成。", "Uninstall complete."))
    return True


UPDATE_CHECK_DELAY = 120           # first update check this many seconds after the monitor starts
UPDATE_CHECK_INTERVAL = 6 * 3600   # then check again this often


def ask_update(new: str) -> bool:
    """Ask whether to update now (a topmost Yes/No box)."""
    text = tr(f"RansomGuard v{new} 已推出（目前是 v{VERSION}）。\n\n要現在更新嗎？控制台會開啟並自動完成更新。",
              f"RansomGuard v{new} is available (you have v{VERSION}).\n\n"
              "Update now? The control panel will open and update automatically.")
    # MB_YESNO | MB_ICONINFORMATION | MB_SETFOREGROUND | MB_TOPMOST; IDYES = 6
    return ctypes.windll.user32.MessageBoxW(None, text, "RansomGuard", 0x4 | 0x40 | 0x10000 | 0x40000) == 6


def update_watcher(stop):
    """Background monitor: whenever GitHub has a newer release, ask the user to update
    (each version once per sign-in) and, on Yes, open the control panel to do it."""
    asked = set()
    if stop.wait(UPDATE_CHECK_DELAY):
        return
    while True:
        new = check_for_update()
        if new and new not in asked:
            asked.add(new)
            init_lang()
            log.info(tr("有新版本 v%s，詢問是否更新", "Version %s is available; asking whether to update"), new)
            if ask_update(new):
                try:
                    spawn_installed("--update")
                except OSError as ex:
                    log.error(tr("無法開啟控制台更新：%s", "Could not open the control panel to update: %s"), ex)
        if stop.wait(UPDATE_CHECK_INTERVAL):
            return


# ---------------- Control panel window ----------------
def status_info():
    """The control panel's two status cards: ((text, light, note), (text, light, note));
    light is ok / warn / bad / off."""
    s = task_state()
    unprotected = tr("目前沒有勒索病毒防護", "No ransomware protection right now")
    mon = {"Running": (tr("執行中", "Running"), "ok",
                       tr("每次登入 Windows 都會自動啟動", "Starts every time you sign in to Windows")),
           "Ready": (tr("已停止", "Stopped"), "warn", unprotected),
           "Disabled": (tr("已停用", "Disabled"), "warn", unprotected),
           "": (tr("尚未安裝", "Not installed"), "off",
                tr("按「安裝／更新並開始監控」", "Click \"Install / update and start monitoring\""))
           }.get(s, (s, "warn", ""))
    st = load_state()
    cut = tr("已切斷", "Cut off")
    if st.get("triggered_at"):
        net = (cut, "bad", tr(f"{st['triggered_at']} 偵測到可疑行為",
                              f"Suspicious activity detected at {st['triggered_at']}"))
    elif network_cut(st):
        net = (cut, "bad", tr("確認安全後再恢復網路", "Restore it once you're sure it's safe"))
    else:
        net = (tr("正常", "Normal"), "ok", tr("連線沒有被限制", "The connection is not restricted"))
    return mon, net


def icon_file() -> str:
    """icon.ico: packed into the exe (PyInstaller --add-data) or next to the script.
    Read from the file itself, never through Windows' icon cache, which can keep an old version's icon
    for the installed exe's path (that is what the taskbar showed until 1.5.3)."""
    base = getattr(sys, "_MEIPASS", None) or os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(base, "icon.ico")
    return path if os.path.exists(path) else sys.executable


def set_window_icons(root, source: str):
    """Set the window's own big (taskbar, Alt+Tab) and small (title bar) icons and its class icons from
    source. Called again after the window is shown, because Tk re-applies its icon when mapping it."""
    if not IS_WINDOWS:
        return
    try:
        u = ctypes.windll.user32
        u.PrivateExtractIconsW.argtypes = [ctypes.c_wchar_p, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                           ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p, ctypes.c_uint,
                                           ctypes.c_uint]
        u.SendMessageW.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p]
        u.SetClassLongPtrW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
        root.update_idletasks()
        hwnd = int(root.wm_frame(), 16)
        # ICON_BIG / SM_CXICON / GCLP_HICON, ICON_SMALL / SM_CXSMICON / GCLP_HICONSM
        for which, metric, cls in ((1, 11, -14), (0, 49, -34)):
            size = u.GetSystemMetrics(metric)  # already scaled for the display (the process is DPI aware)
            h = ctypes.c_void_p()
            if u.PrivateExtractIconsW(source, 0, size, size, ctypes.byref(h), None, 1, 0) == 1 and h:
                u.SendMessageW(hwnd, 0x80, which, h)  # WM_SETICON
                u.SetClassLongPtrW(hwnd, cls, h)
    except Exception:
        log.exception(tr("無法設定視窗圖示", "Could not set the window icon"))


def gui(auto_update=False):
    import queue
    import tkinter as tk
    from tkinter import messagebox, scrolledtext

    if IS_WINDOWS and not is_admin():  # reopen as administrator
        script = [] if FROZEN else [os.path.abspath(__file__)]
        params = subprocess.list2cmdline([*script, *sys.argv[1:]])
        if ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1) > 32:
            return
        messagebox.showerror("RansomGuard", tr("需要系統管理員權限才能使用控制台。",
                                               "Administrator rights are needed to use the control panel."))
        return
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)  # keeps text sharp on high-DPI screens
        # its own taskbar identity, so the taskbar uses this window's icon rather than the icon Windows
        # cached for the exe path or its shortcut (which can be an older version's)
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("leo-code-del.RansomGuard")
    except Exception:
        pass

    root = tk.Tk()
    root.resizable(False, False)
    icon = icon_file()
    try:
        root.iconbitmap(default=icon)  # default= applies it to dialogs too
    except tk.TclError:
        pass
    set_window_icons(root, icon)
    scale = root.winfo_fpixels("1i") / 96  # scale spacing with the display scaling

    def px(n):
        return int(n * scale)

    C = {"bg": "#f3f5f9", "card": "#ffffff", "border": "#dfe3eb", "header": "#1e293b",
         "text": "#1f2937", "muted": "#6b7280",
         "ok": "#16a34a", "warn": "#d97706", "bad": "#dc2626", "off": "#9ca3af"}
    # button styles: (background, hover background, text, disabled text)
    STYLES = {"primary": ("#2563eb", "#1d4ed8", "#ffffff", "#bfd0f7"),
              "success": ("#16a34a", "#15803d", "#ffffff", "#bde5cb"),
              "secondary": ("#ffffff", "#eef1f6", C["text"], "#c3c9d4"),
              "danger": (C["bg"], "#fde8e8", C["bad"], "#e8b4b4"),
              "header": (C["header"], "#334155", "#cbd5e1", "#64748b")}
    root.configure(bg=C["bg"])

    q = queue.Queue()
    buttons = []
    w = {}  # widgets on screen now; the whole window is rebuilt when the language changes

    def make_button(parent, text, cmd, name):
        rim = tk.Frame(parent)  # 1px border (a tk button's own border can only be black on Windows)
        b = tk.Button(rim, text=text, command=cmd, font=(w["font"], 11), relief="flat", bd=0,
                      highlightthickness=0, cursor="hand2", padx=px(12), pady=px(7))
        b.pack(fill="both", padx=1, pady=1)
        buttons.append(b)
        style(b, name)
        return rim, b

    def style(b, name):
        bg, hover, fg, dim = STYLES[name]
        rim = b.master
        edge = C["border"] if name == "secondary" else bg
        rim.config(bg=edge)
        b.config(bg=bg, fg=fg, activebackground=hover, activeforeground=fg, disabledforeground=dim)

        def enter(_):
            if str(b["state"]) == "normal":
                b.config(bg=hover)
                rim.config(bg=C["border"] if name == "secondary" else hover)

        def leave(_):
            b.config(bg=bg)
            rim.config(bg=edge)
        b.bind("<Enter>", enter)
        b.bind("<Leave>", leave)

    def show_status(info):
        for (dot, val, detail), (text, level, note) in zip((w["mon"], w["net"]), info):
            dot.config(fg=C[level])
            val.config(text=text, fg=C["bad"] if level == "bad" else C["text"])
            detail.config(text=note or " ")
        cut = info[1][1] == "bad"  # highlight "Restore network" while the network is cut
        style(w["install"], "secondary" if cut else "primary")
        style(w["restore"], "success" if cut else "secondary")

    def write(msg, tag=None):
        out = w["out"]
        out.config(state="normal")
        out.insert("end", msg + "\n", tag)
        out.see("end")
        out.config(state="disabled")

    def report(msg):
        q.put(("msg", msg))

    def refresh():
        threading.Thread(target=lambda: q.put(("status", status_info())), daemon=True).start()

    def run_bg(fn):
        for b in buttons:
            b.config(state="disabled")
        w["busy"].config(text=tr("執行中...", "Working..."))
        w["working"] = True
        w["out"].config(state="normal")
        w["out"].delete("1.0", "end")
        w["out"].config(state="disabled")

        def work():
            try:
                fn(report)
            except Exception as ex:
                log.exception(tr("控制台操作失敗", "Control panel action failed"))
                report(tr(f"[失敗] {ex}", f"[Failed] {ex}"))
            q.put(("done", None))
        threading.Thread(target=work, daemon=True).start()

    def pump():
        try:
            while True:
                kind, msg = q.get_nowait()
                if kind == "msg":
                    write(msg, "err" if msg.startswith(("[失敗]", "[Failed]")) else None)
                elif kind == "status":
                    show_status(msg)
                elif kind == "update":  # a newer version was found when the window opened
                    if msg and not w.get("working") and messagebox.askyesno(
                            "RansomGuard", tr(f"有新版本 v{msg}（目前是 v{VERSION}）。\n\n要現在更新嗎？",
                                              f"Version {msg} is available (you have v{VERSION}).\n\nUpdate now?")):
                        run_bg(install)
                else:
                    for b in buttons:
                        b.config(state="normal")
                    w["busy"].config(text="")
                    w["working"] = False
                    if UPDATED_TO:  # reopen the control panel from the newly installed version
                        messagebox.showinfo("RansomGuard", tr(f"已更新到 v{UPDATED_TO}，控制台會用新版本重新開啟。",
                                                              f"Updated to v{UPDATED_TO}. The control panel "
                                                              "will reopen with the new version."))
                        try:
                            spawn_installed("--gui")
                        except OSError as ex:
                            write(tr(f"[失敗] 無法開啟新版本：{ex}", f"[Failed] Could not open the new version: {ex}"),
                                  "err")
                        else:
                            root.destroy()
                            return
                    refresh()
        except queue.Empty:
            pass
        w["pump"] = root.after(100, pump)

    def on_restore():
        if network_cut(load_state()) and not messagebox.askyesno(
                tr("恢復網路", "Restore network"),
                tr("請先確認這次是測試或誤判，而不是真的中了勒索病毒。\n\n確定要恢復網路嗎？",
                   "First make sure this was a test or a false alarm, not a real ransomware "
                   "infection.\n\nRestore the network?"),
                icon="warning"):
            return
        run_bg(restore_network)

    def on_stop():
        if messagebox.askyesno(tr("停止監控", "Stop monitoring"),
                               tr("停止後電腦就沒有勒索病毒防護，直到重新開啟監控或下次登入。\n確定要停止嗎？",
                                  "This computer will have no ransomware protection until monitoring "
                                  "is restarted or you sign in again.\nStop monitoring?")):
            run_bg(lambda rep: (stop_monitor(), rep(tr("監控已停止。", "Monitoring stopped."))))

    def on_uninstall():
        title = tr("解除安裝", "Uninstall")
        if network_cut(load_state()):
            messagebox.showinfo(title, tr("網路目前被切斷，請先按「恢復網路並重新開啟監控」。",
                                          "The network is cut off. Click \"Restore network and "
                                          "restart monitoring\" first."))
            return
        if messagebox.askyesno(title, tr("確定要移除背景監控、桌面捷徑與誘餌檔嗎？",
                                         "Remove background monitoring, the desktop shortcut and "
                                         "the canary files?")):
            run_bg(uninstall)

    def on_preview():
        run_bg(lambda rep: (rep(tr("警告畫面開啟中，按「我知道了」即可關閉。",
                                   "Opening the warning. Click \"I understand\" to close it.")),
                            fullscreen_alert(tr("這是警告畫面的預覽，沒有偵測到任何東西",
                                                "This is a preview of the warning; nothing was detected"),
                                             "test")))

    def on_log():
        p = app_dir() / "guard.log"
        if p.exists():
            os.startfile(p)
        else:
            messagebox.showinfo(tr("紀錄檔", "Log"), tr("還沒有紀錄檔。", "There is no log file yet."))

    def on_lang():
        set_lang("en" if LANG == "zh" else "zh")
        build()
        refresh()

    def on_close():
        # closing mid-install would kill the worker thread and could leave monitoring stopped
        if w.get("working"):
            messagebox.showwarning("RansomGuard", tr("操作還在進行中，請等它完成再關閉。",
                                                     "An action is still running. Please wait for it to finish."))
            return
        root.after_cancel(w["pump"])
        root.destroy()

    def center():
        root.update_idletasks()  # center the window, slightly above the middle
        root.geometry(f"+{(root.winfo_screenwidth() - root.winfo_width()) // 2}"
                      f"+{(root.winfo_screenheight() - root.winfo_height()) // 3}")

    def choose_lang():
        """First run: let the user pick the language (English first, then 中文(繁體))."""
        w["font"] = "Segoe UI"
        root.title("RansomGuard")
        w["frame"] = frame = tk.Frame(root, bg=C["bg"])
        frame.pack(fill="both")
        hdr = tk.Frame(frame, bg=C["header"])
        hdr.pack(fill="x")
        top = tk.Frame(hdr, bg=C["header"])
        top.pack(fill="x", padx=px(22), pady=px(16))
        tk.Label(top, text="RansomGuard", font=("Segoe UI", 17, "bold"), fg="#ffffff",
                 bg=C["header"]).pack(side="left")
        tk.Label(top, text=f"v{VERSION}", font=("Segoe UI", 10), fg="#94a3b8",
                 bg=C["header"]).pack(side="left", anchor="s", padx=(px(8), 0), pady=(0, px(4)))
        body = tk.Frame(frame, bg=C["bg"])
        body.pack(fill="both", padx=px(28), pady=(px(22), px(26)))
        tk.Label(body, text="Choose your language", font=("Segoe UI", 13, "bold"), fg=C["text"],
                 bg=C["bg"]).pack(anchor="w")
        tk.Label(body, text="請選擇介面語言", font=("Microsoft JhengHei UI", 11), fg=C["muted"],
                 bg=C["bg"]).pack(anchor="w", pady=(px(2), px(16)))

        def pick(lang):
            set_lang(lang)
            show_panel()

        default = system_lang()
        for lang, text, font in (("en", "English", "Segoe UI"), ("zh", "中文(繁體)", "Microsoft JhengHei UI")):
            rim, b = make_button(body, text, lambda lang=lang: pick(lang),
                                 "primary" if lang == default else "secondary")
            b.config(font=(font, 13), pady=px(10), width=24)
            rim.pack(fill="x", pady=(0, px(10)))
        tk.Label(body, text="You can change this later in the control panel.\n之後可以在控制台右上角切換。",
                 font=("Microsoft JhengHei UI", 9), fg=C["muted"], bg=C["bg"],
                 justify="left").pack(anchor="w", pady=(px(4), 0))

    def show_panel():
        """Show the control panel at one fixed size that fits both languages (English text is wider),
        so switching the language doesn't resize the window or move anything in it."""
        global LANG
        chosen, sizes = LANG, []
        root.withdraw()
        for LANG in ("en", "zh"):
            build()
            root.update_idletasks()
            sizes.append((root.winfo_reqwidth(), root.winfo_reqheight()))
        LANG = chosen
        build()
        root.geometry(f"{max(s[0] for s in sizes)}x{max(s[1] for s in sizes)}")
        refresh()
        center()
        root.deiconify()
        set_window_icons(root, icon)
        if auto_update:  # opened from the "new version available" prompt
            root.after(300, lambda: run_bg(install))
        else:
            threading.Thread(target=lambda: q.put(("update", check_for_update())), daemon=True).start()

    def build():
        if "frame" in w:
            w["frame"].destroy()
        buttons.clear()
        # one font for both languages (JhengHei has its own Latin letters): with the same line heights
        # every row stays exactly where it is when the language is switched
        w["font"] = FONT = "Microsoft JhengHei UI"
        root.title(tr("RansomGuard 控制台", "RansomGuard Control Panel"))
        w["frame"] = frame = tk.Frame(root, bg=C["bg"])
        frame.pack(fill="both", expand=True)

        # header
        hdr = tk.Frame(frame, bg=C["header"])
        hdr.pack(fill="x")
        top = tk.Frame(hdr, bg=C["header"])
        top.pack(fill="x", padx=px(22), pady=(px(16), 0))
        tk.Label(top, text="RansomGuard", font=(FONT, 17, "bold"), fg="#ffffff",
                 bg=C["header"]).pack(side="left")
        tk.Label(top, text=f"v{VERSION}", font=(FONT, 10), fg="#94a3b8",
                 bg=C["header"]).pack(side="left", anchor="s", padx=(px(8), 0), pady=(0, px(4)))
        # language switch: the button shows the *other* language
        rim, b = make_button(top, tr("English", "中文(繁體)"), on_lang, "header")
        b.config(font=(FONT, 10), padx=px(10), pady=px(2), width=10)  # same width in both languages
        rim.pack(side="right")
        tk.Label(hdr, text=tr("偵測勒索病毒行為，發現異常時自動切斷網路",
                              "Detects ransomware behavior and cuts off the network automatically"),
                 font=(FONT, 10), fg="#cbd5e1", bg=C["header"]).pack(anchor="w", padx=px(22), pady=(px(2), px(16)))

        body = tk.Frame(frame, bg=C["bg"])
        body.pack(fill="both", expand=True, padx=px(22), pady=(px(18), px(16)))

        # status cards
        cards = tk.Frame(body, bg=C["bg"])
        cards.pack(fill="x")
        cards.columnconfigure((0, 1), weight=1, uniform="card")

        def card(col, title):
            f = tk.Frame(cards, bg=C["card"], highlightthickness=1, highlightbackground=C["border"])
            f.grid(row=0, column=col, sticky="nsew", padx=(0, px(6)) if col == 0 else (px(6), 0))
            tk.Label(f, text=title, font=(FONT, 10), fg=C["muted"],
                     bg=C["card"]).pack(anchor="w", padx=px(16), pady=(px(12), 0))
            row = tk.Frame(f, bg=C["card"])
            row.pack(anchor="w", padx=px(16))
            dot = tk.Label(row, text="●", font=(FONT, 12), fg=C["off"], bg=C["card"])
            dot.pack(side="left")
            val = tk.Label(row, text=tr("讀取中...", "Loading..."), font=(FONT, 15, "bold"),
                           fg=C["text"], bg=C["card"])
            val.pack(side="left", padx=(px(4), 0))
            # always two lines tall, so a note that wraps in one language doesn't make the card taller
            detail = tk.Label(f, text=" ", font=(FONT, 9), fg=C["muted"], bg=C["card"], height=2,
                              anchor="nw", justify="left", wraplength=px(250))
            detail.pack(fill="x", padx=px(16), pady=(0, px(8)))
            return dot, val, detail

        w["mon"] = card(0, tr("背景監控", "Background monitoring"))
        w["net"] = card(1, tr("網路", "Network"))

        def section(title):
            row = tk.Frame(body, bg=C["bg"])
            row.pack(fill="x", pady=(px(18), px(6)))
            tk.Label(row, text=title, font=(FONT, 10, "bold"), fg=C["muted"], bg=C["bg"]).pack(side="left")
            return row

        # action buttons
        section(tr("操作", "Actions"))
        acts = tk.Frame(body, bg=C["bg"])
        acts.pack(fill="x")
        acts.columnconfigure((0, 1), weight=1, uniform="btn")
        rim, w["install"] = make_button(acts, tr("安裝／更新並開始監控", "Install / update and start monitoring"),
                                        lambda: run_bg(install), "primary")
        w["install"].config(font=(FONT, 12, "bold"), pady=px(9))
        rim.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, px(8)))
        for i, (text, cmd) in enumerate([
                (tr("恢復網路並重新開啟監控", "Restore network and restart monitoring"), on_restore),
                (tr("停止監控", "Stop monitoring"), on_stop),
                (tr("預覽警告畫面", "Preview warning"), on_preview),
                (tr("開啟紀錄檔", "Open log"), on_log)]):
            rim, b = make_button(acts, text, cmd, "secondary")
            rim.grid(row=1 + i // 2, column=i % 2, sticky="ew", pady=(0, px(8)),
                     padx=(0, px(4)) if i % 2 == 0 else (px(4), 0))
            if i == 0:
                w["restore"] = b

        # activity log
        w["busy"] = tk.Label(section(tr("執行紀錄", "Activity")), text="", font=(FONT, 10),
                             fg=C["ok"], bg=C["bg"])
        w["busy"].pack(side="right")
        w["out"] = out = scrolledtext.ScrolledText(
            body, width=60, height=9, font=(FONT, 10), wrap="word", relief="flat", bd=0,
            bg=C["card"], fg=C["text"], highlightthickness=1, highlightbackground=C["border"],
            highlightcolor=C["border"], padx=px(10), pady=px(8))
        out.pack(fill="both", expand=True)  # takes up any spare room of the fixed-size window
        out.tag_config("hint", foreground=C["muted"])
        out.tag_config("err", foreground=C["bad"])
        write(tr("按上方按鈕執行操作，進度會顯示在這裡。", "Click a button above; progress is shown here."),
              "hint")

        foot = tk.Frame(body, bg=C["bg"])
        foot.pack(fill="x", pady=(px(10), 0))
        rim, b = make_button(foot, tr("解除安裝", "Uninstall"), on_uninstall, "danger")
        b.config(font=(FONT, 10), padx=px(10), pady=px(4), width=10)  # same width in both languages
        rim.pack(side="right")

    root.protocol("WM_DELETE_WINDOW", on_close)
    if _LANG_ARG or saved_lang():
        show_panel()
    else:
        choose_lang()
        center()
        root.after(100, lambda: set_window_icons(root, icon))  # after Tk has shown (mapped) the window
    pump()
    root.mainloop()


# ---------------- Main ----------------
def respond(reason: str, dry_run: bool):
    """Handle a trigger. Returns the full-screen warning process (may be None)."""
    init_lang()  # use the language most recently chosen in the control panel (the monitor may predate the change)
    log.critical(tr("偵測到疑似勒索病毒行為：%s", "Possible ransomware behavior detected: %s"), reason)
    # pause the encrypting program before anything else: every second it keeps running costs files
    found = _early_paused[:]  # the programs behind a destructive command, paused already
    _early_paused.clear()
    if PAUSE_ON_TRIGGER and IS_WINDOWS:
        seen = {p["pid"] for p in found}
        found += [p for p in pause_writers(dry_run) if p["pid"] not in seen]
    if dry_run:
        log.warning(tr("[測試模式] 正式模式下，此時會切斷網路",
                       "[Test mode] In normal mode the network would be cut off now"))
        return fullscreen_alert(reason, "test", paused=found)
    record_paused(found)
    if DEFENDER_SCAN_ON_TRIGGER and IS_WINDOWS:
        threading.Thread(target=ask_defender, args=([p["path"] for p in found if p["path"]],),
                         daemon=True).start()
    ok = disconnect_network()
    proc = fullscreen_alert(reason, "cut" if ok else "partial", paused=found)
    if HIBERNATE_ON_TRIGGER:
        log.critical(tr("依設定立即休眠", "Hibernating now, as configured"))
        time.sleep(3)  # let the warning appear first, so it is there after waking up
        _run([sys_exe("shutdown.exe"), "/h"])
    return proc


def run(args):
    exit_with_launcher()
    try:
        from watchdog.observers import Observer
    except ImportError:
        msg = tr("缺少 watchdog 套件，請先執行：pip install watchdog",
                 "The watchdog package is missing. Run: pip install watchdog")
        log.error(msg)
        alert(tr("RansomGuard 無法啟動", "RansomGuard could not start"), msg)
        sys.exit(1)

    if IS_WINDOWS and not args.dry_run and not is_admin():
        msg = tr("需要系統管理員權限才能切斷網路。\n請用「以系統管理員身分執行」啟動，或改用 --dry-run 測試。",
                 "Administrator rights are needed to cut off the network.\n"
                 "Start it with \"Run as administrator\", or use --dry-run to test.")
        log.error(msg)
        alert(tr("RansomGuard 無法啟動", "RansomGuard could not start"), msg)
        sys.exit(1)
    if not args.dry_run and not single_instance():
        log.info(tr("已經有監控在執行，這次不再啟動", "Monitoring is already running; not starting again"))
        sys.exit(0)
    if not args.dry_run:  # safe now: no other monitor is watching the old canary files
        remove_canaries(LEGACY_CANARY_NAMES)
        cleanup_old_files()

    st = load_state()
    if st.get("triggered_at"):
        alert(tr("RansomGuard 提醒", "RansomGuard reminder"),
              tr(f"上次在 {st['triggered_at']} 偵測到疑似勒索病毒並切斷了網路。\n"
                 f"確認電腦安全後，{restore_hint()}。",
                 f"Possible ransomware was detected at {st['triggered_at']} and the network was cut off.\n"
                 f"Once you're sure the computer is safe, {restore_hint()}."))

    watch_dirs = [Path(p) for p in args.watch] if args.watch else default_watch_dirs()
    watch_dirs = [d for d in watch_dirs if d.is_dir()]
    if not watch_dirs:
        log.error(tr("沒有可監控的資料夾", "No folders to watch"))
        sys.exit(1)
    canaries = plant_canaries(watch_dirs if args.watch else default_canary_dirs(), upgrade=not args.dry_run)

    stop = threading.Event()

    def on_trigger(reason):
        proc = respond(reason, args.dry_run)
        if not args.dry_run:
            if proc is not None:
                # wait for the user to close the warning, so it isn't closed together with this program
                keep_offline(proc)
                if proc.returncode != 0:  # the window failed: fall back to a regular alert so the user still knows
                    log.error(tr("全螢幕警告異常結束（代碼 %s）", "Full-screen warning ended abnormally (code %s)"),
                              proc.returncode)
                    alert(tr("RansomGuard：偵測到疑似勒索病毒，網路已切斷",
                             "RansomGuard: possible ransomware detected, network cut off"), reason)
                    time.sleep(60)
            stop.set()

    scanner = None
    if DEFENDER_SCAN_DOWNLOADS and IS_WINDOWS and MPCMDRUN.is_file():
        scanner = DownloadScanner()
        scanner.start()
    handler = make_handler(canaries, on_trigger, args.dry_run, scanner.add if scanner else None)

    def start_observer():
        obs = Observer()
        for d in watch_dirs:
            if d.is_dir():
                obs.schedule(handler, str(d), recursive=True)
        obs.start()
        return obs

    observer = start_observer()
    procmon = None
    if PROCESS_MONITOR and IS_WINDOWS:
        procmon = ProcessMonitor(handler.fire, kill=not args.dry_run)
        procmon.start()
    if FROZEN and not args.dry_run:
        threading.Thread(target=update_watcher, args=(stop,), daemon=True).start()
    restarts = 0

    log.info(tr("RansomGuard %s 開始監控%s：%s", "RansomGuard %s started monitoring%s: %s"), VERSION,
             tr("（測試模式）", " (test mode)") if args.dry_run else "",
             "; ".join(str(d) for d in watch_dirs))
    log.info(tr("誘餌檔：%s", "Canary files: %s"), "; ".join(str(p) for p in canaries))
    try:
        last = time.time()
        while not stop.wait(1):
            if time.time() - last < CHECK_INTERVAL:
                continue
            last = time.time()
            periodic_check(handler, canaries)
            # restart a monitor component that stopped unexpectedly (e.g. a watched folder vanished), up to 10 times
            if restarts < 10 and not observer.is_alive():
                restarts += 1
                log.error(tr("檔案監控意外停止，重新啟動（第 %d 次）",
                             "File monitor stopped unexpectedly; restarting (attempt %d)"), restarts)
                observer = start_observer()
            if restarts < 10 and procmon is not None and not procmon.alive():
                restarts += 1
                log.error(tr("程序監控意外停止，重新啟動（第 %d 次）",
                             "Process monitor stopped unexpectedly; restarting (attempt %d)"), restarts)
                procmon.start()
    except KeyboardInterrupt:
        log.info(tr("使用者中止", "Stopped by user"))
    finally:
        if procmon is not None:
            procmon.stop()
        observer.stop()
        observer.join()
        log.info(tr("監控結束", "Monitoring ended"))


def main():
    if restart_if_borrowed_files():
        return
    fix_console_encoding()
    langs = ["zh", "en"]
    pre = argparse.ArgumentParser(add_help=False)  # read --lang first so the help text is in the right language
    pre.add_argument("--lang", choices=langs)
    init_lang(pre.parse_known_args()[0].lang)
    ap = argparse.ArgumentParser(description=tr("偵測勒索病毒行為並自動斷網",
                                                "Detects ransomware behavior and cuts off the network"))
    ap.add_argument("--version", action="version", version=f"RansomGuard {VERSION}")
    ap.add_argument("--monitor", action="store_true",
                    help=tr("開始監控（.exe 不加參數會開啟控制台）",
                            "start monitoring (the .exe opens the control panel when run without options)"))
    ap.add_argument("--gui", action="store_true", help=tr("開啟控制台", "open the control panel"))
    ap.add_argument("--update", action="store_true",
                    help=tr("開啟控制台並立刻更新到最新版本", "open the control panel and update to the latest version"))
    ap.add_argument("--dry-run", action="store_true",
                    help=tr("測試模式，不會真的斷網", "test mode: never actually cut off the network"))
    ap.add_argument("--restore", action="store_true",
                    help=tr("恢復網路，並重新開啟背景監控", "restore the network and restart background monitoring"))
    ap.add_argument("--install", action="store_true",
                    help=tr("安裝／更新背景監控並開始監控", "install / update background monitoring and start it"))
    ap.add_argument("--watch", action="append", metavar="DIR",
                    help=tr("自訂監控資料夾（可重複）", "watch a custom folder (can be repeated)"))
    ap.add_argument("--test-alert", action="store_true",
                    help=tr("只顯示全螢幕警告看看樣子，不偵測也不斷網",
                            "only show the full-screen warning; no detection, no network cut"))
    ap.add_argument("--lang", choices=langs,
                    help=tr("介面語言：zh＝中文(繁體)、en＝English；預設依 Windows 顯示語言",
                            "interface language: zh = 中文(繁體) (Traditional Chinese), en = English; "
                            "defaults to the Windows display language"))
    args = ap.parse_args()
    setup_logging()
    if args.test_alert:
        fullscreen_alert(tr("這是警告畫面的預覽（--test-alert），沒有偵測到任何東西",
                            "This is a preview of the warning (--test-alert); nothing was detected"),
                         "test", wait=True)
    elif args.restore:
        restore_network(log.info)
    elif args.install:
        if IS_WINDOWS and not is_admin():
            log.error(tr("需要以系統管理員身分執行才能安裝", "Administrator rights are needed to install"))
            sys.exit(1)
        try:
            ok = install(log.info)
        except Exception:
            log.exception(tr("安裝失敗", "Install failed"))
            ok = False
        sys.exit(0 if ok else 1)
    elif args.gui or args.update or (FROZEN and not (args.monitor or args.dry_run or args.watch)):
        gui(auto_update=args.update)
    else:
        run(args)


if __name__ == "__main__":
    main()
