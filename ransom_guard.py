#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RansomGuard — 偵測疑似勒索病毒的加密行為，觸發時自動切斷網路。

偵測方式（任一成立就觸發）：
  1. 誘餌檔（canary）被修改、移動或刪除（另有定期檢查，避免漏掉事件）
  2. 短時間內多個檔案「壞掉」：.docx/.pdf/.jpg/.mp4 等檔頭不對了，
     或純文字檔（.txt/.py/.cpp…）變成高亂度內容（像被加密）
  3. 短時間內大量檔案被改成陌生副檔名（例如 報告.docx → 報告.docx.locked）
  4. 短時間內多個資料夾出現勒索訊息檔（例如 HOW_TO_DECRYPT.txt）
  5. 有程序執行勒索病毒/入侵者常用的破壞指令：刪除系統還原點（vssadmin、wmic）、
     關閉開機修復（bcdedit）、刪除備份（wbadmin）、清除事件紀錄、關閉 Defender
     （正式模式會立刻終止該程序）

觸發後：停用所有網路介面卡（失敗時改用防火牆封鎖）→ 寫入紀錄
        → 全螢幕紅色警告（所有螢幕、閃爍、警示音），警告期間網路卡若被重新啟用會再次停用
        （可選：HIBERNATE_ON_TRIGGER = True 會直接休眠，讓加密停下來）

用法（Windows，正式模式需以系統管理員身分執行）：
  python ransom_guard.py             正式監控（打包成 .exe 後，不加參數會開啟控制台）
  python ransom_guard.py --monitor   正式監控（排程工作用這個）
  python ransom_guard.py --gui       控制台：安裝、恢復網路並重新開啟監控、預覽警告、解除安裝
  python ransom_guard.py --dry-run   測試模式：只記錄與跳窗，不會真的斷網
  python ransom_guard.py --restore   恢復網路，並重新開啟背景監控
  python ransom_guard.py --install   安裝／更新背景監控（.exe 會複製到 Program Files）
  python ransom_guard.py --test-alert  預覽全螢幕警告（不偵測、不斷網）
  python ransom_guard.py --watch D:\\資料 --watch E:\\備份   自訂監控資料夾

需要套件：pip install watchdog
紀錄檔位置：%LOCALAPPDATA%\\RansomGuard\\guard.log

打包成單一執行檔（輸出 dist\\RansomGuard.exe；圖標 icon.ico 由 make_icon.py 產生）：
  python -m PyInstaller --onefile --windowed --uac-admin --name RansomGuard --icon ..\\icon.ico ^
         --distpath dist --workpath build --specpath build ransom_guard.py

下載與更新：https://github.com/leo-code-del/RansomGuard/releases
  下載新版 RansomGuard.exe → 執行 → 按「安裝／更新並開始監控」
"""

import argparse
import base64
import ctypes
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
import uuid
from collections import Counter, deque
from logging.handlers import RotatingFileHandler
from pathlib import Path

VERSION = "1.1.0"  # 發布新版時改這裡，並在 GitHub 建立對應的 Release（v1.1.0）
IS_WINDOWS = os.name == "nt"
FROZEN = bool(getattr(sys, "frozen", False))  # 用 PyInstaller 打包成 .exe 執行中
TASK_NAME = "RansomGuard"
INSTALL_DIR = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "RansomGuard"
INSTALL_EXE = INSTALL_DIR / "RansomGuard.exe"

# =============== 可調整的設定 ===============
WINDOW_SEC = 30              # 統計時間窗（秒）
BROKEN_THRESHOLD = 8         # 時間窗內「壞掉」的檔案數達到此值就觸發
EXT_CHANGE_THRESHOLD = 10    # 時間窗內被改成陌生副檔名的檔案數達到此值就觸發
ENTROPY_LIMIT = 7.5          # 純文字檔亂度上限（bits/byte；加密後約 7.9–8.0）
ENTROPY_MIN_SIZE = 4096      # 小於此大小的檔案不做亂度判斷（樣本太少不準）
NOTE_DIR_THRESHOLD = 3       # 時間窗內有幾個資料夾出現勒索訊息檔就觸發
PROCESS_MONITOR = True       # 監看新程序，攔截刪除還原點、關閉 Defender 等破壞指令
CHECK_INTERVAL = 15          # 每隔幾秒定期檢查誘餌檔與監控狀態
HIBERNATE_ON_TRIGGER = False # True：斷網後立刻休眠，阻止加密繼續進行
# ============================================

CANARY_NAMES = ["!!!_canary_勿刪.docx", "!!!_canary_勿刪.xlsx", "zzz_canary_勿刪.docx"]
CANARY_BYTES = ((
    "這是防勒索病毒的誘餌檔（RansomGuard canary），請勿開啟修改、移動或刪除。\n"
    "This is a ransomware canary file. Do not modify, move or delete it.\n"
) * 200).encode("utf-8")

# 常見檔案格式的檔頭（被加密後檔頭幾乎一定會壞）；(位移, 內容) 表示檔頭不在開頭
_OLE = [b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"]
_ZIP = [b"PK\x03\x04"]
_RIFF = [b"RIFF"]
_MP4 = [(4, b"ftyp"), (4, b"moov"), (4, b"mdat"), (4, b"wide"), (4, b"free"), (4, b"skip")]
_MKV = [b"\x1a\x45\xdf\xa3"]
MAGIC = {
    ".docx": _ZIP, ".xlsx": _ZIP, ".pptx": _ZIP, ".odt": _ZIP, ".ods": _ZIP,
    ".odp": _ZIP, ".epub": _ZIP, ".docm": _ZIP, ".xlsm": _ZIP, ".pptm": _ZIP,
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
    ".flac": [b"fLaC"], ".ogg": [b"OggS"],
    ".rar": [b"Rar!\x1a\x07"],
    ".7z": [b"7z\xbc\xaf\x27\x1c"],
    ".gz": [b"\x1f\x8b"],
    ".sqlite": [b"SQLite format 3\x00"],
}
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
}
COMMON_EXTS = set(MAGIC) | TEXT_EXTS | OTHER_COMMON_EXTS
IGNORE_EXTS = {".tmp", ".crdownload", ".part", ".download", ".partial"}

# 勒索訊息檔名（勒索病毒會在每個資料夾丟一份同名的說明檔）
_S = r"[\W_]*"
NOTE_PATTERN = re.compile(
    r"decrypt|ransom|解密|贖金|赎金|勒索"
    rf"|(recover|restore|unlock|return|get{_S}back){_S}(all{_S})?(my|your|the)?{_S}files"
    rf"|files{_S}(are{_S}|were{_S}|have{_S}been{_S})?(encrypted|locked)"
    rf"|how{_S}to{_S}(recover|restore|decrypt|unlock|back)"
    rf"|(恢復|恢复|還原|还原){_S}(您的|你的)?(檔案|文件)|(檔案|文件){_S}(已經|已经|已)?(被)?加密",
    re.IGNORECASE)

# 勒索病毒/入侵者常用的破壞指令（比對小寫後的命令列）
_DANGEROUS_CMDS = [
    (r"vssadmin(\.exe)?\W.*\bdelete\s+shadows", "刪除系統還原點"),
    (r"vssadmin(\.exe)?\W.*\bresize\s+shadowstorage", "縮小還原點空間（等於刪除還原點）"),
    (r"\bshadowcopy\b.*\bdelete\b", "刪除系統還原點"),
    (r"win32_shadowcopy.*(\.delete\(|remove-(cim|wmi)\w*)", "刪除系統還原點"),
    (r"bcdedit(\.exe)?\W.*recoveryenabled\s+(no|off|false|0)\b", "關閉 Windows 開機修復"),
    (r"bcdedit(\.exe)?\W.*bootstatuspolicy\s+ignoreallfailures", "關閉 Windows 開機修復"),
    (r"wbadmin(\.exe)?\W.*\bdelete\s+(catalog|systemstatebackup|backup)", "刪除 Windows 備份"),
    (r"wevtutil(\.exe)?\W+(cl|clear-log)\s", "清除事件紀錄"),
    (r"set-mppreference\b.*-disable(realtimemonitoring|behaviormonitoring|ioavprotection"
     r"|scriptscanning|blockatfirstseen)\s+(\$true|1)\b", "關閉 Windows Defender 防護"),
]
DANGEROUS_CMDS = [(re.compile(p), what) for p, what in _DANGEROUS_CMDS]
_PS_ENCODED = re.compile(r"(?:^|\s)[-/]e(?:c|nc?\w*)?\s+([A-Za-z0-9+/=]{12,})", re.IGNORECASE)

log = logging.getLogger("RansomGuard")


# ---------------- 基本工具 ----------------
def app_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") if IS_WINDOWS else None
    d = Path(base) / "RansomGuard" if base else Path.home() / ".ransom_guard"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _system32() -> Path:
    """系統資料夾的絕對路徑。外部程式一律用絕對路徑執行，避免有人在目前資料夾
    放一個假的 powershell.exe，被本程式以系統管理員權限執行。"""
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
    # 輸出被導向檔案或管線時（不是主控台），預設編碼可能不支援中文，print 會直接當掉
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
    if sys.stderr is not None:  # 用 pythonw 執行時沒有主控台
        sh = logging.StreamHandler()
        sh.setFormatter(fmt)
        log.addHandler(sh)


def load_state() -> dict:
    try:
        return json.loads((app_dir() / "state.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_state(st: dict):
    (app_dir() / "state.json").write_text(
        json.dumps(st, ensure_ascii=False, indent=2), encoding="utf-8")


def is_admin() -> bool:
    if not IS_WINDOWS:
        return getattr(os, "geteuid", lambda: -1)() == 0
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


_JOB = None
_MUTEX = None


def kill_with_me(proc):
    """把子程序放進 Job Object：本程式結束（包括被強制終止）時子程序跟著結束，
    不會留下一直在背景執行的孤兒 PowerShell。"""
    global _JOB
    if not IS_WINDOWS:
        return
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateJobObjectW.restype = ctypes.c_void_p
    k32.OpenProcess.restype = ctypes.c_void_p
    k32.SetInformationJobObject.argtypes = [ctypes.c_void_p, ctypes.c_int,
                                            ctypes.c_void_p, ctypes.c_ulong]
    k32.AssignProcessToJobObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    k32.CloseHandle.argtypes = [ctypes.c_void_p]
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
            log.warning("無法建立 Job Object（錯誤 %d）", ctypes.get_last_error())
            return
        _JOB = job
    h = k32.OpenProcess(0x0100 | 0x0001, False, proc.pid)  # SET_QUOTA | TERMINATE
    if not h or not k32.AssignProcessToJobObject(_JOB, h):
        log.warning("無法把子程序 %s 放進 Job Object（錯誤 %d）", proc.pid, ctypes.get_last_error())
    if h:
        k32.CloseHandle(h)


def exit_with_launcher():
    """單一檔案的 .exe 其實是兩個程序：外層負責解壓縮，內層才是本程式。工作排程器停止
    工作時只會結束外層，所以外層一結束這裡也跟著結束，避免監控變成停不掉的孤兒。"""
    if not (IS_WINDOWS and FROZEN):
        return
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.OpenProcess.restype = ctypes.c_void_p
    k32.QueryFullProcessImageNameW.argtypes = [ctypes.c_void_p, ctypes.c_ulong,
                                               ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_ulong)]
    k32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
    k32.CloseHandle.argtypes = [ctypes.c_void_p]
    h = k32.OpenProcess(0x00100000 | 0x1000, False, os.getppid())  # SYNCHRONIZE | QUERY_LIMITED
    if not h:
        return
    buf = ctypes.create_unicode_buffer(1024)
    n = ctypes.c_ulong(len(buf))
    if (not k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(n))
            or norm(buf.value) != norm(sys.executable)):
        k32.CloseHandle(h)  # 外層不是本程式（例如 onedir 打包），不必處理
        return

    def wait():
        k32.WaitForSingleObject(h, 0xFFFFFFFF)
        log.info("外層程序已結束，監控跟著結束")
        os._exit(0)
    threading.Thread(target=wait, daemon=True).start()


def single_instance() -> bool:
    """同一時間只允許一個正式監控；已經有一個在執行就回傳 False。"""
    global _MUTEX
    if not IS_WINDOWS:
        return True
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateMutexW.restype = ctypes.c_void_p
    _MUTEX = k32.CreateMutexW(None, False, "Global\\RansomGuardMonitor")
    return ctypes.get_last_error() != 183  # ERROR_ALREADY_EXISTS


def alert(title: str, msg: str):
    """跳出最上層警告視窗（不阻塞監控）。"""
    if not IS_WINDOWS:
        log.info("[警告視窗] %s：%s", title, msg.replace("\n", " "))
        return
    def _box():
        # MB_ICONERROR | MB_SYSTEMMODAL | MB_TOPMOST
        ctypes.windll.user32.MessageBoxW(None, msg, title, 0x10 | 0x1000 | 0x40000)
    threading.Thread(target=_box).start()


# 全螢幕警告：用 PowerShell + WinForms 畫，所有螢幕都蓋滿、紅色閃爍、發出警示音
# （腳本與資料直接放在命令列，不寫成檔案，避免以系統管理員執行前被其他程式偷換）
ALERT_PS1 = r'''
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

$info = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__INFO_B64__')) | ConvertFrom-Json
$isTest = ($info.status -eq 'test')
switch ($info.status) {
    'cut'     { $netText = '網路已自動切斷' }
    'partial' { $netText = '網路可能沒有完全切斷！請立刻拔掉網路線、關閉 Wi-Fi' }
    default   { $netText = '（測試模式：沒有切斷網路）' }
}
$steps = @(
    '1. 不要恢復網路，也不要插上備份硬碟或隨身碟',
    '2. 如果檔案還在一個一個被改名、打不開，立刻按住電源鍵強制關機',
    '3. 用手機拍下桌面或資料夾裡出現的勒索訊息',
    '4. 用手機（不要用這台電腦）更改 Email、銀行等重要帳號的密碼'
) -join "`n"
if ($isTest) {
    $hint = '這是測試，按下方按鈕關閉即可。'
} else {
    $hint = "如果確認是誤判（例如是你自己動到誘餌檔）：關閉這個視窗後，$($info.restore)。"
}

$script:ack = $false
$script:forms = New-Object System.Collections.ArrayList
$script:tick = 0
$script:bright = [System.Drawing.Color]::FromArgb(205, 0, 0)
$script:dark   = [System.Drawing.Color]::FromArgb(105, 0, 0)
$yellow = [System.Drawing.Color]::FromArgb(255, 225, 0)
$white  = [System.Drawing.Color]::White
$fontName = 'Microsoft JhengHei UI'

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
    $f.Text = 'RansomGuard 警告'
    $f.BackColor = $script:bright
    $W = $scr.Bounds.Width
    $H = $scr.Bounds.Height
    $k = $H / 1080.0

    $y = [int](60 * $k)
    $y = Add-Text $f '！！ 偵測到疑似勒索病毒 ！！' (50 * $k) $true $white $y 40 ($W - 80) 'MiddleCenter'
    $y = Add-Text $f $netText (30 * $k) $true $yellow $y 40 ($W - 80) 'MiddleCenter'
    $y += [int](20 * $k)
    $y = Add-Text $f ("偵測時間：" + $info.time + "`n原因：" + $info.reason) (15 * $k) $false $white $y 80 ($W - 160) 'MiddleCenter'
    $y += [int](25 * $k)
    $y = Add-Text $f '接下來請這樣做：' (22 * $k) $true $yellow $y ([int]($W * 0.16)) ([int]($W * 0.68)) 'MiddleLeft'
    $y = Add-Text $f $steps (20 * $k) $false $white $y ([int]($W * 0.16)) ([int]($W * 0.68)) 'MiddleLeft'
    $y += [int](20 * $k)
    $y = Add-Text $f $hint (16 * $k) $false $white $y 80 ($W - 160) 'MiddleCenter'

    $btnFont = New-Object System.Drawing.Font($fontName, [single](18 * $k), [System.Drawing.FontStyle]::Bold)
    $bw = [int](380 * $k); $bh = [int](72 * $k); $gap = [int](40 * $k)
    $by = [Math]::Min($y + [int](30 * $k), $H - $bh - [int](30 * $k))
    $count = if ($isTest) { 1 } else { 2 }
    $bx = [int](($W - ($count * $bw + ($count - 1) * $gap)) / 2)

    $ok = New-Object System.Windows.Forms.Button
    $ok.Text = '我知道了（關閉警告）'
    $ok.Font = $btnFont
    $ok.FlatStyle = 'Flat'
    $ok.BackColor = $white
    $ok.ForeColor = $script:dark
    $ok.SetBounds($bx, $by, $bw, $bh)
    $ok.add_Click({ Close-All })
    $f.Controls.Add($ok)

    if (-not $isTest) {
        $sd = New-Object System.Windows.Forms.Button
        $sd.Text = '立即強制關機'
        $sd.Font = $btnFont
        $sd.FlatStyle = 'Flat'
        $sd.BackColor = [System.Drawing.Color]::Black
        $sd.ForeColor = $yellow
        $sd.SetBounds($bx + $bw + $gap, $by, $bw, $bh)
        $sd.add_Click({
            $r = [System.Windows.Forms.MessageBox]::Show($this.FindForm(), "確定要立即強制關機嗎？`n尚未儲存的工作會遺失。", 'RansomGuard', [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
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
    if ($script:tick -le 24) {
        $c = if ($script:tick % 2) { $script:dark } else { $script:bright }
        foreach ($f in $script:forms) { $f.BackColor = $c }
        if ($script:tick % 2) { [System.Media.SystemSounds]::Hand.Play() }
    }
    if (($script:tick % 4) -eq 0) { foreach ($f in $script:forms) { $f.TopMost = $true } }
})

for ($i = 1; $i -lt $script:forms.Count; $i++) { $script:forms[$i].Show() }
$timer.Start()
[System.Windows.Forms.Application]::Run($script:forms[0])
'''


def fullscreen_alert(reason: str, status: str, wait: bool = False):
    """全螢幕警告。status: cut（已斷網）/ partial（斷網不完整）/ test（測試）。"""
    log.warning("[全螢幕警告] %s（%s）", reason, status)
    if not IS_WINDOWS:
        return None
    try:
        info = json.dumps({
            "status": status,
            "reason": reason if len(reason) <= 160 else reason[:157] + "...",
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "restore": restore_hint(),
        }, ensure_ascii=False)
        script = ALERT_PS1.replace(
            "__INFO_B64__", base64.b64encode(info.encode("utf-8")).decode("ascii"))
        proc = subprocess.Popen(
            ps_encoded_args(script, "-STA", "-WindowStyle", "Hidden"),
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            creationflags=CREATE_NO_WINDOW)
        assert proc.stderr is not None
        try:
            rc = proc.wait(timeout=4)  # 4 秒內就出錯結束 = 視窗沒開起來
            if rc != 0:
                err = proc.stderr.read().decode("utf-8", "replace").strip()
                raise RuntimeError(f"全螢幕警告啟動失敗（代碼 {rc}）：{err[:300]}")
        except subprocess.TimeoutExpired:
            # 還在執行 = 警告視窗正常顯示中；持續讀掉錯誤輸出，免得管線塞滿卡住視窗
            threading.Thread(target=proc.stderr.read, daemon=True).start()
        if wait:
            proc.wait()
        return proc
    except Exception as ex:
        log.error("%s；改用一般警告視窗", ex)
        alert("RansomGuard：偵測到疑似勒索病毒", f"{reason}\n\n狀態：{status}")
        return None


def ps_encoded_args(script: str, *opts: str) -> list:
    """用 -EncodedCommand 執行一段 PowerShell 腳本（不必寫成檔案）。"""
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


# ---------------- 監控資料夾 ----------------
_KNOWN_FOLDERS = {
    "Desktop":   "B4BFCC3A-DB2C-424C-B029-7FE99A87C641",
    "Documents": "FDD39AD0-238F-46AF-ADB4-6C85480369C7",
    "Pictures":  "33E28130-4E1E-4676-835A-98395C3BC3BB",
    "Downloads": "374DE290-123F-4565-9164-39C4925E467B",
    "Videos":    "18989B1D-99B5-455B-841C-AB7C74E4DDFC",
    "Music":     "4BD8D571-6D19-48D3-BE97-422220080E43",
}


def _known_folder(name: str):
    """取得 Windows 實際的「文件」「圖片」等路徑（含 OneDrive 重新導向）。"""
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


def plant_canaries(dirs):
    paths = []
    for d in dirs:
        for name in CANARY_NAMES:
            p = Path(d) / name
            try:
                if p.exists() and p.read_bytes() != CANARY_BYTES:
                    log.warning("誘餌檔內容和預期不同（程式沒執行時被改過？）：%s", p)
                    alert("RansomGuard 注意",
                          f"誘餌檔在程式沒執行時被修改過：\n{p}\n\n請確認電腦是否異常。")
                if not p.exists() or p.read_bytes() != CANARY_BYTES:
                    p.write_bytes(CANARY_BYTES)
                paths.append(p)
            except OSError as ex:
                log.warning("無法建立誘餌檔 %s：%s", p, ex)
    return paths


def check_canaries(canaries):
    """回傳第一個異常誘餌檔的說明；全部正常回傳 None。"""
    for p in canaries:
        try:
            if Path(p).read_bytes() != CANARY_BYTES:
                return f"誘餌檔內容被修改：{p}"
        except FileNotFoundError:
            return f"誘餌檔不見了：{p}"
        except OSError:
            pass  # 暫時被鎖住（例如防毒正在掃描），下次再檢查
    return None


def periodic_check(handler, canaries):
    """定期檢查誘餌檔：檔案事件可能漏掉（緩衝區滿、檔案被鎖住時讀不到內容）。"""
    if handler.triggered_at is not None:
        return
    reason = check_canaries(canaries)
    if reason:
        handler.fire(reason + "（定期檢查發現）")


# ---------------- 判斷檔案是否「壞掉」 ----------------
# 雲端硬碟（OneDrive 等）尚未下載的檔案：一讀取就會觸發下載，不要碰
_CLOUD_ATTRS = 0x1000 | 0x40000 | 0x400000  # OFFLINE | RECALL_ON_OPEN | RECALL_ON_DATA_ACCESS


def _magic_ok(data: bytes, sigs) -> bool:
    for s in sigs:
        off, sig = s if isinstance(s, tuple) else (0, s)
        if data[off:off + len(sig)] == sig:
            return True
    return False


def broken_reason(path: str):
    ext = Path(path).suffix.lower()
    if ext not in MAGIC and ext not in TEXT_EXTS:
        return None
    try:
        st = os.stat(path)
        if getattr(st, "st_file_attributes", 0) & _CLOUD_ATTRS:
            return None
        size = st.st_size
        with open(path, "rb") as f:
            data = f.read(65536)
    except OSError:
        return None
    if len(data) < 8:  # 空檔或寫入中
        return None
    if not data.strip(b"\0"):  # 全部是 0：下載工具預先配置空間、還沒寫入內容
        return None
    if ext in MAGIC:
        ok = (b"%PDF" in data[:1024]) if ext == ".pdf" else _magic_ok(data, MAGIC[ext])
        return None if ok else "檔頭不符"
    if ext == ".ts" and data[0] == 0x47 and (len(data) <= 188 or data[188] == 0x47):
        return None  # MPEG-TS 影片（同副檔名），不是 TypeScript
    if size >= ENTROPY_MIN_SIZE:
        h = entropy(data)
        if h > ENTROPY_LIMIT:
            return f"亂度 {h:.2f}"
    return None


def suspicious_ext(event_type: str, src: str, dest: str) -> bool:
    if event_type == "moved":
        s, d = Path(src).suffix.lower(), Path(dest).suffix.lower()
        return s in COMMON_EXTS and d not in COMMON_EXTS and d != "" and s != d
    if event_type == "created":
        sfx = [x.lower() for x in Path(src).suffixes]
        return (len(sfx) >= 2 and sfx[-1] not in COMMON_EXTS
                and any(x in COMMON_EXTS for x in sfx[:-1]))
    return False


def ignorable(path: str) -> bool:
    name = os.path.basename(path)
    return name.startswith("~") or Path(name).suffix.lower() in IGNORE_EXTS


def is_ransom_note(name: str) -> bool:
    return bool(NOTE_PATTERN.search(Path(name).stem))


def dangerous_command(cmdline: str):
    """命令列是勒索病毒常用的破壞指令就回傳說明，否則回傳 None。
    PowerShell 的 -EncodedCommand 會先解碼再比對。"""
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
        for pat, what in DANGEROUS_CMDS:
            if pat.search(low):
                return what
    return None


# ---------------- 事件處理 ----------------
def make_handler(canaries, on_trigger, dry_run):
    from watchdog.events import FileSystemEventHandler

    class Guard(FileSystemEventHandler):
        def __init__(self):
            self.canaries = {norm(p) for p in canaries}
            self.broken = deque()   # (time, path)
            self.extchg = deque()
            self.notes = deque()    # (time, 資料夾)
            self.lock = threading.Lock()
            self.triggered_at = None

        def fire(self, reason):
            with self.lock:
                now = time.time()
                if self.triggered_at is not None:
                    # 正式模式只觸發一次；測試模式 10 秒後可再次觸發
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
                self.fire(f"{WINDOW_SEC} 秒內有 {n} 個{label}（例如 {example}）")

        def on_any_event(self, event):
            if event.is_directory:
                return
            try:
                self._handle(event)
            except Exception:
                log.exception("處理事件時發生錯誤")

        def _handle(self, e):
            t = e.event_type
            if t not in ("created", "modified", "moved", "deleted", "closed"):
                return
            src = e.src_path
            dest = getattr(e, "dest_path", "") or ""
            src = src.decode() if isinstance(src, bytes) else src
            dest = dest.decode() if isinstance(dest, bytes) else dest

            # 1. 誘餌檔
            if norm(src) in self.canaries:
                if t == "deleted":
                    return self.fire(f"誘餌檔被刪除：{src}")
                if t == "moved":
                    return self.fire(f"誘餌檔被改名或移動：{src} → {dest}")
                try:
                    if Path(src).read_bytes() != CANARY_BYTES:
                        return self.fire(f"誘餌檔內容被修改：{src}")
                except OSError:
                    pass
                return
            if dest and norm(dest) in self.canaries:
                return self.fire(f"有檔案覆蓋了誘餌檔：{src} → {dest}")

            # 3. 改成陌生副檔名
            if suspicious_ext(t, src, dest):
                self._count(self.extchg, dest or src, EXT_CHANGE_THRESHOLD,
                            "檔案被改成陌生副檔名", dest or src)

            # 4. 勒索訊息檔
            if t in ("created", "moved"):
                path = dest if t == "moved" else src
                if is_ransom_note(os.path.basename(path)):
                    log.warning("出現疑似勒索訊息檔：%s", path)
                    self._count(self.notes, os.path.dirname(path), NOTE_DIR_THRESHOLD,
                                "資料夾出現勒索訊息檔", path)

            # 2. 檔案內容壞掉
            if t in ("created", "modified", "closed", "moved"):
                path = dest if t == "moved" else src
                if ignorable(path):
                    return
                reason = broken_reason(path)
                if reason:
                    log.info("疑似被加密的檔案（%s）：%s", reason, path)
                    self._count(self.broken, path, BROKEN_THRESHOLD,
                                "檔案疑似被加密", path)

    return Guard()


# ---------------- 程序監控（Windows） ----------------
# 透過 WMI 取得每個新程序的命令列，一行一筆：PID <tab> 父 PID <tab> 名稱 <tab> 命令列
PROC_PS1 = r'''
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$q = "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'"
Register-CimIndicationEvent -Query $q -SourceIdentifier RGProc -ErrorAction Stop
[Console]::Out.WriteLine('READY'); [Console]::Out.Flush()
while ($true) {
    $e = Wait-Event -SourceIdentifier RGProc
    $p = $e.SourceEventArgs.NewEvent.TargetInstance
    $line = '{0}{4}{1}{4}{2}{4}{3}' -f $p.ProcessId, $p.ParentProcessId, $p.Name, $p.CommandLine, "`t"
    [Console]::Out.WriteLine(($line -replace "[\r\n]", ' ')); [Console]::Out.Flush()
    Remove-Event -EventIdentifier $e.EventIdentifier
}
'''


class ProcessMonitor:
    """監看新啟動的程序；發現勒索病毒常用的破壞指令（刪除還原點等）就終止它並觸發。"""

    def __init__(self, on_hit, kill: bool):
        self.on_hit = on_hit
        self.kill = kill
        self.proc = None

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
            if line == "READY":
                log.info("程序監控已啟動")
                continue
            parts = line.split("\t", 3)
            if len(parts) != 4:
                continue
            try:
                self._check(int(parts[0]), int(parts[1] or 0), parts[2], parts[3])
            except Exception:
                log.exception("檢查程序時發生錯誤")

    def _check(self, pid, ppid, name, cmdline):
        if ppid == os.getpid() and name.lower() == "powershell.exe":  # 本程式自己叫出來的
            return
        what = dangerous_command(cmdline)
        if not what:
            return
        if self.kill:
            try:
                os.kill(pid, signal.SIGTERM)  # Windows 上等於 TerminateProcess
                result = "已強制終止"
            except OSError as ex:
                result = f"無法終止：{ex}"
        else:
            result = "測試模式：未終止"
        log.critical("可疑指令（%s）%s PID %s，父程序 PID %s，%s：%s",
                     what, name, pid, ppid, result, cmdline)
        self.on_hit(f"有程序在{what}：{name}（PID {pid}，{result}）{cmdline[:120]}")


# ---------------- 網路控制（Windows） ----------------
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
        log.error("執行 %s 失敗：%s", args, ex)


def disconnect_network() -> bool:
    if not IS_WINDOWS:
        log.error("目前只支援 Windows 斷網")
        return False
    st = load_state()
    try:
        _, out, _ = _ps("Get-NetAdapter | Where-Object {$_.Status -ne 'Disabled'} "
                        "| ForEach-Object {$_.Name}")
        names = [l.strip() for l in out.splitlines() if l.strip()]
        st["disabled_adapters"] = sorted(set(st.get("disabled_adapters", []) + names))
        st["triggered_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        save_state(st)
        rc, _, err = _ps("Get-NetAdapter | Where-Object {$_.Status -ne 'Disabled'} "
                         "| Disable-NetAdapter -Confirm:$false")
        if rc != 0:
            log.error("停用網路卡時出現錯誤：%s", err)
    except Exception:
        log.exception("停用網路卡失敗")

    up = adapters_up()
    if up == "0":
        log.critical("已停用所有網路卡：%s", ", ".join(st.get("disabled_adapters", [])))
        return True
    log.error("仍有網路卡在線上（%s），改用防火牆封鎖與備援方式斷線", up)
    block_firewall()
    _run([sys_exe("ipconfig.exe"), "/release"])
    _run([sys_exe("netsh.exe"), "wlan", "disconnect"])
    return False


def adapters_up() -> str:
    """回傳連線中的網路卡數量（字串）；查詢失敗回傳 "?"。"""
    try:
        return _ps("@(Get-NetAdapter | Where-Object {$_.Status -eq 'Up'}).Count")[1]
    except Exception:
        return "?"


def block_firewall():
    """停用網路卡失敗時的備援：防火牆所有設定檔改成封鎖進出連線（原設定存進 state.json）。"""
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
            log.critical("已用防火牆封鎖所有進出連線")
        else:
            log.error("防火牆封鎖失敗：%s", err)
    except Exception:
        log.exception("防火牆封鎖失敗")


def keep_offline(proc):
    """警告視窗開著的期間，網路卡若被重新啟用（例如被惡意程式打開）就再停用一次。"""
    while proc.poll() is None:
        time.sleep(10)
        if proc.poll() is None and adapters_up() not in ("0", "?"):
            log.warning("偵測到網路卡被重新啟用，再次切斷網路")
            disconnect_network()


def _ps_quote(s: str) -> str:
    return "'" + str(s).replace("'", "''") + "'"


def network_cut(st: dict) -> bool:
    return bool(st.get("triggered_at") or st.get("disabled_adapters") or st.get("firewall"))


def restore_network(report=print) -> bool:
    """恢復網路卡與防火牆設定、重設誘餌檔，再重新開啟背景監控。"""
    if IS_WINDOWS and not is_admin():
        report("需要以系統管理員身分執行才能恢復網路。")
        return False
    st = load_state()
    if st.get("triggered_at"):
        report(f"RansomGuard 在 {st['triggered_at']} 切斷了網路。")
    installed = bool(task_state())
    report("停止監控（避免重設誘餌檔時又觸發）...")
    stop_monitor()

    ok = True
    names = st.get("disabled_adapters") or []
    if names:
        report("重新啟用網路卡...")
        # 一張一張啟用：其中一張不見了（例如拔掉的 USB 網卡）也不影響其他張
        _, out, err = _ps(
            f"$t = @(Get-NetAdapter -Name @({','.join(_ps_quote(n) for n in names)}) "
            "-ErrorAction SilentlyContinue | Where-Object {$_.Status -eq 'Disabled'}); "
            "foreach ($a in $t) { try { Enable-NetAdapter -Name $a.Name -Confirm:$false "
            "-ErrorAction Stop; \"OK`t$($a.Name)\" } "
            "catch { \"FAIL`t$($a.Name)`t$($_.Exception.Message)\" } }")
        lines = [l.split("\t") for l in out.splitlines() if l.strip()]
        for r in lines:
            if r[0] == "OK":
                log.info("已重新啟用網路卡：%s", r[1])
                report(f"  已啟用 {r[1]}")
            else:
                ok = False
                log.error("無法啟用網路卡 %s：%s", r[1], r[-1])
                report(f"  無法啟用 {r[1]}：{r[-1]}")
        if not lines:
            report("  網路卡都已經是啟用狀態" + (f"（{err}）" if err else ""))
    else:
        report("沒有被本程式停用的網路卡。")
    for p in st.get("firewall") or []:
        r = _ps(f"Set-NetFirewallProfile -Name {_ps_quote(p['Name'])} "
                f"-Enabled {_ps_quote(p['Enabled'])} -DefaultInboundAction {_ps_quote(p['In'])} "
                f"-DefaultOutboundAction {_ps_quote(p['Out'])}")
        if r[0] == 0:
            log.info("已還原防火牆設定：%s", p["Name"])
            report(f"  已還原防火牆設定 {p['Name']}")
        else:
            ok = False
            log.error("還原防火牆設定失敗（%s）：%s", p["Name"], r[2])
            report(f"  還原防火牆設定失敗（{p['Name']}）：{r[2]}")
    if network_cut(st):
        time.sleep(3)
        _run([sys_exe("ipconfig.exe"), "/renew"])
    if ok:
        save_state({})
    else:
        report("部分設定沒有還原成功，請按 Win+R 輸入 ncpa.cpl 手動啟用網路卡。")

    report("重設誘餌檔...")
    remove_canaries()
    if installed:
        report("重新開啟監控...")
        report("  監控已重新啟動" if start_monitor() else
               "  監控沒有正常啟動，請按「安裝／更新並開始監控」，或查看紀錄檔")
    else:
        report("尚未安裝背景監控（排程工作），所以沒有重新開啟監控。")
    up = adapters_up()
    report(f"完成。目前連線中的網路卡：{up} 張" + (
        "（Wi-Fi 可能需要幾秒鐘重新連線）" if up == "0" else ""))
    return ok


def remove_canaries():
    """刪掉誘餌檔，監控重新啟動時會建立新的（避免誤判「程式沒執行時被改過」）。"""
    for d in default_canary_dirs():
        for name in CANARY_NAMES:
            try:
                (d / name).unlink(missing_ok=True)
            except OSError as ex:
                log.warning("無法刪除誘餌檔 %s：%s", d / name, ex)


# ---------------- 背景監控（排程工作）與安裝 ----------------
# 背景監控程序：.exe 或 ransom_guard.py 加 --monitor、舊版不加參數的 ransom_guard.py，
# 以及它叫出來的程序監控 PowerShell（用編碼後的腳本內容辨認）
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
    """排程工作狀態（Running / Ready / Disabled…）；尚未安裝回傳空字串。"""
    try:
        return _ps(f"(Get-ScheduledTask -TaskName {_ps_quote(TASK_NAME)} "
                   "-ErrorAction SilentlyContinue).State")[1]
    except Exception:
        return ""


def stop_monitor():
    _ps(f"Stop-ScheduledTask -TaskName {_ps_quote(TASK_NAME)} -ErrorAction SilentlyContinue")
    proc_enc = ps_encoded_args(PROC_PS1)[-1][:200]
    _ps(_KILL_PS1.replace("__ME__", f"{os.getpid()},{os.getppid()}")
        .replace("__PROC__", proc_enc))
    log.info("已停止背景監控")


def start_monitor() -> bool:
    _ps(f"Start-ScheduledTask -TaskName {_ps_quote(TASK_NAME)} -ErrorAction Stop")
    time.sleep(5)  # 啟動失敗（例如缺套件）會在幾秒內結束
    return task_state() == "Running"


def launcher():
    """(執行檔, 參數)：執行本程式的方式。"""
    if FROZEN:
        return str(INSTALL_EXE), ""
    pyw = Path(sys.executable).with_name("pythonw.exe")
    # -E 忽略 PYTHON* 環境變數、-P 不從程式所在資料夾載入模組（避免被放假的 json.py）
    flags = "-E -P" if sys.version_info >= (3, 11) else "-E"
    return str(pyw if pyw.exists() else sys.executable), f'{flags} "{os.path.abspath(__file__)}"'


def desktop_lnk() -> Path:
    return _known_folder("Desktop") / "RansomGuard.lnk"


def restore_hint() -> str:
    if desktop_lnk().exists():
        return "開啟桌面上的「RansomGuard」，按「恢復網路並重新開啟監控」"
    if FROZEN:
        return f"執行 {sys.executable}，按「恢復網路並重新開啟監控」"
    return f"雙擊 {Path(os.path.abspath(__file__)).parent / '恢復網路.bat'} 恢復網路"


def install(report=print) -> bool:
    """複製到 Program Files、建立登入時以最高權限執行的排程工作與桌面捷徑，然後開始監控。"""
    report("停止舊的監控...")
    stop_monitor()
    if FROZEN and norm(sys.executable) != norm(INSTALL_EXE):
        # 以系統管理員執行的程式放在只有管理員能改的資料夾，才不會被偷換
        report(f"複製程式到 {INSTALL_DIR} ...")
        INSTALL_DIR.mkdir(parents=True, exist_ok=True)
        for i in range(10):
            try:
                shutil.copy2(sys.executable, str(INSTALL_EXE))
                break
            except PermissionError:  # 舊的監控程序還沒完全結束
                if i == 9:
                    raise
                time.sleep(1)
    exe, args = launcher()
    workdir = str(INSTALL_DIR if FROZEN else Path(os.path.abspath(__file__)).parent)
    report("建立登入時自動執行的排程工作...")
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
        f"-Principal $p -Settings $s -Description {_ps_quote('偵測勒索病毒行為並自動切斷網路')} "
        "-Force -ErrorAction Stop | Out-Null")
    if rc != 0:
        raise RuntimeError(f"建立排程工作失敗：{err}")
    report("建立桌面捷徑「RansomGuard」...")
    _ps(f"$s = (New-Object -ComObject WScript.Shell).CreateShortcut({_ps_quote(str(desktop_lnk()))}); "
        f"$s.TargetPath = {_ps_quote(exe)}; $s.Arguments = {_ps_quote((args + ' --gui').strip() if args else '')}; "
        f"$s.WorkingDirectory = {_ps_quote(workdir)}; $s.Description = 'RansomGuard 控制台'; $s.Save()")
    report("開始監控...")
    ok = start_monitor()
    log.info("已安裝背景監控：%s %s", exe, args)
    report("完成！監控已在背景執行，之後每次登入 Windows 都會自動啟動。" if ok else
           f"排程工作已建立，但監控目前狀態是 {task_state() or '未知'}，請查看紀錄檔。")
    return ok


def uninstall(report=print) -> bool:
    report("停止監控...")
    stop_monitor()
    _, _, err = _ps(f"Unregister-ScheduledTask -TaskName {_ps_quote(TASK_NAME)} "
                     "-Confirm:$false -ErrorAction SilentlyContinue")
    if task_state():
        report(f"刪除排程工作失敗：{err}")
        return False
    report("已刪除排程工作")
    desktop_lnk().unlink(missing_ok=True)
    remove_canaries()
    report("已刪除桌面捷徑與誘餌檔")
    if INSTALL_EXE.exists():
        if FROZEN and norm(sys.executable) == norm(INSTALL_EXE):
            # 正在執行的檔案刪不掉：交給 Windows 在下次開機時刪除
            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            k32.MoveFileExW(str(INSTALL_EXE), None, 4)  # MOVEFILE_DELAY_UNTIL_REBOOT
            k32.MoveFileExW(str(INSTALL_DIR), None, 4)
            report(f"{INSTALL_EXE} 會在下次開機時刪除")
        else:
            try:
                INSTALL_EXE.unlink()
                INSTALL_DIR.rmdir()
                report(f"已刪除 {INSTALL_DIR}")
            except OSError as ex:
                report(f"無法刪除 {INSTALL_DIR}：{ex}")
    log.info("已解除安裝背景監控")
    report("解除安裝完成。")
    return True


# ---------------- 控制台視窗 ----------------
def status_info():
    """控制台的兩張狀態卡：((文字, 燈號, 說明), (文字, 燈號, 說明))，燈號是 ok / warn / bad / off。"""
    s = task_state()
    mon = {"Running": ("執行中", "ok", "每次登入 Windows 都會自動啟動"),
           "Ready": ("已停止", "warn", "目前沒有勒索病毒防護"),
           "Disabled": ("已停用", "warn", "目前沒有勒索病毒防護"),
           "": ("尚未安裝", "off", "按「安裝／更新並開始監控」")}.get(s, (s, "warn", ""))
    st = load_state()
    if st.get("triggered_at"):
        net = ("已切斷", "bad", f"{st['triggered_at']} 偵測到可疑行為")
    elif network_cut(st):
        net = ("已切斷", "bad", "確認安全後再恢復網路")
    else:
        net = ("正常", "ok", "連線沒有被限制")
    return mon, net


def gui():
    import queue
    import tkinter as tk
    from tkinter import messagebox, scrolledtext

    if IS_WINDOWS and not is_admin():  # 以系統管理員身分重新開啟
        script = [] if FROZEN else [os.path.abspath(__file__)]
        params = subprocess.list2cmdline([*script, *sys.argv[1:]])
        if ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1) > 32:
            return
        messagebox.showerror("RansomGuard", "需要系統管理員權限才能使用控制台。")
        return
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)  # 高解析度螢幕上字才不會糊
    except Exception:
        pass

    root = tk.Tk()
    root.title("RansomGuard 控制台")
    root.resizable(False, False)
    icon = sys.executable if FROZEN else os.path.join(os.path.dirname(os.path.abspath(__file__)), "icon.ico")
    try:
        root.iconbitmap(default=icon)  # .exe 直接用內嵌的圖標；default 讓對話框也套用
    except tk.TclError:
        pass
    scale = root.winfo_fpixels("1i") / 96  # 間距跟著螢幕縮放比例放大

    def px(n):
        return int(n * scale)

    FONT = "Microsoft JhengHei UI"
    C = {"bg": "#f3f5f9", "card": "#ffffff", "border": "#dfe3eb", "header": "#1e293b",
         "text": "#1f2937", "muted": "#6b7280",
         "ok": "#16a34a", "warn": "#d97706", "bad": "#dc2626", "off": "#9ca3af"}
    # 按鈕樣式：(底色, 滑鼠移上去的底色, 字色, 停用時字色)
    STYLES = {"primary": ("#2563eb", "#1d4ed8", "#ffffff", "#bfd0f7"),
              "success": ("#16a34a", "#15803d", "#ffffff", "#bde5cb"),
              "secondary": ("#ffffff", "#eef1f6", C["text"], "#c3c9d4"),
              "danger": (C["bg"], "#fde8e8", C["bad"], "#e8b4b4")}
    root.configure(bg=C["bg"])

    q = queue.Queue()
    buttons = []

    def make_button(parent, text, cmd, name):
        rim = tk.Frame(parent)  # 1px 外框（tk 按鈕本身的框線在 Windows 上只能是黑色）
        b = tk.Button(rim, text=text, command=cmd, font=(FONT, 11), relief="flat", bd=0,
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

    # 標題列
    hdr = tk.Frame(root, bg=C["header"])
    hdr.pack(fill="x")
    top = tk.Frame(hdr, bg=C["header"])
    top.pack(fill="x", padx=px(22), pady=(px(16), 0))
    tk.Label(top, text="RansomGuard", font=(FONT, 17, "bold"), fg="#ffffff",
             bg=C["header"]).pack(side="left")
    tk.Label(top, text=f"v{VERSION}", font=(FONT, 10), fg="#94a3b8",
             bg=C["header"]).pack(side="left", anchor="s", padx=(px(8), 0), pady=(0, px(4)))
    tk.Label(hdr, text="偵測勒索病毒行為，發現異常時自動切斷網路", font=(FONT, 10), fg="#cbd5e1",
             bg=C["header"]).pack(anchor="w", padx=px(22), pady=(px(2), px(16)))

    body = tk.Frame(root, bg=C["bg"])
    body.pack(fill="both", padx=px(22), pady=(px(18), px(16)))

    # 狀態卡
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
        val = tk.Label(row, text="讀取中...", font=(FONT, 15, "bold"), fg=C["text"], bg=C["card"])
        val.pack(side="left", padx=(px(4), 0))
        detail = tk.Label(f, text=" ", font=(FONT, 9), fg=C["muted"], bg=C["card"],
                          justify="left", wraplength=px(230))
        detail.pack(anchor="w", padx=px(16), pady=(0, px(12)))
        return dot, val, detail

    mon_card = card(0, "背景監控")
    net_card = card(1, "網路")

    def show_status(info):
        for (dot, val, detail), (text, level, note) in zip((mon_card, net_card), info):
            dot.config(fg=C[level])
            val.config(text=text, fg=C["bad"] if level == "bad" else C["text"])
            detail.config(text=note or " ")
        cut = info[1][1] == "bad"  # 斷網時改成強調「恢復網路」
        style(install_btn, "secondary" if cut else "primary")
        style(restore_btn, "success" if cut else "secondary")

    def section(title):
        row = tk.Frame(body, bg=C["bg"])
        row.pack(fill="x", pady=(px(18), px(6)))
        tk.Label(row, text=title, font=(FONT, 10, "bold"), fg=C["muted"], bg=C["bg"]).pack(side="left")
        return row

    def write(msg, tag=None):
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
        busy.config(text="執行中...")
        out.config(state="normal")
        out.delete("1.0", "end")
        out.config(state="disabled")

        def work():
            try:
                fn(report)
            except Exception as ex:
                log.exception("控制台操作失敗")
                report(f"[失敗] {ex}")
            q.put(("done", None))
        threading.Thread(target=work, daemon=True).start()

    def pump():
        try:
            while True:
                kind, msg = q.get_nowait()
                if kind == "msg":
                    write(msg, "err" if msg.startswith("[失敗]") else None)
                elif kind == "status":
                    show_status(msg)
                else:
                    for b in buttons:
                        b.config(state="normal")
                    busy.config(text="")
                    refresh()
        except queue.Empty:
            pass
        root.after(100, pump)

    def on_restore():
        if network_cut(load_state()) and not messagebox.askyesno(
                "恢復網路", "請先確認這次是測試或誤判，而不是真的中了勒索病毒。\n\n確定要恢復網路嗎？",
                icon="warning"):
            return
        run_bg(restore_network)

    def on_stop():
        if messagebox.askyesno("停止監控", "停止後電腦就沒有勒索病毒防護，直到重新開啟監控或下次登入。\n確定要停止嗎？"):
            run_bg(lambda rep: (stop_monitor(), rep("監控已停止。")))

    def on_uninstall():
        if network_cut(load_state()):
            messagebox.showinfo("解除安裝", "網路目前被切斷，請先按「恢復網路並重新開啟監控」。")
            return
        if messagebox.askyesno("解除安裝", "確定要移除背景監控、桌面捷徑與誘餌檔嗎？"):
            run_bg(uninstall)

    def on_preview():
        run_bg(lambda rep: (rep("警告畫面開啟中，按「我知道了」即可關閉。"),
                            fullscreen_alert("這是警告畫面的預覽，沒有偵測到任何東西", "test")))

    def on_log():
        p = app_dir() / "guard.log"
        if p.exists():
            os.startfile(p)
        else:
            messagebox.showinfo("紀錄檔", "還沒有紀錄檔。")

    # 操作按鈕
    section("操作")
    acts = tk.Frame(body, bg=C["bg"])
    acts.pack(fill="x")
    acts.columnconfigure((0, 1), weight=1, uniform="btn")
    rim, install_btn = make_button(acts, "安裝／更新並開始監控", lambda: run_bg(install), "primary")
    install_btn.config(font=(FONT, 12, "bold"), pady=px(9))
    rim.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, px(8)))
    for i, (text, cmd) in enumerate([("恢復網路並重新開啟監控", on_restore), ("停止監控", on_stop),
                                     ("預覽警告畫面", on_preview), ("開啟紀錄檔", on_log)]):
        rim, b = make_button(acts, text, cmd, "secondary")
        rim.grid(row=1 + i // 2, column=i % 2, sticky="ew", pady=(0, px(8)),
                 padx=(0, px(4)) if i % 2 == 0 else (px(4), 0))
        if i == 0:
            restore_btn = b

    # 執行紀錄
    busy = tk.Label(section("執行紀錄"), text="", font=(FONT, 10), fg=C["ok"], bg=C["bg"])
    busy.pack(side="right")
    out = scrolledtext.ScrolledText(body, width=60, height=9, font=(FONT, 10), wrap="word",
                                    relief="flat", bd=0, bg=C["card"], fg=C["text"],
                                    highlightthickness=1, highlightbackground=C["border"],
                                    highlightcolor=C["border"], padx=px(10), pady=px(8))
    out.pack(fill="x")
    out.tag_config("hint", foreground=C["muted"])
    out.tag_config("err", foreground=C["bad"])
    write("按上方按鈕執行操作，進度會顯示在這裡。", "hint")

    foot = tk.Frame(body, bg=C["bg"])
    foot.pack(fill="x", pady=(px(10), 0))
    rim, b = make_button(foot, "解除安裝", on_uninstall, "danger")
    b.config(font=(FONT, 10), padx=px(10), pady=px(4))
    rim.pack(side="right")

    refresh()
    pump()
    root.update_idletasks()  # 視窗置中偏上
    root.geometry(f"+{(root.winfo_screenwidth() - root.winfo_width()) // 2}"
                  f"+{(root.winfo_screenheight() - root.winfo_height()) // 3}")
    root.mainloop()


# ---------------- 主程式 ----------------
def respond(reason: str, dry_run: bool):
    """觸發後的處理。回傳全螢幕警告的程序（可能是 None）。"""
    log.critical("偵測到疑似勒索病毒行為：%s", reason)
    if dry_run:
        log.warning("[測試模式] 正式模式下，此時會切斷網路")
        return fullscreen_alert(reason, "test")
    ok = disconnect_network()
    proc = fullscreen_alert(reason, "cut" if ok else "partial")
    if HIBERNATE_ON_TRIGGER:
        log.critical("依設定立即休眠")
        time.sleep(3)  # 讓警告先出現，醒來時就會看到
        _run([sys_exe("shutdown.exe"), "/h"])
    return proc


def run(args):
    exit_with_launcher()
    try:
        from watchdog.observers import Observer
    except ImportError:
        msg = "缺少 watchdog 套件，請先執行：pip install watchdog"
        log.error(msg)
        alert("RansomGuard 無法啟動", msg)
        sys.exit(1)

    if IS_WINDOWS and not args.dry_run and not is_admin():
        msg = "需要系統管理員權限才能切斷網路。\n請用「以系統管理員身分執行」啟動，或改用 --dry-run 測試。"
        log.error(msg)
        alert("RansomGuard 無法啟動", msg)
        sys.exit(1)
    if not args.dry_run and not single_instance():
        log.info("已經有監控在執行，這次不再啟動")
        sys.exit(0)

    st = load_state()
    if st.get("triggered_at"):
        alert("RansomGuard 提醒",
              f"上次在 {st['triggered_at']} 偵測到疑似勒索病毒並切斷了網路。\n"
              f"確認電腦安全後，{restore_hint()}。")

    watch_dirs = [Path(p) for p in args.watch] if args.watch else default_watch_dirs()
    watch_dirs = [d for d in watch_dirs if d.is_dir()]
    if not watch_dirs:
        log.error("沒有可監控的資料夾")
        sys.exit(1)
    canaries = plant_canaries(watch_dirs if args.watch else default_canary_dirs())

    stop = threading.Event()

    def on_trigger(reason):
        proc = respond(reason, args.dry_run)
        if not args.dry_run:
            if proc is not None:
                keep_offline(proc)  # 等使用者關掉警告再結束，避免警告視窗跟著程式被關掉
                if proc.returncode != 0:  # 視窗中途出錯：改用一般警告，至少要讓你知道
                    log.error("全螢幕警告異常結束（代碼 %s）", proc.returncode)
                    alert("RansomGuard：偵測到疑似勒索病毒，網路已切斷", reason)
                    time.sleep(60)
            stop.set()

    handler = make_handler(canaries, on_trigger, args.dry_run)

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
    restarts = 0

    log.info("RansomGuard %s 開始監控%s：%s", VERSION, "（測試模式）" if args.dry_run else "",
             "; ".join(str(d) for d in watch_dirs))
    log.info("誘餌檔：%s", "; ".join(str(p) for p in canaries))
    try:
        last = time.time()
        while not stop.wait(1):
            if time.time() - last < CHECK_INTERVAL:
                continue
            last = time.time()
            periodic_check(handler, canaries)
            # 監控元件意外停止（例如被監控的資料夾暫時消失）時自動重啟，最多 10 次
            if restarts < 10 and not observer.is_alive():
                restarts += 1
                log.error("檔案監控意外停止，重新啟動（第 %d 次）", restarts)
                observer = start_observer()
            if restarts < 10 and procmon is not None and not procmon.alive():
                restarts += 1
                log.error("程序監控意外停止，重新啟動（第 %d 次）", restarts)
                procmon.start()
    except KeyboardInterrupt:
        log.info("使用者中止")
    finally:
        if procmon is not None:
            procmon.stop()
        observer.stop()
        observer.join()
        log.info("監控結束")


def main():
    fix_console_encoding()
    ap = argparse.ArgumentParser(description="偵測勒索病毒行為並自動斷網")
    ap.add_argument("--version", action="version", version=f"RansomGuard {VERSION}")
    ap.add_argument("--monitor", action="store_true", help="開始監控（.exe 不加參數會開啟控制台）")
    ap.add_argument("--gui", action="store_true", help="開啟控制台")
    ap.add_argument("--dry-run", action="store_true", help="測試模式，不會真的斷網")
    ap.add_argument("--restore", action="store_true", help="恢復網路，並重新開啟背景監控")
    ap.add_argument("--install", action="store_true", help="安裝／更新背景監控並開始監控")
    ap.add_argument("--watch", action="append", metavar="DIR", help="自訂監控資料夾（可重複）")
    ap.add_argument("--test-alert", action="store_true", help="只顯示全螢幕警告看看樣子，不偵測也不斷網")
    args = ap.parse_args()
    setup_logging()
    if args.test_alert:
        fullscreen_alert("這是警告畫面的預覽（--test-alert），沒有偵測到任何東西", "test", wait=True)
    elif args.restore:
        restore_network(log.info)
    elif args.install:
        if IS_WINDOWS and not is_admin():
            log.error("需要以系統管理員身分執行才能安裝")
            sys.exit(1)
        try:
            ok = install(log.info)
        except Exception:
            log.exception("安裝失敗")
            ok = False
        sys.exit(0 if ok else 1)
    elif args.gui or (FROZEN and not (args.monitor or args.dry_run or args.watch)):
        gui()
    else:
        run(args)


if __name__ == "__main__":
    main()
