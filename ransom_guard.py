#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RansomGuard — 偵測疑似勒索病毒的加密行為，觸發時自動切斷網路。

偵測方式（任一成立就觸發）：
  1. 誘餌檔（canary）被修改、移動或刪除
  2. 短時間內多個檔案「壞掉」：.docx/.pdf/.jpg 等檔頭不對了，
     或純文字檔（.txt/.py/.cpp…）變成高亂度內容（像被加密）
  3. 短時間內大量檔案被改成陌生副檔名（例如 報告.docx → 報告.docx.locked）

觸發後：停用所有網路介面卡 → 寫入紀錄 → 全螢幕紅色警告（所有螢幕、閃爍、警示音）
        （可選：HIBERNATE_ON_TRIGGER = True 會直接休眠，讓加密停下來）

用法（Windows，正式模式需以系統管理員身分執行）：
  python ransom_guard.py             正式監控
  python ransom_guard.py --dry-run   測試模式：只記錄與跳窗，不會真的斷網
  python ransom_guard.py --restore   把本程式停用的網路卡重新啟用
  python ransom_guard.py --test-alert  預覽全螢幕警告（不偵測、不斷網）
  python ransom_guard.py --watch D:\\資料 --watch E:\\備份   自訂監控資料夾

需要套件：pip install watchdog
紀錄檔位置：%LOCALAPPDATA%\\RansomGuard\\guard.log
"""

import argparse
import ctypes
import json
import logging
import math
import os
import subprocess
import sys
import threading
import time
import uuid
from collections import Counter, deque
from logging.handlers import RotatingFileHandler
from pathlib import Path

IS_WINDOWS = os.name == "nt"

# =============== 可調整的設定 ===============
WINDOW_SEC = 30              # 統計時間窗（秒）
BROKEN_THRESHOLD = 8         # 時間窗內「壞掉」的檔案數達到此值就觸發
EXT_CHANGE_THRESHOLD = 10    # 時間窗內被改成陌生副檔名的檔案數達到此值就觸發
ENTROPY_LIMIT = 7.5          # 純文字檔亂度上限（bits/byte；加密後約 7.9–8.0）
ENTROPY_MIN_SIZE = 4096      # 小於此大小的檔案不做亂度判斷（樣本太少不準）
HIBERNATE_ON_TRIGGER = False # True：斷網後立刻休眠，阻止加密繼續進行
# ============================================

CANARY_NAMES = ["!!!_canary_勿刪.docx", "!!!_canary_勿刪.xlsx", "zzz_canary_勿刪.docx"]
CANARY_BYTES = ((
    "這是防勒索病毒的誘餌檔（RansomGuard canary），請勿開啟修改、移動或刪除。\n"
    "This is a ransomware canary file. Do not modify, move or delete it.\n"
) * 200).encode("utf-8")

# 常見檔案格式的檔頭（被加密後檔頭幾乎一定會壞）
_OLE = [b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"]
_ZIP = [b"PK\x03\x04"]
MAGIC = {
    ".docx": _ZIP, ".xlsx": _ZIP, ".pptx": _ZIP, ".zip": _ZIP,
    ".odt": _ZIP, ".ods": _ZIP, ".odp": _ZIP, ".epub": _ZIP,
    ".doc": _OLE, ".xls": _OLE, ".ppt": _OLE,
    ".pdf": [b"%PDF"],
    ".jpg": [b"\xff\xd8\xff"], ".jpeg": [b"\xff\xd8\xff"],
    ".png": [b"\x89PNG\r\n\x1a\n"],
    ".gif": [b"GIF87a", b"GIF89a"],
    ".rar": [b"Rar!\x1a\x07"],
    ".7z": [b"7z\xbc\xaf\x27\x1c"],
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

log = logging.getLogger("RansomGuard")


# ---------------- 基本工具 ----------------
def app_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") if IS_WINDOWS else None
    d = Path(base) / "RansomGuard" if base else Path.home() / ".ransom_guard"
    d.mkdir(parents=True, exist_ok=True)
    return d


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
        return os.geteuid() == 0
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


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
ALERT_PS1 = r'''
param([string]$InfoFile)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

$info = Get-Content -LiteralPath $InfoFile -Raw -Encoding UTF8 | ConvertFrom-Json
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
    $hint = "如果確認是誤判（例如是你自己動到誘餌檔）：關閉這個視窗後，雙擊 $($info.restore) 恢復網路。"
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
        d = app_dir()
        ps1 = d / "alert.ps1"
        ps1.write_text(ALERT_PS1, encoding="utf-8-sig")  # 有 BOM，Windows PowerShell 才讀得懂中文
        info = d / "alert.json"
        info.write_text(json.dumps({
            "status": status,
            "reason": reason if len(reason) <= 160 else reason[:157] + "...",
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "restore": str(Path(os.path.abspath(__file__)).parent / "恢復網路.bat"),
        }, ensure_ascii=False), encoding="utf-8")
        proc = subprocess.Popen(
            ["powershell", "-NoProfile", "-STA", "-ExecutionPolicy", "Bypass",
             "-WindowStyle", "Hidden", "-File", str(ps1), "-InfoFile", str(info)],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            creationflags=CREATE_NO_WINDOW)
        try:
            proc.wait(timeout=4)  # 4 秒內就結束 = 視窗沒開起來
            err = proc.stderr.read().decode("utf-8", "replace").strip()
            raise RuntimeError(f"全螢幕警告啟動失敗（代碼 {proc.returncode}）：{err[:300]}")
        except subprocess.TimeoutExpired:
            pass  # 還在執行 = 警告視窗正常顯示中
        if wait:
            proc.wait()
        return proc
    except Exception as ex:
        log.error("%s；改用一般警告視窗", ex)
        alert("RansomGuard：偵測到疑似勒索病毒", f"{reason}\n\n狀態：{status}")
        return None


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
                                                          ctypes.byref(p)) == 0:
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


# ---------------- 判斷檔案是否「壞掉」 ----------------
def broken_reason(path: str):
    ext = Path(path).suffix.lower()
    if ext not in MAGIC and ext not in TEXT_EXTS:
        return None
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            data = f.read(65536)
    except OSError:
        return None
    if len(data) < 8:  # 空檔或寫入中
        return None
    if ext in MAGIC:
        ok = (b"%PDF" in data[:1024]) if ext == ".pdf" else \
             any(data.startswith(m) for m in MAGIC[ext])
        return None if ok else "檔頭不符"
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


# ---------------- 事件處理 ----------------
def make_handler(canaries, on_trigger, dry_run):
    from watchdog.events import FileSystemEventHandler

    class Guard(FileSystemEventHandler):
        def __init__(self):
            self.canaries = {norm(p) for p in canaries}
            self.broken = deque()   # (time, path)
            self.extchg = deque()
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
            on_trigger(reason)

        def _count(self, q, path, threshold, label):
            now = time.time()
            with self.lock:
                q.append((now, norm(path)))
                while q and now - q[0][0] > WINDOW_SEC:
                    q.popleft()
                n = len({p for _, p in q})
            if n >= threshold:
                self.fire(f"{WINDOW_SEC} 秒內有 {n} 個檔案{label}（例如 {path}）")

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
                            "被改成陌生副檔名")

            # 2. 檔案內容壞掉
            if t in ("created", "modified", "closed", "moved"):
                path = dest if t == "moved" else src
                if ignorable(path):
                    return
                reason = broken_reason(path)
                if reason:
                    log.info("疑似被加密的檔案（%s）：%s", reason, path)
                    self._count(self.broken, path, BROKEN_THRESHOLD, "疑似被加密")

    return Guard()


# ---------------- 網路控制（Windows） ----------------
CREATE_NO_WINDOW = 0x08000000


def _ps(cmd: str, timeout=60):
    full = "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; " + cmd
    r = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
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

    try:
        _, up, _ = _ps("@(Get-NetAdapter | Where-Object {$_.Status -eq 'Up'}).Count")
    except Exception:
        up = "?"
    if up == "0":
        log.critical("已停用所有網路卡：%s", ", ".join(st.get("disabled_adapters", [])))
        return True
    log.error("仍有網路卡在線上（%s），改用備援方式斷線", up)
    _run(["ipconfig", "/release"])
    _run(["netsh", "wlan", "disconnect"])
    return False


def restore_network():
    st = load_state()
    names = st.get("disabled_adapters") or []
    if names:
        arr = ",".join("'" + n.replace("'", "''") + "'" for n in names)
        cmd = f"Enable-NetAdapter -Name @({arr}) -Confirm:$false"
    else:
        cmd = "Get-NetAdapter | Enable-NetAdapter -Confirm:$false"
    rc, _, err = _ps(cmd)
    if rc == 0:
        log.info("已重新啟用網路卡：%s", ", ".join(names) or "全部")
        save_state({})
        print("網路卡已重新啟用。")
    else:
        log.error("重新啟用失敗：%s", err)
        print("重新啟用失敗，請確認是以系統管理員身分執行：", err)


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
        _run(["shutdown", "/h"])
    return proc


def run(args):
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

    st = load_state()
    if st.get("triggered_at"):
        alert("RansomGuard 提醒",
              f"上次在 {st['triggered_at']} 偵測到疑似勒索病毒並切斷了網路。\n"
              "確認電腦安全後，再執行 --restore 恢復網路。")

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
                proc.wait()  # 等使用者關掉警告再結束，避免警告視窗跟著程式被關掉
                if proc.returncode != 0:  # 視窗中途出錯：改用一般警告，至少要讓你知道
                    log.error("全螢幕警告異常結束（代碼 %s）", proc.returncode)
                    alert("RansomGuard：偵測到疑似勒索病毒，網路已切斷", reason)
                    time.sleep(60)
            stop.set()

    handler = make_handler(canaries, on_trigger, args.dry_run)
    observer = Observer()
    for d in watch_dirs:
        observer.schedule(handler, str(d), recursive=True)
    observer.start()

    log.info("開始監控%s：%s", "（測試模式）" if args.dry_run else "",
             "; ".join(str(d) for d in watch_dirs))
    log.info("誘餌檔：%s", "; ".join(str(p) for p in canaries))
    try:
        while not stop.wait(1):
            pass
    except KeyboardInterrupt:
        log.info("使用者中止")
    finally:
        observer.stop()
        observer.join()
        log.info("監控結束")


def main():
    ap = argparse.ArgumentParser(description="偵測勒索病毒行為並自動斷網")
    ap.add_argument("--dry-run", action="store_true", help="測試模式，不會真的斷網")
    ap.add_argument("--restore", action="store_true", help="重新啟用被本程式停用的網路卡")
    ap.add_argument("--watch", action="append", metavar="DIR", help="自訂監控資料夾（可重複）")
    ap.add_argument("--test-alert", action="store_true", help="只顯示全螢幕警告看看樣子，不偵測也不斷網")
    args = ap.parse_args()
    setup_logging()
    if args.test_alert:
        fullscreen_alert("這是警告畫面的預覽（--test-alert），沒有偵測到任何東西", "test", wait=True)
    elif args.restore:
        restore_network()
    else:
        run(args)


if __name__ == "__main__":
    main()
