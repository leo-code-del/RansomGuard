"""Microsoft Defender scans: of paused programs, of new downloads, and before resuming programs."""
import os
import subprocess
import threading
import time
from collections import deque
from pathlib import Path

from . import config, response, winapi
from .config import log, tr
from .winapi import norm


MPCMDRUN = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Windows Defender" / "MpCmdRun.exe"


def defender_scan(path=None, timeout=600):
    """Scan one file (or run a quick scan) with Microsoft Defender, which removes what it finds.
    Returns MpCmdRun's exit code (0 = no threats, 2 = threat found), or None if it could not scan."""
    if not MPCMDRUN.is_file():
        return None
    args = ([str(MPCMDRUN), "-Scan", "-ScanType", "3", "-File", path] if path else
            [str(MPCMDRUN), "-Scan", "-ScanType", "1"])
    try:
        r = subprocess.run(args, capture_output=True, timeout=timeout, creationflags=winapi.CREATE_NO_WINDOW)
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
        now = winapi.process_path(pid) if isinstance(pid, int) else ""
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
        ok = response.set_paused(pid, False)
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
        self.roots = [(norm(winapi._known_folder("Downloads")), True), (norm(winapi._known_folder("Desktop")), False)]
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
        config.init_lang()  # the language most recently chosen in the control panel (the monitor may predate it)
        winapi.alert(tr("RansomGuard：Defender 發現威脅", "RansomGuard: Defender found a threat"),
                     tr(f"新檔案含有威脅：\n{path}\n\nMicrosoft Defender 正在處理（通常會隔離或刪除）。請不要開啟這個檔案。",
                        f"A new file contains a threat:\n{path}\n\nMicrosoft Defender is handling it (it usually "
                        "quarantines or deletes it). Do not open this file."))
