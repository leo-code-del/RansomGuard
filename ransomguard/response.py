"""What happens on a trigger: pausing the programs that write the most (or started a destructive
command) and the full-screen warning."""
import base64
import ctypes
import json
import os
import subprocess
import threading
import time

from . import config, defender, install, network, storage, winapi
from .config import log, tr
from .winapi import norm


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


def fullscreen_alert(reason: str, status: str, wait: bool = False, paused=(), files=()):
    """Full-screen warning. status: cut (network cut) / partial (cut may be incomplete) / test.
    paused: the programs pause_writers() found; files: the files that looked encrypted."""
    log.warning(tr("[全螢幕警告] %s（%s）", "[Full-screen warning] %s (%s)"), reason, status)
    if not config.IS_WINDOWS:
        return None
    try:
        reason = reason if len(reason) <= 160 else reason[:157] + "..."
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        detail = tr(f"偵測時間：{now}\n原因：{reason}", f"Detected at: {now}\nReason: {reason}")
        if files:
            names = tr("、", ", ").join(os.path.basename(f) for f in list(files)[-3:])
            more = tr(f" 等 {len(files)} 個", f" and {len(files) - 3} more") if len(files) > 3 else ""
            detail += "\n" + tr(f"像被加密的檔案：{names}{more}", f"Files that look encrypted: {names}{more}")
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
                     tr(f"如果確認是誤判（例如是你自己動到誘餌檔）：關閉這個視窗後，{install.restore_hint()}。",
                        "If this is a false alarm (e.g. you touched a canary file yourself): "
                        f"close this window, then {install.restore_hint()}.")),
            "ok": tr("我知道了（關閉警告）", "I understand (close warning)"),
            "shutdown": tr("立即強制關機", "Force shut down now"),
            "confirm": tr("確定要立即強制關機嗎？\n尚未儲存的工作會遺失。",
                          "Force the computer to shut down now?\nUnsaved work will be lost."),
        }}, ensure_ascii=False)
        env = dict(os.environ, RG_ALERT_INFO=base64.b64encode(info.encode("utf-8")).decode("ascii"))
        proc = subprocess.Popen(
            winapi.ps_encoded_args(ALERT_PS1, "-STA", "-WindowStyle", "Hidden"),
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env,
            creationflags=winapi.CREATE_NO_WINDOW)
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
        winapi.alert(tr("RansomGuard：偵測到疑似勒索病毒", "RansomGuard: possible ransomware detected"),
                     tr(f"{reason}\n\n狀態：{status}", f"{reason}\n\nStatus: {status}"))
        return None


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


def write_counters() -> dict:
    """{pid: (name, write operations, bytes written)} of every readable process except this program and its
    children."""
    k32 = winapi.kernel32()
    me, out, io = os.getpid(), {}, (ctypes.c_uint64 * 6)()
    for pid, ppid, name in winapi.process_list():
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
    k32 = winapi.kernel32()
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
        path = winapi.process_path(pid)
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
        st = storage.load_state()
        known = {p.get("pid") for p in st.get("paused", [])}
        st["paused"] = st.get("paused", []) + [p for p in new if p["pid"] not in known]
        storage.save_state(st)
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
        parents = {pid: (parent, name) for pid, parent, name in winapi.process_list()}
    except Exception:
        log.exception(tr("讀取程序清單失敗", "Failed to list processes"))
        return []
    found, pid, below = [], ppid, None
    for _ in range(ANCESTOR_LEVELS):
        if pid in (0, 4, os.getpid()) or pid not in parents:
            break
        started = winapi.process_started(pid)
        if below is not None and (started is None or started >= below):
            break
        name, path = parents[pid][1], winapi.process_path(pid)
        if trusted_process(name, path):
            break
        p = _pause(pid, name, path, dry_run)
        log.critical(tr("下達危險指令的程式 %s（PID %s），%s：%s",
                        "Program that started the destructive command %s (PID %s), %s: %s"),
                     name, pid, p["result"], path)
        found.append(p)
        pid, below = parents[pid][0], started
    return found


def record_incident(reason: str, files):
    """Keep the detection report (why, which files) until the network is restored, for the control panel. Never
    raises: nothing may stop the network from being cut."""
    try:
        st = storage.load_state()
        st["incident"] = {"reason": reason, "files": list(files)}
        storage.save_state(storage.clean_state(st))
    except OSError:
        log.exception(tr("無法記錄偵測報告", "Could not record the detection report"))
    if files:
        log.critical(tr("被判定像被加密的檔案（%d 個）：%s", "Files that looked encrypted (%d): %s"), len(files),
                     "; ".join(files))


def respond(reason: str, dry_run: bool, files=()):
    """Handle a trigger. files: the files that were counted (the evidence). Returns the full-screen warning process
    (may be None)."""
    config.init_lang()  # use the language most recently chosen in the control panel (the monitor may predate the change)
    log.critical(tr("偵測到疑似勒索病毒行為：%s", "Possible ransomware behavior detected: %s"), reason)
    # pause the encrypting program before anything else: every second it keeps running costs files
    found = _early_paused[:]  # the programs behind a destructive command, paused already
    _early_paused.clear()
    if config.PAUSE_ON_TRIGGER and config.IS_WINDOWS:
        seen = {p["pid"] for p in found}
        found += [p for p in pause_writers(dry_run) if p["pid"] not in seen]
    if dry_run:
        log.warning(tr("[測試模式] 正式模式下，此時會切斷網路",
                       "[Test mode] In normal mode the network would be cut off now"))
        return fullscreen_alert(reason, "test", paused=found, files=files)
    record_paused(found)
    record_incident(reason, files)
    if config.DEFENDER_SCAN_ON_TRIGGER and config.IS_WINDOWS:
        threading.Thread(target=defender.ask_defender, args=([p["path"] for p in found if p["path"]],),
                         daemon=True).start()
    ok = network.disconnect_network()
    proc = fullscreen_alert(reason, "cut" if ok else "partial", paused=found, files=files)
    if config.HIBERNATE_ON_TRIGGER:
        log.critical(tr("依設定立即休眠", "Hibernating now, as configured"))
        time.sleep(3)  # let the warning appear first, so it is there after waking up
        winapi._run([winapi.sys_exe("shutdown.exe"), "/h"])
    return proc
