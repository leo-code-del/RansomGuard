"""Destructive commands (deleting restore points, disabling recovery, clearing logs...) and the
process monitor that ends them as they start."""
import base64
import os
import re
import signal
import subprocess
import threading
from collections import deque

from . import config, response, winapi
from .config import log, tr


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
            winapi.ps_encoded_args(PROC_PS1, "-NonInteractive"),
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            creationflags=winapi.CREATE_NO_WINDOW)
        winapi.kill_with_me(self.proc)
        threading.Thread(target=self._read, args=(self.proc,), daemon=True).start()

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def stop(self):
        proc = self.proc
        if proc is not None and proc.poll() is None:
            proc.kill()
            try:
                proc.wait(5)  # reaped, so its handle doesn't stay open
            except subprocess.TimeoutExpired:
                pass

    def _read(self, proc):
        try:
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
        finally:
            # the PowerShell ended (or was stopped): let go of its pipe and process handle. The monitor restarts a
            # dead one up to 10 times an hour, and each would otherwise leave both open.
            if proc.stdout is not None:
                proc.stdout.close()
            try:
                proc.wait(5)
            except subprocess.TimeoutExpired:
                pass

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
        if config.PAUSE_ON_TRIGGER:
            early = response.pause_ancestors(ppid, dry_run=not self.kill)
            response.record_paused(early)  # right away: after a first trigger no respond() follows to record them
            response._early_paused.extend(early)
        log.critical(tr("可疑指令（%s）%s PID %s，父程序 PID %s，%s：%s",
                        "Suspicious command (%s) %s PID %s, parent PID %s, %s: %s"),
                     what, name, pid, ppid, result, cmdline)
        self.on_hit(tr(f"有程序在{what}：{name}（PID {pid}，{result}）{cmdline[:120]}",
                       f"A process is {what}: {name} (PID {pid}, {result}) {cmdline[:120]}"))
