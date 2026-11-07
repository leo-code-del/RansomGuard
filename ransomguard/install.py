"""The background monitor's scheduled task, installing, uninstalling and the health check."""
import ctypes
import logging
import os
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

from . import canary, config, filetrace, gui, processes, storage, updates, winapi
from .config import log, tr
from .winapi import norm


UPDATED_TO = None  # version install() just downloaded from GitHub, if any


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
        return winapi._ps(f"(Get-ScheduledTask -TaskName {winapi._ps_quote(config.TASK_NAME)} "
                          "-ErrorAction SilentlyContinue).State")[1]
    except Exception:
        return ""


def stop_monitor():
    winapi._ps(f"Stop-ScheduledTask -TaskName {winapi._ps_quote(config.TASK_NAME)} -ErrorAction SilentlyContinue")
    # the encoded opening line of PROC_PS1, the same in every version, so older monitors' scripts match too
    proc_enc = winapi.ps_encoded_args(processes.PROC_PS1)[-1][:120]
    winapi._ps(_KILL_PS1.replace("__ME__", f"{os.getpid()},{os.getppid()}")
               .replace("__PROC__", proc_enc))
    filetrace.stop_trace_session()  # an ended monitor leaves its file trace session to Windows
    log.info(tr("已停止背景監控", "Background monitoring stopped"))


# The scheduled task also starts the monitor every minute when it isn't running (ransomware with administrator
# rights often ends security programs first); while it runs, Task Scheduler starts no second one. A stop the user
# asked for is written down, in the folder only administrators can change, and holds until Windows restarts; the
# repeating trigger is taken off meanwhile, since each start would unpack the program (12 MB) just to exit again.
# The monitor puts it back when it starts.
MONITOR_RESTART_MINUTES = 1


def _set_restart_trigger(on: bool) -> bool:
    """Keep the task's sign-in trigger, and add (on) or drop the one that starts the monitor again every
    MONITOR_RESTART_MINUTES. Returns whether it worked."""
    task = winapi._ps_quote(config.TASK_NAME)
    add = ("$r = New-ScheduledTaskTrigger -Once -At (Get-Date) "
           f"-RepetitionInterval (New-TimeSpan -Minutes {MONITOR_RESTART_MINUTES}); "
           "$r.Repetition.StopAtDurationEnd = $false; $keep += $r; ") if on else ""
    rc, _, err = winapi._ps(
        f"$t = Get-ScheduledTask -TaskName {task} -ErrorAction Stop; "
        "$keep = @($t.Triggers | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_TaskLogonTrigger' }); "
        f"{add}Set-ScheduledTask -TaskName {task} -Trigger $keep -ErrorAction Stop | Out-Null")
    if rc != 0:
        log.warning(tr("無法調整排程工作的自動重啟設定：%s", "Could not change the scheduled task's restart trigger: %s"),
                    err[:200])
    return rc == 0


def restart_interval() -> str:
    """How often the scheduled task starts a monitor that isn't running, as Task Scheduler says it ("PT1M");
    "" if it doesn't (no repeating trigger, or no task)."""
    rc, out, _ = winapi._ps(f"@((Get-ScheduledTask -TaskName {winapi._ps_quote(config.TASK_NAME)} -ErrorAction Stop)"
                            ".Triggers | ForEach-Object { $_.Repetition.Interval } | Where-Object { $_ })[0]")
    return out.strip() if rc == 0 else ""


def ensure_restart_trigger():
    """When the monitor starts: put the repeating trigger back after a stop until restart, or bring an older
    install's interval (5 minutes) to MONITOR_RESTART_MINUTES."""
    if restart_interval() != f"PT{MONITOR_RESTART_MINUTES}M" and _set_restart_trigger(True):
        log.info(tr("排程工作會在監控被結束後 %d 分鐘內重新啟動它", "The scheduled task starts the monitor again within "
                    "%d minute(s) if it is ended"), MONITOR_RESTART_MINUTES)


def stop_monitor_until_restart():
    """The control panel's "Stop monitoring until restart" (under "Pause or stop monitoring")."""
    d = storage.state_dir()
    d.mkdir(parents=True, exist_ok=True)
    (d / "monitor_stopped").write_text(str(winapi.boot_time()), encoding="utf-8")
    _set_restart_trigger(False)  # written down first: the stop holds even if this fails
    stop_monitor()


def stopped_by_user() -> bool:
    """The user stopped monitoring since Windows last started."""
    try:
        stopped_boot = float((storage.state_dir() / "monitor_stopped").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return abs(stopped_boot - winapi.boot_time()) < 120


def start_monitor() -> bool:
    try:
        (storage.state_dir() / "monitor_stopped").unlink(missing_ok=True)
    except OSError:
        pass
    winapi._ps(f"Start-ScheduledTask -TaskName {winapi._ps_quote(config.TASK_NAME)} -ErrorAction Stop")
    time.sleep(5)  # a failed start (e.g. a missing package) exits within a few seconds
    return task_state() == "Running"


def launcher():
    """(executable, arguments) used to run this program."""
    if config.FROZEN:
        return str(config.INSTALL_EXE), ""
    pyw = Path(sys.executable).with_name("pythonw.exe")
    # -E ignores PYTHON* environment variables; -P doesn't load modules from the script folder (no fake json.py)
    flags = "-E -P" if sys.version_info >= (3, 11) else "-E"
    return str(pyw if pyw.exists() else sys.executable), f'{flags} "{config.SCRIPT}"'


def desktop_lnk() -> Path:
    return winapi._known_folder("Desktop") / "RansomGuard.lnk"


def restore_hint() -> str:
    button = tr("「恢復網路並重新開啟監控」", "\"Restore network and restart monitoring\"")
    if desktop_lnk().exists():
        return tr(f"開啟桌面上的「RansomGuard」，按{button}",
                  f"open \"RansomGuard\" on the desktop and click {button}")
    if config.FROZEN:
        return tr(f"執行 {sys.executable}，按{button}", f"run {sys.executable} and click {button}")
    bat = config.ROOT / "restore_network.bat"
    return tr(f"雙擊 {bat} 恢復網路", f"double-click {bat} to restore the network")


def cleanup_old_files():
    """Remove what older versions left behind: exes replaced by an update (RansomGuard.old-*.exe)
    and the alert files very early versions wrote to the app folder."""
    for p in [*config.INSTALL_DIR.glob("RansomGuard.old-*.exe"), config.app_dir() / "alert.json", config.app_dir() / "alert.ps1"]:
        try:
            p.unlink(missing_ok=True)
        except OSError:  # still running (e.g. an open control panel); tried again next time
            pass


def replace_install_exe(write):
    """Put a new INSTALL_EXE in place with write(). A running exe can't be overwritten but can be
    renamed, so the old one is moved aside first (and put back if writing fails)."""
    config.INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    old = None
    if config.INSTALL_EXE.exists():
        old = config.INSTALL_DIR / f"RansomGuard.old-{uuid.uuid4().hex[:8]}.exe"
        for i in range(10):
            try:
                os.replace(config.INSTALL_EXE, old)
                break
            except PermissionError:  # briefly locked, e.g. antivirus scanning the exe
                if i == 9:
                    raise
                time.sleep(1)
    try:
        write()
    except Exception:
        if old is not None:
            os.replace(old, config.INSTALL_EXE)
        raise
    if old is not None:
        try:
            old.unlink()
        except OSError:  # still running (e.g. this control panel): Windows deletes it at the next restart
            winapi.delete_at_restart(old)


def spawn_installed(*args):
    """Start the installed exe as a fresh program. A one-file PyInstaller exe started by another one
    inherits its environment and would reuse the starter's unpacked files (%TEMP%\\_MEI...), which are
    deleted when the starter exits; it then fails as soon as it loads another module."""
    return subprocess.Popen([str(config.INSTALL_EXE), *args], cwd=str(config.INSTALL_DIR), env=winapi.fresh_env())


def install(report=print, update=True) -> bool:
    """Put this exe into Program Files (or, with update, the newer release from GitHub if there is one),
    create a scheduled task that runs elevated at sign-in and a desktop shortcut, then start monitoring.
    update=False keeps the version that is running, for users who want to stay on it.
    If anything fails, the monitoring that was installed before is started again."""
    report(tr("停止舊的監控...", "Stopping the old monitor..."))
    stop_monitor()
    try:
        return _install(report, update)
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
var stateDir = (test && env("RG_HEALTH_STATE") != "") ? env("RG_HEALTH_STATE") : env("ProgramData") + "\\RansomGuard";

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
    if (/"triggered_at"\s*:\s*"[^"]/.test(readText(stateDir + "\\state.json"))) return "";
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
              "要開啟下載頁面重新安裝嗎？\n（下載 RansomGuard.exe 後執行，按「安裝並開始監控」）"
            : "RansomGuard's background protection is gone from this computer. Most often Microsoft Defender " +
              "removed it by mistake.\n\nOpen the download page to install it again?\n(Download RansomGuard.exe, " +
              "run it and click \"Install and start monitoring\".)") :
        (zh ? "RansomGuard 的背景監控沒有在執行，這台電腦目前沒有勒索病毒防護。\n\n" +
              "要開啟控制台嗎？（按「安裝並開始監控」就會重新開始）"
            : "RansomGuard's background monitoring is not running, so this computer has no ransomware " +
              "protection right now.\n\nOpen the control panel? (Click \"Install and start monitoring\" " +
              "to start it again.)");
    // 4 = Yes/No, 48 = warning icon, 4096 = stays on top; 6 = Yes
    if (sh.Popup(msg, 0, "RansomGuard", 4 + 48 + 4096) == 6) {
        var lnk = sh.SpecialFolders("Desktop") + "\\RansomGuard.lnk";
        sh.Run(problem == "stopped" && fso.FileExists(lnk) ? "\"" + lnk + "\"" : RELEASES);
    }
}
'''.replace("__TASK__", config.TASK_NAME)


def install_health_check(report):
    """Save health_check.js next to the exe (only administrators can change it there) and run it at sign-in
    (after the monitor had time to start) and every day."""
    js = config.INSTALL_DIR / "health_check.js"
    config.INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    js.write_text(HEALTH_JS, encoding="utf-16")
    rc, _, err = winapi._ps(
        r'$u = "$env:USERDOMAIN\$env:USERNAME"; '
        f"$a = New-ScheduledTaskAction -Execute {winapi._ps_quote(winapi.sys_exe('wscript.exe'))} "
        f"-Argument {winapi._ps_quote(f'//B //Nologo \"{js}\"')}; "
        "$t1 = New-ScheduledTaskTrigger -AtLogOn -User $u; $t1.Delay = 'PT5M'; "
        "$t2 = New-ScheduledTaskTrigger -Daily -At '12:00'; "
        "$p = New-ScheduledTaskPrincipal -UserId $u -LogonType Interactive -RunLevel Limited; "
        "$s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable "
        "-ExecutionTimeLimit (New-TimeSpan -Hours 1) -MultipleInstances IgnoreNew; "
        f"Register-ScheduledTask -TaskName {winapi._ps_quote(HEALTH_TASK)} -Action $a -Trigger $t1, $t2 -Principal $p "
        f"-Settings $s -Description {winapi._ps_quote(tr('背景防護不見或沒有執行時提醒', 'Warns when background protection is gone or not running'))} "  # noqa: E501
        "-Force -ErrorAction Stop | Out-Null")
    if rc == 0:
        report(tr("已建立防護狀態檢查（登入後與每天提醒防護是否還在）",
                  "Health check created (warns at sign-in and daily if protection is gone)"))
    else:  # not worth failing the install over
        log.warning(tr("建立防護狀態檢查失敗：%s", "Could not create the health check: %s"), err)
        report(tr(f"  無法建立防護狀態檢查：{err}", f"  Could not create the health check: {err}"))


def _install(report, update=True) -> bool:
    global UPDATED_TO
    storage.secure_state_dir()
    UPDATED_TO = updates.fetch_update(report) if config.FROZEN and update else None
    if update and not config.FROZEN:
        report(tr("從原始碼執行時，請用 git pull 更新程式碼。", "Running from source: update the code with git pull."))
    if config.FROZEN and UPDATED_TO is None and norm(sys.executable) != norm(config.INSTALL_EXE):
        # a program that runs as administrator must live in a folder only administrators can change
        report(tr(f"複製程式到 {config.INSTALL_DIR} ...", f"Copying the program to {config.INSTALL_DIR} ..."))
        replace_install_exe(lambda: shutil.copy2(sys.executable, str(config.INSTALL_EXE)))
    cleanup_old_files()
    exe, args = launcher()
    workdir = str(config.INSTALL_DIR if config.FROZEN else config.ROOT)
    report(tr("建立登入時自動執行的排程工作...", "Creating a scheduled task that runs at sign-in..."))
    rc, _, err = winapi._ps(
        r'$u = "$env:USERDOMAIN\$env:USERNAME"; '
        f"$a = New-ScheduledTaskAction -Execute {winapi._ps_quote(exe)} "
        f"-Argument {winapi._ps_quote((args + ' --monitor').strip())} -WorkingDirectory {winapi._ps_quote(workdir)}; "
        "$t = New-ScheduledTaskTrigger -AtLogOn -User $u; "
        # also every minute: starts the monitor again if something ended it (MultipleInstances IgnoreNew
        # leaves a running monitor alone); the repetition never expires
        "$t2 = New-ScheduledTaskTrigger -Once -At (Get-Date) "
        f"-RepetitionInterval (New-TimeSpan -Minutes {MONITOR_RESTART_MINUTES}); "
        "$t2.Repetition.StopAtDurationEnd = $false; "  # never end the running monitor because of this trigger
        "$p = New-ScheduledTaskPrincipal -UserId $u -LogonType Interactive -RunLevel Highest; "
        "$s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries "
        "-ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew "
        "-RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1); "
        f"Register-ScheduledTask -TaskName {winapi._ps_quote(config.TASK_NAME)} -Action $a -Trigger $t, $t2 "
        f"-Principal $p -Settings $s "
        f"-Description {winapi._ps_quote(tr('偵測勒索病毒行為並自動切斷網路', 'Detects ransomware behavior and cuts off the network automatically'))} "  # noqa: E501
        "-Force -ErrorAction Stop | Out-Null")
    if rc != 0:
        raise RuntimeError(tr(f"建立排程工作失敗：{err}", f"Failed to create the scheduled task: {err}"))
    install_health_check(report)
    report(tr("建立桌面捷徑「RansomGuard」...", "Creating the \"RansomGuard\" desktop shortcut..."))
    # the shortcut names an icon file of its own, so it never shows a stale icon cached for the exe path
    icon = gui.icon_file()
    if config.FROZEN and icon.endswith(".ico"):
        shutil.copy2(icon, str(config.INSTALL_DIR / "icon.ico"))
        icon = str(config.INSTALL_DIR / "icon.ico")
    shortcut_args = (args + " --gui").strip() if args else ""
    winapi._ps(f"$s = (New-Object -ComObject WScript.Shell).CreateShortcut({winapi._ps_quote(str(desktop_lnk()))}); "
               f"$s.TargetPath = {winapi._ps_quote(exe)}; $s.Arguments = {winapi._ps_quote(shortcut_args)}; "
               f"$s.WorkingDirectory = {winapi._ps_quote(workdir)}; $s.IconLocation = {winapi._ps_quote(icon + ',0')}; "
               f"$s.Description = {winapi._ps_quote(tr('RansomGuard 控制台', 'RansomGuard control panel'))}; $s.Save()")
    # Windows caches icons per file path, and the installed path never changes: tell the shell the exe
    # changed and refresh the cache, so the shortcut doesn't keep showing an older version's icon
    if config.IS_WINDOWS:
        ctypes.windll.shell32.SHChangeNotify(0x2000, 0x0005, str(config.INSTALL_EXE), None)  # UPDATEITEM, PATHW
        ctypes.windll.shell32.SHChangeNotify(0x08000000, 0x1000, None, None)  # ASSOCCHANGED, FLUSH
        winapi._run([winapi.sys_exe("ie4uinit.exe"), "-show"])
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
    _, _, err = winapi._ps(f"Unregister-ScheduledTask -TaskName {winapi._ps_quote(config.TASK_NAME)} "
                           "-Confirm:$false -ErrorAction SilentlyContinue")
    if task_state():
        report(tr(f"刪除排程工作失敗：{err}", f"Failed to delete the scheduled task: {err}"))
        return False
    winapi._ps(f"Unregister-ScheduledTask -TaskName {winapi._ps_quote(HEALTH_TASK)} "
               "-Confirm:$false -ErrorAction SilentlyContinue")
    report(tr("已刪除排程工作", "Scheduled task deleted"))
    desktop_lnk().unlink(missing_ok=True)
    canary.remove_canaries()
    report(tr("已刪除桌面捷徑與誘餌檔", "Desktop shortcut and canary files deleted"))
    if config.INSTALL_DIR.is_dir():
        # the exe, its icon and exes left by updates; files still running are deleted at the next restart
        later = []
        for p in config.INSTALL_DIR.iterdir():
            try:
                p.unlink()
            except OSError:
                later.append(p)
        try:
            if later:
                raise OSError
            config.INSTALL_DIR.rmdir()
            report(tr(f"已刪除 {config.INSTALL_DIR}", f"Deleted {config.INSTALL_DIR}"))
        except OSError:
            for p in [*later, config.INSTALL_DIR]:
                winapi.delete_at_restart(p)
            report(tr(f"{config.INSTALL_DIR} 會在下次開機時刪除", f"{config.INSTALL_DIR} will be deleted at the next restart"))
    log.info(tr("已解除安裝背景監控", "Background monitoring uninstalled"))
    remove_app_data(report)
    report(tr("解除安裝完成。", "Uninstall complete."))
    return True


def remove_app_data(report):
    """Delete the log, state and settings (%LOCALAPPDATA%\\RansomGuard): nothing of the user is left behind."""
    for h in [h for h in log.handlers if isinstance(h, logging.FileHandler)]:
        log.removeHandler(h)  # this program's own handle on guard.log would keep it from being deleted
        h.close()
    folder = config.app_dir()
    shutil.rmtree(folder, ignore_errors=True)
    report(tr(f"已刪除紀錄檔與設定（{folder}）", f"Deleted the log and settings ({folder})") if not folder.exists() else
           tr(f"  有些檔案仍在使用中，沒有刪除：{folder}", f"  Some files are still in use and were not deleted: {folder}"))
    state = storage.state_dir()
    if os.path.lexists(state) and norm(state) != norm(folder):
        try:
            storage._remove_entry(state)  # the network state, canary record and watched folders
            report(tr(f"已刪除狀態資料（{state}）", f"Deleted the state data ({state})"))
        except OSError as ex:
            report(tr(f"  無法刪除 {state}：{ex}", f"  Could not delete {state}: {ex}"))
