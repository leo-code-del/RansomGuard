"""The control panel's "Self-check": is protection really working on this computer? It reads the scheduled task,
the log, the canary files and the state folder's permissions (nothing is changed), then runs a drill: simulated
encryption in a temporary folder, watched by this program's detection in test mode (no network cut, no warning,
the real canary record untouched)."""
import os
import re
import shutil
import tempfile
import threading
import time
from pathlib import Path

from . import backup, canary, config, detection, install, storage, winapi
from .config import log, tr


OK, WARN, FAIL = "ok", "warn", "fail"
_START = re.compile(r"RansomGuard (\d+\.\d+\.\d+) (開始監控|started monitoring)[：:]")
_PROCMON = re.compile(r"(程序監控已啟動|Process monitor started).*[（(](?:即時追蹤|real-time trace)[：:] ?(True|False)")
_WRITE_RIGHTS = ("FullControl", "Modify", "Write", "Delete", "ChangePermissions", "TakeOwnership", "CreateFiles",
                 "CreateDirectories", "AppendData")
_ADMINS, _SYSTEM = "S-1-5-32-544", "S-1-5-18"


def _log_lines() -> list:
    """The log, oldest part first (guard.log.3 ... guard.log)."""
    lines = []
    for part in reversed(storage._log_files(config.app_dir() / "guard.log")):
        try:
            lines += part.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            pass
    return lines


def check_task():
    state = install.task_state()
    if state == "Running":
        return OK, tr("背景監控正在執行", "Background monitoring is running")
    if not state:
        return FAIL, tr("背景監控沒有安裝：按「安裝並開始監控」", "Background monitoring is not installed: click "
                        "\"Install and start monitoring\"")
    if install.stopped_by_user():
        return WARN, tr("你停止了背景監控，重新開機後會自動再啟動", "You stopped background monitoring; it starts again "
                        "when Windows restarts")
    return FAIL, tr(f"背景監控沒有在執行（{state}）：按「安裝並開始監控」",
                    f"Background monitoring is not running ({state}): click \"Install and start monitoring\"")


def check_restart_trigger():
    """The scheduled task starts the monitor again within MONITOR_RESTART_MINUTES if something ends it."""
    if not install.task_state() or install.stopped_by_user():
        return []  # not installed, or stopped by the user (reported above)
    minutes, interval = install.MONITOR_RESTART_MINUTES, install.restart_interval()
    if interval == f"PT{minutes}M":
        return [(OK, tr(f"監控被結束時，{minutes} 分鐘內會自動重新啟動",
                        f"If monitoring is ended, it starts again within {minutes} minute(s)"))]
    found = re.fullmatch(r"PT(\d+)M", interval)
    if found:  # an older install's interval; the monitor of this version changes it when it starts
        return [(WARN, tr(f"監控被結束時要 {found.group(1)} 分鐘內才會重新啟動（這個版本是 {minutes} 分鐘）："
                          "按「安裝並開始監控」更新",
                          f"If monitoring is ended, it starts again only within {found.group(1)} minutes (this "
                          f"version: {minutes}): click \"Install and start monitoring\" to update it"))]
    return [(WARN, tr("監控被結束時不會自動重新啟動：按「安裝並開始監控」修正",
                      "If monitoring is ended, it isn't started again: click \"Install and start monitoring\" to fix "
                      "it"))]


def check_monitor_log(lines):
    """The last monitor start in the log: its version, and whether the process monitor started after it."""
    start = last_start(lines)  # (test-mode starts don't match: their line reads "開始監控（測試模式）：")
    if not _START.search(lines[start] if lines else ""):
        return [(WARN, tr("紀錄檔裡找不到背景監控啟動的紀錄（紀錄檔可能剛清除過）",
                          "The log has no record of background monitoring starting (it may have been cleared)"))]
    version = _START.search(lines[start]).group(1)
    out = [(OK, tr(f"背景監控是 v{version}，和控制台相同", f"Background monitoring is v{version}, like the control panel"))
           if version == config.VERSION else
           (WARN, tr(f"背景監控是 v{version}，控制台是 v{config.VERSION}：按「安裝並開始監控」讓兩者一致",
                     f"Background monitoring is v{version}, the control panel v{config.VERSION}: click \"Install and "
                     "start monitoring\" to bring them in line"))]
    trace = next((m.group(2) for m in map(_PROCMON.search, lines[start:]) if m), None)
    if trace is None:
        out.append((FAIL, tr("程序監控沒有啟動：危險指令不會被攔截",
                             "The process monitor didn't start: dangerous commands aren't stopped")))
    elif trace == "True":
        out.append((OK, tr("程序監控正在執行（含即時追蹤）", "The process monitor is running (with real-time trace)")))
    else:
        out.append((WARN, tr("程序監控正在執行，但沒有即時追蹤：很短的程序可能抓不到",
                             "The process monitor is running without real-time trace: very short processes may "
                             "be missed")))
    return out


def last_start(lines) -> int:
    """Where background monitoring last started in the log (0 if the log doesn't say)."""
    return next((i for i in range(len(lines) - 1, -1, -1) if _START.search(lines[i])), 0)


def check_errors(lines):
    """Errors since background monitoring last started (what happened before doesn't matter for now)."""
    errors = [line for line in lines[last_start(lines):] if "[ERROR]" in line]
    if not errors:
        return OK, tr("背景監控這次啟動後沒有錯誤", "No errors since background monitoring started")
    last = errors[-1][:19] + " " + errors[-1].split("] ", 1)[-1][:120]
    return WARN, tr(f"背景監控這次啟動後有 {len(errors)} 個錯誤，最近一個：{last}",
                    f"{len(errors)} error(s) since background monitoring started, the latest: {last}")


def check_canary_files():
    paths = [Path(p) for p in canary.canary_record()]
    if not paths:
        return FAIL, tr("沒有誘餌檔：背景監控啟動時會放好，請確認它有在執行",
                        "No canary files: background monitoring puts them in place when it starts; make sure it runs")
    problems, checked = [], 0
    for p in paths:
        if not p.parent.is_dir():
            continue  # the folder isn't there (a USB drive that is unplugged)
        checked += 1
        try:
            if not canary.canary_intact(p, p.read_bytes()):
                problems.append(tr(f"內容被改過：{p}", f"modified: {p}"))
            elif config.IS_WINDOWS and not os.stat(p).st_file_attributes & 0x2:
                problems.append(tr(f"沒有隱藏：{p}", f"not hidden: {p}"))
        except FileNotFoundError:
            problems.append(tr(f"不見了：{p}", f"missing: {p}"))
        except OSError:
            pass  # locked for a moment (antivirus)
    if problems:
        return FAIL, tr(f"{len(problems)} 個誘餌檔有問題：", f"{len(problems)} canary file(s) have a problem: ") + \
            tr("；", "; ").join(problems[:3])
    return OK, tr(f"{checked} 個誘餌檔都完好、隱藏", f"All {checked} canary files are intact and hidden")


def check_state_permissions():
    """Only SYSTEM and Administrators may change the state folder, nothing inherited, owned by Administrators."""
    d = storage.state_dir()
    if not config.IS_WINDOWS:
        return OK, tr("（不是 Windows，不檢查權限）", "(not Windows: permissions not checked)")
    if not d.is_dir():
        return WARN, tr(f"還沒有狀態資料夾（{d}）：背景監控啟動時會建立", f"No state folder yet ({d}): background "
                        "monitoring creates it when it starts")
    rc, out, err = winapi._ps(
        f"$a = Get-Acl -LiteralPath {winapi._ps_quote(str(d))}; "
        "\"OWNER`t$($a.GetOwner([Security.Principal.SecurityIdentifier]).Value)\"; "
        "foreach ($r in $a.Access) { try { $s = $r.IdentityReference.Translate("
        "[Security.Principal.SecurityIdentifier]).Value } catch { $s = \"$($r.IdentityReference)\" }; "
        "\"ACE`t$s`t$($r.FileSystemRights)`t$($r.IsInherited)`t$($r.AccessControlType)\" }")
    if rc != 0:
        return WARN, tr(f"無法讀取狀態資料夾的權限：{err[:120]}", f"Could not read the state folder's permissions: {err[:120]}")
    problems = []
    for row in (line.split("\t") for line in out.splitlines()):
        if row[0] == "OWNER" and len(row) > 1 and row[1] not in (_ADMINS, _SYSTEM):
            problems.append(tr(f"擁有者是 {row[1]}", f"owned by {row[1]}"))
        elif row[0] == "ACE" and len(row) >= 5:
            sid, rights, inherited, kind = row[1:5]
            if inherited == "True":
                problems.append(tr("有繼承來的權限", "it inherits permissions"))
            elif kind == "Allow" and sid not in (_ADMINS, _SYSTEM) and any(w in rights for w in _WRITE_RIGHTS):
                problems.append(tr(f"{sid} 可以修改（{rights}）", f"{sid} can change it ({rights})"))
    if problems:
        return FAIL, tr("狀態資料夾不夠安全：", "The state folder isn't safe: ") + tr("；", "; ").join(
            sorted(set(problems))) + tr("。按「安裝並開始監控」修正", ". Click \"Install and start monitoring\" to fix it")
    return OK, tr("狀態資料夾只有系統管理員能修改", "Only administrators can change the state folder")


def check_network_and_backup():
    out = []
    paused = storage.detection_paused_until()
    if paused:
        at = time.strftime("%H:%M", time.localtime(paused))
        out.append((WARN, tr(f"檔案偵測暫停中，{at} 自動恢復（誘餌檔照常監控）",
                             f"File detection is paused until {at} (canary files are still watched)")))
    if storage.network_cut(storage.load_state()):
        out.append((WARN, tr("網路目前被切斷：確認安全後按「恢復網路並重新開啟監控」",
                             "The network is cut off: once you're sure it's safe, click \"Restore network and "
                             "restart monitoring\"")))
    else:
        out.append((OK, tr("網路正常", "The network is normal")))
    text, light, note = backup.backup_status()
    out.append((OK if light == "ok" else WARN, tr(f"備份：{text}（{note}）", f"Backup: {text} ({note})")))
    return out


def drill(timeout=15.0):
    """Simulated encryption in a temporary folder, watched by this program's detection in test mode: 12 documents
    encrypted in place, and a canary file modified. [(result, text)]: whether, and how fast, each was detected."""
    from watchdog.observers import Observer
    d = Path(tempfile.mkdtemp(prefix="rg_selfcheck_"))
    try:
        work, decoy = d / "Documents", d / "Pictures"
        work.mkdir()
        decoy.mkdir()
        for i in range(12):
            (work / f"report{i}.docx").write_bytes(canary.CANARY_DOCX)  # real Word files
        bait = decoy / canary.CANARY_NAMES[1]  # written here directly: the real canary record is left alone
        bait.write_bytes(canary.canary_bytes(bait))
        results = []
        for name, folder, canaries, act in (
                (tr("模擬加密 12 個文件", "simulated encryption of 12 documents"), work, [],
                 lambda: [p.write_bytes(os.urandom(p.stat().st_size)) for p in sorted(work.iterdir())]),
                (tr("模擬修改誘餌檔", "simulated change to a canary file"), decoy, [bait],
                 lambda: bait.write_bytes(b"encrypted" * 100))):
            fired = threading.Event()
            handler = detection.make_handler(canaries, lambda reason: fired.set(), dry_run=True)
            obs = Observer()
            obs.schedule(handler, str(folder), recursive=True)
            obs.start()
            try:
                time.sleep(0.5)
                t0 = time.monotonic()
                act()
                caught = fired.wait(timeout)
                took = time.monotonic() - t0
            finally:
                obs.stop()
                obs.join(10)
            if caught:
                results.append((OK, tr(f"演練：{name}，{took:.1f} 秒內偵測到", f"Drill: {name}, detected within {took:.1f} s")))
            else:
                results.append((FAIL, tr(f"演練：{name}，{timeout:.0f} 秒內沒有偵測到",
                                         f"Drill: {name}, not detected within {timeout:.0f} s")))
        return results
    except Exception as ex:
        log.exception(tr("自我檢查演練失敗", "The self-check drill failed"))
        return [(FAIL, tr(f"演練無法進行：{ex}", f"The drill could not run: {ex}"))]
    finally:
        shutil.rmtree(d, ignore_errors=True)


def run_selfcheck(report) -> list:
    """The control panel's "Self-check": every check, reported as it is done, then a summary. Returns the results."""
    report(tr("自我檢查中（約 10 秒）...", "Self-checking (about 10 seconds)..."))
    label = {OK: tr("[正常]", "[OK]"), WARN: tr("[注意]", "[Check]"), FAIL: tr("[失敗]", "[Failed]")}
    results = []

    def step(fn, *args):
        try:
            found = fn(*args)
        except Exception as ex:
            log.exception(tr("自我檢查失敗", "Self-check failed"))
            found = (FAIL, tr(f"無法檢查：{ex}", f"Could not check: {ex}"))
        for result, text in found if isinstance(found, list) else [found]:
            results.append(result)
            report(f"{label[result]} {text}")

    lines = _log_lines()
    step(check_task)
    step(check_restart_trigger)
    step(check_monitor_log, lines)
    step(check_canary_files)
    step(check_state_permissions)
    step(check_errors, lines)
    step(check_network_and_backup)
    step(drill)
    fails, warns = results.count(FAIL), results.count(WARN)
    summary = (tr("自我檢查完成：全部正常。", "Self-check done: everything works.") if not fails and not warns else
               tr(f"自我檢查完成：{fails} 項失敗、{warns} 項需要注意，詳見上方。",
                  f"Self-check done: {fails} failed, {warns} to check (see above)."))
    log.info("%s", summary)
    report(summary)
    return results
