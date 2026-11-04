"""The monitor's main loop and the command line."""
import argparse
import sys
import threading
import time
from pathlib import Path

from . import canary, config, defender, detection, folders, gui, install, network, processes, response, storage, updates, winapi
from .config import log, tr


# how often (seconds) folders that aren't watched are looked for: looking up a NAS that is off can take a while
REWATCH_INTERVAL = 60


def run(args, stop=None):
    """The monitor. stop: an Event that ends it (tests); it otherwise runs until Windows ends it."""
    winapi.exit_with_launcher()
    try:
        from watchdog.observers import Observer
    except ImportError:
        msg = tr("缺少 watchdog 套件，請先執行：pip install watchdog",
                 "The watchdog package is missing. Run: pip install watchdog")
        log.error(msg)
        winapi.alert(tr("RansomGuard 無法啟動", "RansomGuard could not start"), msg)
        sys.exit(1)

    if config.IS_WINDOWS and not args.dry_run and not winapi.is_admin():
        msg = tr("需要系統管理員權限才能切斷網路。\n請用「以系統管理員身分執行」啟動，或改用 --dry-run 測試。",
                 "Administrator rights are needed to cut off the network.\n"
                 "Start it with \"Run as administrator\", or use --dry-run to test.")
        log.error(msg)
        winapi.alert(tr("RansomGuard 無法啟動", "RansomGuard could not start"), msg)
        sys.exit(1)
    if not args.dry_run and not winapi.single_instance():
        log.info(tr("已經有監控在執行，這次不再啟動", "Monitoring is already running; not starting again"))
        sys.exit(0)
    if not args.dry_run:
        storage.secure_state_dir()
        if install.stopped_by_user():  # the task's every-few-minutes trigger must not undo "Stop monitoring"
            log.info(tr("使用者已停止監控，重新開機前不會自動啟動", "Monitoring was stopped by the user; "
                        "it doesn't start by itself until Windows restarts"))
            sys.exit(0)
        canary.remove_legacy_canaries()  # safe now: no other monitor is watching the old canary files
        install.cleanup_old_files()

    st = storage.load_state()
    if st.get("triggered_at") and not args.dry_run and abs(st.get("reminded", 0) - winapi.boot_time()) > 120:
        # once per Windows start: the task may start the monitor again every few minutes
        st["reminded"] = winapi.boot_time()
        storage.save_state(st)
        why = "\n".join(storage.incident_lines(st, limit=3))
        winapi.alert(tr("RansomGuard 提醒", "RansomGuard reminder"),
                     tr(f"上次在 {st['triggered_at']} 偵測到疑似勒索病毒並切斷了網路。\n"
                        f"{why}\n\n確認電腦安全後，{install.restore_hint()}。",
                        f"Possible ransomware was detected at {st['triggered_at']} and the network was cut off.\n"
                        f"{why}\n\nOnce you're sure the computer is safe, {install.restore_hint()}."))

    wanted = [Path(p) for p in args.watch] if args.watch else folders.default_watch_dirs() + folders.extra_watch_dirs()
    watch_dirs = [d for d in wanted if d.is_dir()]  # the others (e.g. a USB drive not plugged in) are added when they appear
    if not watch_dirs:
        log.error(tr("沒有可監控的資料夾", "No folders to watch"))
        sys.exit(1)
    canaries = canary.plant_canaries(watch_dirs, upgrade=not args.dry_run)

    stop = stop or threading.Event()

    def on_trigger(reason, files=()):
        proc = response.respond(reason, args.dry_run, files)
        if not args.dry_run:
            if proc is not None:
                # wait for the user to close the warning, so it isn't closed together with this program
                network.keep_offline(proc)
                if proc.returncode != 0:  # the window failed: fall back to a regular alert so the user still knows
                    log.error(tr("全螢幕警告異常結束（代碼 %s）", "Full-screen warning ended abnormally (code %s)"),
                              proc.returncode)
                    winapi.alert(tr("RansomGuard：偵測到疑似勒索病毒，網路已切斷",
                                    "RansomGuard: possible ransomware detected, network cut off"), reason)
            # monitoring goes on (it doesn't trigger a second time): dangerous commands are still stopped and
            # the programs behind them paused while the network is cut

    def trigger(reason):
        # in a thread of its own: the response lasts until the warning is closed, and the thread that found
        # the problem (the process monitor, the file monitor, the periodic check) has to go on working
        threading.Thread(target=on_trigger, args=(reason, list(handler.last_files)), daemon=True).start()

    scanner = None
    if config.DEFENDER_SCAN_DOWNLOADS and config.IS_WINDOWS and defender.MPCMDRUN.is_file():
        scanner = defender.DownloadScanner()
        scanner.start()
    handler = detection.make_handler(canaries, trigger, args.dry_run, scanner.add if scanner else None)

    def start_observer():
        obs = Observer()
        for d in watch_dirs:
            if d.is_dir():
                obs.schedule(handler, str(d), recursive=True)
        obs.start()
        return obs

    def unwatched():
        """Folders to watch that exist but have no working watcher: a watched USB drive that was unplugged
        (its watcher stops) and plugged in again, or one that wasn't there when the monitor started."""
        live = {winapi.norm(e.watch.path) for e in observer.emitters if e.is_alive()}
        return [d for d in wanted if winapi.norm(d) not in live and d.is_dir()]  # only those are looked up

    def not_watched_now():
        """Folders whose watcher stopped (a USB drive was unplugged, say): their canary files are left out of the
        periodic check until they are watched again. In their place there may now be another drive, without
        canary files, and that is no attack."""
        return {winapi.norm(e.watch.path) for e in observer.emitters if not e.is_alive()}

    def watch_again(dirs):
        # canary files first, before the folder is watched, so planting them is no file event: a folder that
        # comes back keeps intact ones (the same drive) and gets new ones (another drive, a new folder)
        known = {winapi.norm(p) for p in canaries}
        added = [p for p in canary.plant_canaries(dirs, upgrade=not args.dry_run) if winapi.norm(p) not in known]
        canaries.extend(added)
        handler.canaries.update(winapi.norm(p) for p in added)
        watching = {winapi.norm(d) for d in watch_dirs}
        watch_dirs.extend(d for d in dirs if winapi.norm(d) not in watching)
        again = {winapi.norm(d) for d in dirs}
        for e in list(observer.emitters):
            if winapi.norm(e.watch.path) in again:
                observer.unschedule(e.watch)  # the stopped watcher; a new one takes its place
        for d in dirs:
            observer.schedule(handler, str(d), recursive=True)

    observer = start_observer()
    procmon = None
    if config.PROCESS_MONITOR and config.IS_WINDOWS:
        procmon = processes.ProcessMonitor(handler.fire, kill=not args.dry_run)
        procmon.start()
    if config.FROZEN and not args.dry_run:
        threading.Thread(target=updates.update_watcher, args=(stop,), daemon=True).start()
    restarts, restarts_since = 0, time.time()

    log.info(tr("RansomGuard %s 開始監控%s：%s", "RansomGuard %s started monitoring%s: %s"), config.VERSION,
             tr("（測試模式）", " (test mode)") if args.dry_run else "",
             "; ".join(str(d) for d in watch_dirs))
    log.info(tr("誘餌檔：%s", "Canary files: %s"), "; ".join(str(p) for p in canaries))
    try:
        last = pruned = probed = time.time()
        while not stop.wait(1):
            if time.time() - last < config.CHECK_INTERVAL:
                continue
            last = time.time()
            stopped = not_watched_now()
            detection.periodic_check(handler, [p for p in canaries if winapi.norm(p.parent) not in stopped]
                                     if stopped else canaries)
            if last - pruned > 86400:  # the monitor can run for weeks: keep the log to LOG_KEEP_DAYS anyway
                pruned = last
                storage.prune_own_log()
            # restart a monitor component that stopped unexpectedly and watch folders that came back, up to 10
            # times an hour, so a crash loop doesn't spin but a drive coming and going isn't fatal either
            if last - restarts_since > 3600:
                restarts, restarts_since = 0, last
            try:
                if restarts < 10 and not observer.is_alive():
                    restarts += 1
                    log.error(tr("檔案監控意外停止，重新啟動（第 %d 次）",
                                 "File monitor stopped unexpectedly; restarting (attempt %d)"), restarts)
                    observer = start_observer()
                elif restarts < 10 and last - probed >= REWATCH_INTERVAL:
                    probed = last
                    again = unwatched()
                    if again:
                        restarts += 1
                        log.warning(tr("開始監控（再次）出現的資料夾：%s", "Watching folders that (re)appeared: %s"),
                                    "; ".join(str(d) for d in again))
                        watch_again(again)
            except OSError as ex:  # the folder went away again in between; tried again next time
                log.error(tr("無法監控資料夾：%s", "Could not watch a folder: %s"), ex)
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
    if winapi.restart_if_borrowed_files():
        return
    winapi.fix_console_encoding()
    langs = ["zh", "en"]
    pre = argparse.ArgumentParser(add_help=False)  # read --lang first so the help text is in the right language
    pre.add_argument("--lang", choices=langs)
    config.init_lang(pre.parse_known_args()[0].lang)
    ap = argparse.ArgumentParser(description=tr("偵測勒索病毒行為並自動斷網",
                                                "Detects ransomware behavior and cuts off the network"))
    ap.add_argument("--version", action="version", version=f"RansomGuard {config.VERSION}")
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
                    help=tr("安裝背景監控並開始監控（有新版會先更新）",
                            "install background monitoring and start it (updating first if there is a newer release)"))
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
    storage.setup_logging()
    if args.test_alert:
        response.fullscreen_alert(tr("這是警告畫面的預覽（--test-alert），沒有偵測到任何東西",
                                     "This is a preview of the warning (--test-alert); nothing was detected"),
                                  "test", wait=True)
    elif args.restore:
        network.restore_network(log.info)
    elif args.install:
        if config.IS_WINDOWS and not winapi.is_admin():
            log.error(tr("需要以系統管理員身分執行才能安裝", "Administrator rights are needed to install"))
            sys.exit(1)
        try:
            ok = install.install(log.info)
        except Exception:
            log.exception(tr("安裝失敗", "Install failed"))
            ok = False
        sys.exit(0 if ok else 1)
    elif args.gui or args.update or (config.FROZEN and not (args.monitor or args.dry_run or args.watch)):
        gui.gui(auto_update=args.update)
    else:
        run(args)
