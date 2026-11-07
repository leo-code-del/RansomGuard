"""The control panel window."""
import ctypes
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

from . import backup, canary, config, folders, install, network, response, selftest, storage, tray, updates, winapi
from .config import log, tr
from .winapi import norm


def status_info():
    """Background monitoring and the network, for the control panel: ((text, light, note), (text, light, note));
    light is ok / paused (running, file detection paused) / warn / bad / off."""
    s = install.task_state()
    unprotected = tr("目前沒有勒索病毒防護", "No ransomware protection right now")
    mon = {"Running": (tr("執行中", "Running"), "ok",
                       tr("每次登入 Windows 都會自動啟動", "Starts every time you sign in to Windows")),
           "Ready": (tr("已停止", "Stopped"), "warn", unprotected),
           "Disabled": (tr("已停用", "Disabled"), "warn", unprotected),
           "": (tr("尚未安裝", "Not installed"), "off",
                tr("按「安裝並開始監控」", "Click \"Install and start monitoring\""))
           }.get(s, (s, "warn", ""))
    paused = storage.detection_paused_until()
    if s == "Running" and paused:
        at = time.strftime("%H:%M", time.localtime(paused))
        mon = (tr("偵測暫停中", "Detection paused"), "paused",
               tr(f"{at} 自動恢復；誘餌檔照常監控", f"Resumes at {at}; canary files are still watched"))
    st = storage.load_state()
    cut = tr("已切斷", "Cut off")
    if st.get("triggered_at"):
        net = (cut, "bad", tr(f"{st['triggered_at']} 偵測到可疑行為",
                              f"Suspicious activity detected at {st['triggered_at']}"))
    elif storage.network_cut(st):
        net = (cut, "bad", tr("確認安全後再恢復網路", "Restore it once you're sure it's safe"))
    else:
        net = (tr("正常", "Normal"), "ok", tr("連線沒有被限制", "The connection is not restricted"))
    return mon, net


def home_status(info):
    """The control panel home page's one status, from status_info(): (title, light, note, what to do), what to do
    being restore / install / resume / selfcheck. A cut network comes first, then whether it is protected."""
    (mon_text, mon_light, mon_note), (_, net_light, net_note) = info
    if net_light == "bad":
        return tr("網路已切斷", "Network cut off"), "bad", net_note, "restore"
    if mon_light == "off":
        return (tr("尚未安裝", "Not installed"), "off",
                tr("安裝後就會在背景保護這台電腦。", "Install it to protect this computer in the background."), "install")
    if mon_light == "warn":
        return (tr("沒有防護", "Not protected"), "warn",
                tr(f"背景監控{mon_text}，這台電腦目前沒有勒索病毒防護。",
                   f"Background monitoring: {mon_text}. This computer has no ransomware protection right now."), "install")
    if mon_light == "paused":
        return mon_text, "paused", mon_note, "resume"
    return (tr("已受到保護", "Protected"), "ok",
            tr("背景監控執行中，每次登入 Windows 都會自動啟動；網路正常。",
               "Background monitoring is running and starts every time you sign in; the network is normal."), "selfcheck")


def icon_file() -> str:
    """icon.ico: packed into the exe (PyInstaller --add-data) or next to the script.
    Read from the file itself, never through Windows' icon cache, which can keep an old version's icon
    for the installed exe's path (that is what the taskbar showed until 1.5.3)."""
    base = getattr(sys, "_MEIPASS", None) or str(config.ROOT)
    path = os.path.join(base, "icon.ico")
    return path if os.path.exists(path) else sys.executable


def set_window_icons(root, source: str):
    """Set the window's own big (taskbar, Alt+Tab) and small (title bar) icons and its class icons from
    source. Called again after the window is shown, because Tk re-applies its icon when mapping it."""
    if not config.IS_WINDOWS:
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
    from tkinter import filedialog, messagebox, scrolledtext
    from tkinter import font as tkfont

    if config.IS_WINDOWS and not winapi.is_admin():  # reopen as administrator
        script = [] if config.FROZEN else [str(config.SCRIPT)]
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
    storage.secure_state_dir()  # the control panel runs with administrator rights, like the monitor

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
         "ok": "#16a34a", "paused": "#d97706", "warn": "#d97706", "bad": "#dc2626", "off": "#9ca3af"}
    # button styles: (background, hover background, text, disabled text)
    STYLES = {"primary": ("#2563eb", "#1d4ed8", "#ffffff", "#bfd0f7"),
              "success": ("#16a34a", "#15803d", "#ffffff", "#bde5cb"),
              "secondary": ("#ffffff", "#eef1f6", C["text"], "#c3c9d4"),
              "danger": (C["bg"], "#fde8e8", C["bad"], "#e8b4b4"),
              "link": (C["bg"], "#e8ecf3", C["text"], "#c3c9d4"),
              "header": (C["header"], "#334155", "#cbd5e1", "#64748b")}
    root.configure(bg=C["bg"])

    q = queue.Queue()
    buttons = []
    w = {"page": "home", "lines": []}  # the window's state; it is rebuilt when the language changes
    pw = {}  # widgets of the page on screen now (home, protection, tools or settings)

    def make_button(parent, text, cmd, name, track=True):
        """track: disable it while an action runs (not for buttons of a dialog, which may be gone by then)."""
        rim = tk.Frame(parent)  # 1px border (a tk button's own border can only be black on Windows)
        b = tk.Button(rim, text=text, command=cmd, font=(w["font"], 11), relief="flat", bd=0,
                      highlightthickness=0, cursor="hand2", padx=px(12), pady=px(5))
        b.pack(fill="both", padx=1, pady=1)
        if track:
            buttons.append(b)
            if w.get("working"):  # a page opened while an action runs
                b.config(state="disabled")

        # bound once and reading the current style, so restyling (show_status) doesn't stack handlers
        def enter(_):
            if str(b["state"]) == "normal":
                hover = STYLES[b.rg_style][1]
                b.config(bg=hover)
                rim.config(bg=C["border"] if b.rg_style == "secondary" else hover)
        b.bind("<Enter>", enter, add="+")
        b.bind("<Leave>", lambda _: style(b, b.rg_style), add="+")
        style(b, name)
        return rim, b

    def style(b, name):
        b.rg_style = name
        bg, hover, fg, dim = STYLES[name]
        b.master.config(bg=C["border"] if name == "secondary" else bg)
        b.config(bg=bg, fg=fg, activebackground=hover, activeforeground=fg, disabledforeground=dim)

    def on_install():
        run_bg(lambda rep: install.install(rep, update=False))

    def on_selfcheck():
        run_bg(selftest.run_selfcheck)

    def resume_now():
        storage.resume_detection()
        write(tr("檔案偵測已恢復。", "File detection resumed."))
        refresh()

    # what home_status() suggests: (command, button style); on_restore is defined further down
    actions = {"restore": (lambda: on_restore(), "success"), "install": (on_install, "primary"),
               "resume": (resume_now, "secondary"), "selfcheck": (on_selfcheck, "secondary")}

    def show_status(info):
        w["status"] = info  # kept, so a page opened later shows it at once
        if "hero" in pw:
            dot, title, note, action = pw["hero"]
            text, light, detail, todo = home_status(info)
            cmd, name = actions[todo]
            label = {"restore": tr("恢復網路並重新開啟監控", "Restore network and restart monitoring"),
                     "install": tr("安裝並開始監控", "Install and start monitoring"),
                     "resume": tr("立即恢復偵測", "Resume detection now"),
                     "selfcheck": tr("自我檢查", "Self-check")}[todo]
            dot.config(fg=C[light])
            title.config(text=text, fg=C["bad"] if light == "bad" else C["text"])
            note.config(text=nb(detail))
            action.config(text=label, command=cmd, state="disabled" if w.get("working") else "normal")
            style(action, name)
        # on the protection page, color only what needs the user now
        cut, running = info[1][1] == "bad", info[0][1] in ("ok", "paused")
        if "install" in pw:
            style(pw["install"], "primary" if not cut and not running else "secondary")
        if "restore" in pw:
            style(pw["restore"], "success" if cut else "secondary")

    def update_label():
        new = w.get("new")
        return tr(f"更新到 v{new}", f"Update to v{new}") if new else tr("檢查版本更新", "Check for updates")

    def offer_update(new):
        """A newer version is known (found by the automatic check or the button): name it, then ask."""
        w["new"] = new
        show_page(w["page"])  # the home page's Tools row and the Update button name it
        if messagebox.askyesno("RansomGuard", tr(
                f"有新版本 v{new}（目前是 v{config.VERSION}）。\n\n要現在更新嗎？\n"
                "選「否」會繼續用目前的版本監控，之後隨時可以再按「檢查版本更新」。",
                f"Version {new} is available (you have v{config.VERSION}).\n\nUpdate now?\n"
                "With \"No\" monitoring continues with this version; you can click \"Check for updates\" "
                "again any time.")):
            run_bg(install.install)

    def write(msg, tag=None):
        """Add a line to the progress area (kept, so it survives switching pages and the language)."""
        w["lines"].append((msg, tag))
        w["intro"] = False
        out = w.get("out")
        if out is not None and out.winfo_exists():
            out.config(state="normal")
            out.insert("end", msg + "\n", tag)
            out.see("end")
            out.config(state="disabled")

    def clear_progress():
        w["lines"] = []
        out = w.get("out")
        if out is not None and out.winfo_exists():
            out.config(state="normal")
            out.delete("1.0", "end")
            out.config(state="disabled")

    def intro():
        """What the progress area says before any action: the detection report while the network is cut, else a
        hint. Written again in the new language when it is switched."""
        clear_progress()
        report_lines = storage.incident_lines(storage.load_state())
        if report_lines:  # say why, so the user can tell a false alarm from a real attack
            write(tr("偵測報告", "Detection report"), "err")
            for line in report_lines:
                write(line)
            w["out"].see("1.0")  # from the top: why it triggered comes first
        else:
            write(tr("操作的進度和結果會顯示在這裡。", "The progress and results of what you do show here."), "hint")
        w["intro"] = True

    def report(msg):
        q.put(("msg", msg))

    def refresh():
        def work():
            q.put(("status", status_info()))
            q.put(("backup", backup.backup_status()))
        threading.Thread(target=work, daemon=True).start()

    def show_backup(info):
        w["backup"] = info
        if "backup" in pw:
            text, level, _ = info
            dot, val = pw["backup"]
            dot.config(fg=C[level])
            val.config(text=text, fg=C["bad"] if level == "bad" else C["text"])

    def run_bg(fn):
        for b in buttons:
            if b.winfo_exists():
                b.config(state="disabled")
        w["busy"].config(text=tr("執行中...", "Working..."))
        w["working"] = True
        clear_progress()

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
                elif kind == "backup":
                    show_backup(msg)
                elif kind == "update":  # the automatic check found a newer version when the window opened
                    if msg and not w.get("working"):
                        offer_update(msg)
                    elif msg:  # busy now: just name it
                        w["new"] = msg
                        show_page(w["page"])
                else:
                    for b in buttons:
                        if b.winfo_exists():  # (a page closed meanwhile takes its buttons with it)
                            b.config(state="normal")
                    w["busy"].config(text="")
                    w["working"] = False
                    if install.UPDATED_TO:  # reopen the control panel from the newly installed version
                        messagebox.showinfo("RansomGuard", tr(f"已更新到 v{install.UPDATED_TO}，控制台會用新版本重新開啟。",
                                                              f"Updated to v{install.UPDATED_TO}. The control panel "
                                                              "will reopen with the new version."))
                        try:
                            install.spawn_installed("--gui")
                        except OSError as ex:
                            write(tr(f"[失敗] 無法開啟新版本：{ex}", f"[Failed] Could not open the new version: {ex}"),
                                  "err")
                        else:
                            root.destroy()
                            return
                    refresh()
                    offer = w.pop("offer", None)  # found by the "Check for updates" button
                    if offer:
                        offer_update(offer)
        except queue.Empty:
            pass
        w["pump"] = root.after(100, pump)

    def on_restore():
        st = storage.load_state()
        report_text = "\n".join(storage.incident_lines(st, limit=5))
        if storage.network_cut(st) and not messagebox.askyesno(
                tr("恢復網路", "Restore network"),
                (report_text + "\n\n" if report_text else "")
                + tr("請先確認這次是測試或誤判，而不是真的中了勒索病毒：例如上面的檔案是不是你自己剛剛在處理的。"
                     "\n\n確定要恢復網路嗎？",
                     "First make sure this was a test or a false alarm, not a real ransomware infection: for example, "
                     "whether you were working on the files above yourself.\n\nRestore the network?"),
                icon="warning"):
            return
        run_bg(network.restore_network)

    def stop_monitoring():
        if messagebox.askyesno(tr("停止監控", "Stop monitoring"),
                               tr("停止後電腦就沒有勒索病毒防護，直到你按「安裝並開始監控」或重新開機。\n確定要停止嗎？",
                                  "This computer will have no ransomware protection until you click \"Install "
                                  "and start monitoring\" or restart Windows.\nStop monitoring?")):
            run_bg(lambda rep: (install.stop_monitor_until_restart(),
                                rep(tr("監控已停止，重新開機後會自動再啟動。",
                                       "Monitoring stopped. It starts again by itself when Windows restarts."))))

    def on_stop():
        """Dialog: pause file detection for a while (bulk work), resume it, or stop monitoring until a restart."""
        title = tr("暫停／停止監控", "Pause or stop monitoring")
        F = w["font"]
        dlg = tk.Toplevel(root)
        dlg.title(title)
        dlg.configure(bg=C["bg"])
        dlg.resizable(False, False)
        dlg.transient(root)
        pad = tk.Frame(dlg, bg=C["bg"])
        pad.pack(fill="both", padx=px(20), pady=px(16))

        def label(text, bold=False, muted=False, gap=(0, 0)):
            tk.Label(pad, text=text, font=(F, 10, "bold") if bold else (F, 9), fg=C["muted"] if muted else C["text"],
                     bg=C["bg"], justify="left", wraplength=px(420)).pack(anchor="w", pady=gap)

        def choose(fn):
            def run():
                dlg.destroy()
                fn()
            return run

        def pause(minutes):
            until = storage.pause_detection(minutes)
            at = time.strftime("%H:%M", time.localtime(until))
            write(tr(f"檔案偵測已暫停，{at} 自動恢復。誘餌檔與危險指令照常監控。",
                     f"File detection is paused until {at}. Canary files and dangerous commands are still watched."))
            refresh()

        def resume():
            storage.resume_detection()
            write(tr("檔案偵測已恢復。", "File detection resumed."))
            refresh()

        def option(text, cmd, name="secondary"):
            make_button(pad, text, cmd, name, track=False)[0].pack(fill="x", pady=(0, px(6)))

        paused = storage.detection_paused_until()
        label(tr("暫停檔案偵測", "Pause file detection"), bold=True)
        label(tr("要大量轉檔、改名或用加密軟體加密檔案時使用。暫停期間不計算「檔案像被加密」「陌生副檔名」「勒索信」"
                 "「加密副本」；誘餌檔和危險指令照常監控。時間到自動恢復。",
                 "For bulk work such as converting, renaming or encrypting many files on purpose. While paused, files "
                 "that look encrypted, unknown extensions, ransom notes and encrypted copies aren't counted; canary "
                 "files and dangerous commands are still watched. It resumes by itself."),
              muted=True, gap=(0, px(8)))
        if paused:
            at = time.strftime("%H:%M", time.localtime(paused))
            option(tr(f"立即恢復偵測（原本 {at} 恢復）", f"Resume detection now (due at {at})"), choose(resume), "primary")
        option(tr("暫停 30 分鐘", "Pause for 30 minutes"), choose(lambda: pause(30)), "secondary" if paused else "primary")
        option(tr("暫停 2 小時", "Pause for 2 hours"), choose(lambda: pause(120)))
        label(tr("停止監控", "Stop monitoring"), bold=True, gap=(px(8), 0))
        label(tr("完全沒有防護，直到你按「安裝並開始監控」或重新開機。", "No protection at all until you click \"Install and "
                 "start monitoring\" or restart Windows."), muted=True, gap=(0, px(8)))
        option(tr("停止監控到重新開機…", "Stop monitoring until restart…"), choose(stop_monitoring), "danger")
        make_button(pad, tr("取消", "Cancel"), dlg.destroy, "secondary", track=False)[0].pack(anchor="e", pady=(px(6), 0))
        dlg.update_idletasks()
        dlg.geometry(f"+{root.winfo_rootx() + px(30)}+{root.winfo_rooty() + px(60)}")
        dlg.grab_set()

    def on_uninstall():
        title = tr("解除安裝", "Uninstall")
        if storage.network_cut(storage.load_state()):
            messagebox.showinfo(title, tr("網路目前被切斷，請先按「恢復網路並重新開啟監控」。",
                                          "The network is cut off. Click \"Restore network and "
                                          "restart monitoring\" first."))
            return
        if messagebox.askyesno(title, tr("確定要移除背景監控、桌面捷徑與誘餌檔嗎？",
                                         "Remove background monitoring, the desktop shortcut and "
                                         "the canary files?")):
            run_bg(install.uninstall)

    def on_preview():
        run_bg(lambda rep: (rep(tr("警告畫面開啟中，按「我知道了」即可關閉。",
                                   "Opening the warning. Click \"I understand\" to close it.")),
                            response.fullscreen_alert(tr("這是警告畫面的預覽，沒有偵測到任何東西",
                                                         "This is a preview of the warning; nothing was detected"),
                                                      "test")))

    def on_log():
        p = config.app_dir() / "guard.log"
        if p.exists():
            os.startfile(p)
        else:
            messagebox.showinfo(tr("紀錄檔", "Log"), tr("還沒有紀錄檔。", "There is no log file yet."))

    def on_watch_folders():
        """Dialog: the folders watched besides the default ones (another drive, a USB drive, a NAS...)."""
        title = tr("監控的資料夾", "Watched folders")
        F = w["font"]
        dlg = tk.Toplevel(root)
        dlg.title(title)
        dlg.configure(bg=C["bg"])
        dlg.resizable(False, False)
        dlg.transient(root)
        pad = tk.Frame(dlg, bg=C["bg"])
        pad.pack(fill="both", padx=px(20), pady=px(16))

        def label(text, bold=False, muted=False, gap=(0, 0)):
            tk.Label(pad, text=text, font=(F, 10, "bold") if bold else (F, 9), fg=C["muted"] if muted else C["text"],
                     bg=C["bg"], justify="left", wraplength=px(440)).pack(anchor="w", pady=gap)
        label(tr("一律監控", "Always watched"), bold=True)
        label("\n".join(str(d) for d in folders.default_watch_dirs()), gap=(px(2), px(12)))

        def folder_list(heading, items, problem):
            """A titled list of folders with Add and Remove; problem(path) says why one can't be added ("" if it
            can)."""
            label(heading, bold=True)
            lb = tk.Listbox(pad, font=(F, 10), height=3, width=54, relief="flat", bd=0, highlightthickness=1,
                            highlightbackground=C["border"], activestyle="none", selectbackground="#dbeafe",
                            selectforeground=C["text"])
            lb.pack(fill="x", pady=(px(4), px(8)))
            for d in items:
                lb.insert("end", str(d))

            def add():
                path = filedialog.askdirectory(parent=dlg, title=title, mustexist=True)
                if not path:
                    return
                path = os.path.normpath(path)
                why = problem(path)
                if why:
                    messagebox.showwarning(title, f"{path}\n\n{why}", parent=dlg)
                elif norm(path) not in {norm(p) for p in lb.get(0, "end")}:
                    lb.insert("end", path)

            def remove():
                for i in reversed(lb.curselection()):
                    lb.delete(i)
            row = tk.Frame(pad, bg=C["bg"])
            row.pack(fill="x")
            make_button(row, tr("新增資料夾…", "Add folder…"), add, "secondary", track=False)[0].pack(side="left")
            make_button(row, tr("移除", "Remove"), remove, "secondary", track=False)[0].pack(side="left",
                                                                                           padx=(px(6), 0))
            return lb

        lb = folder_list(tr("另外監控的資料夾（例如 D 槽、隨身碟、NAS）", "Also watched (e.g. another drive, a USB drive, a NAS)"),
                         folders.extra_watch_dirs(), folders.watch_problem)
        label(nb(tr("每個監控的資料夾都會放入隱藏的誘餌檔。", "Each watched folder gets hidden canary files.")),
              muted=True, gap=(px(6), px(14)))
        # (checked against the watched folders as listed now, including ones added but not saved yet)
        skip = folder_list(tr("不偵測的子資料夾（例如 node_modules、程式的輸出資料夾）",
                              "Not checked (e.g. node_modules, a build output folder)"),
                           folders.excluded_dirs(),
                           lambda p: folders.exclude_problem(p, folders.default_watch_dirs()
                                                             + [Path(x) for x in lb.get(0, "end")]))
        label(nb(tr("只排除會自己大量變動的資料夾：裡面的檔案變動不會被計算，勒索病毒在這裡加密不會被發現；誘餌檔和危險指令照常監控。"
                    "儲存後背景監控會重新啟動。",
                    "Exclude only folders that change a lot on their own: what happens in them isn't counted, so "
                    "ransomware encrypting them goes unnoticed; canary files and dangerous commands are still "
                    "watched. Saving restarts background monitoring.")),
              muted=True, gap=(px(6), px(10)))

        def save():
            new = [Path(p) for p in lb.get(0, "end")]
            skipped = [Path(p) for p in skip.get(0, "end")]
            removed = [d for d in folders.extra_watch_dirs() if norm(d) not in {norm(n) for n in new}]
            dlg.destroy()

            def work(rep):
                folders.save_extra_watch_dirs(new)
                folders.save_excluded_dirs(skipped)
                rep(tr(f"已儲存：另外監控 {len(new)} 個資料夾，不偵測 {len(skipped)} 個子資料夾。",
                       f"Saved: {len(new)} more folder(s) watched, {len(skipped)} subfolder(s) not checked."))
                installed = bool(install.task_state())
                if installed:
                    install.stop_monitor()  # before its canaries go, or removing them would trigger it
                if removed:
                    canary.remove_canaries(only_in=removed)
                if installed:
                    rep(tr("  監控已重新啟動", "  Monitoring restarted") if install.start_monitor() else
                        tr("  監控沒有正常啟動，請按「安裝並開始監控」", "  Monitoring did not start. Click \"Install "
                           "and start monitoring\""))
            run_bg(work)
        bottom = tk.Frame(pad, bg=C["bg"])
        bottom.pack(fill="x")
        make_button(bottom, tr("儲存", "Save"), save, "primary", track=False)[0].pack(side="right")
        make_button(bottom, tr("取消", "Cancel"), dlg.destroy, "secondary", track=False)[0].pack(
            side="right", padx=(0, px(6)))
        dlg.update_idletasks()
        dlg.geometry(f"+{root.winfo_rootx() + px(30)}+{root.winfo_rooty() + px(60)}")
        dlg.grab_set()

    def on_backup():
        """Dialog: why a backup matters and how to set one up (Windows' own settings open; nothing is changed here)."""
        title = tr("備份", "Backup")
        F = w["font"]
        dlg = tk.Toplevel(root)
        dlg.title(title)
        dlg.configure(bg=C["bg"])
        dlg.resizable(False, False)
        dlg.transient(root)
        pad = tk.Frame(dlg, bg=C["bg"])
        pad.pack(fill="both", padx=px(20), pady=px(16))

        def label(text, bold=False, muted=False, gap=(0, 0)):
            tk.Label(pad, text=text, font=(F, 10, "bold") if bold else (F, 9), fg=C["muted"] if muted else C["text"],
                     bg=C["bg"], justify="left", wraplength=px(440)).pack(anchor="w", pady=gap)

        def button(text, cmd):
            make_button(pad, text, cmd, "secondary", track=False)[0].pack(anchor="w", pady=(px(4), px(12)))

        def opened(fn):
            def run():
                try:
                    fn()
                except OSError as ex:
                    messagebox.showerror(title, str(ex), parent=dlg)
            return run
        text, _, note = backup.backup_status()
        label(tr(f"目前：{text}（{note}）", f"Now: {text} ({note})"), bold=True, gap=(0, px(4)))
        # (no-break spaces after the Latin words: Tk breaks lines at spaces, and there would be no other one)
        label(tr("RansomGuard 能在勒索病毒發作時切斷網路，但沒辦法救回已經被加密的檔案，只有備份可以。",
                 "RansomGuard cuts the network when ransomware strikes, but it can't bring encrypted files back. "
                 "Only a backup can."), muted=True, gap=(0, px(12)))
        label(tr("檔案歷程記錄：備份到外接硬碟", "File History: back up to an external drive"), bold=True)
        label(tr("Windows 內建，定期把檔案複製到外接硬碟。備份完把硬碟拔掉：一直接著的硬碟會被勒索病毒一起加密。",
                 "Built into Windows: copies your files to an external drive regularly. Unplug the drive after a "
                 "backup: a drive that stays connected gets encrypted too."))
        button(tr("開啟檔案歷程記錄", "Open File History"),
               opened(lambda: subprocess.Popen([winapi.sys_exe("control.exe"), "/name", "Microsoft.FileHistory"])))
        label(tr("OneDrive：桌面、文件、圖片放到雲端", "OneDrive: keep Desktop, Documents and Pictures in the cloud"), bold=True)
        label(tr("檔案會保留舊版本，被加密後可以還原到之前的版本。需要 Microsoft 帳號。",
                 "Earlier versions of each file are kept, so encrypted files can be restored. Needs a Microsoft account."))
        button(tr("開啟 Windows 備份設定", "Open Windows backup settings"), opened(lambda: os.startfile("ms-settings:backup")))
        other = tk.BooleanVar(value=config.load_settings().get("other_backup") is True)

        def on_other():
            config.set_setting("other_backup", bool(other.get()))
        tk.Checkbutton(pad, text=tr("我用其他備份程式（不再提醒）", "I back up with another program (no more reminders)"),
                       variable=other, command=on_other, font=(F, 10), fg=C["text"], bg=C["bg"],
                       activebackground=C["bg"], selectcolor=C["card"], highlightthickness=0, bd=0,
                       cursor="hand2").pack(anchor="w", pady=(0, px(12)))

        def close():
            dlg.destroy()
            refresh()
        dlg.protocol("WM_DELETE_WINDOW", close)
        make_button(pad, tr("關閉", "Close"), close, "primary", track=False)[0].pack(anchor="e")
        dlg.update_idletasks()
        dlg.geometry(f"+{root.winfo_rootx() + px(30)}+{root.winfo_rooty() + px(40)}")
        dlg.grab_set()

    def on_auto_update():
        if w["auto"].get() and not messagebox.askyesno(
                tr("自動檢查新版本", "Check for updates automatically"),
                tr("開啟後，RansomGuard 每 6 小時，以及開啟控制台時，會連到 GitHub 檢查有沒有新版本。\n"
                   "GitHub 會因此看到這台電腦的 IP 位址（不會傳送其他資料）。\n\n要開啟嗎？",
                   "RansomGuard will then contact GitHub every 6 hours, and when the control panel opens, to look "
                   "for a new version.\nGitHub sees this computer's IP address when it does (nothing else is "
                   "sent).\n\nTurn it on?")):
            w["auto"].set(False)
        config.set_setting("auto_update_check", bool(w["auto"].get()))

    def on_clear_log():
        if messagebox.askyesno(tr("清除紀錄檔", "Clear log"),
                               tr("紀錄檔記錄了偵測到的檔案與程式。確定要清除嗎？",
                                  "The log lists the files and programs that were detected. Clear it?")):
            ok = storage.clear_log()
            write(tr("紀錄檔已清除。", "The log was cleared.") if ok else
                  tr("[失敗] 有部分紀錄檔正在使用中，沒有清除。", "[Failed] Part of the log is in use and was not cleared."),
                  None if ok else "err")

    def on_lang():
        config.set_lang("en" if config.LANG == "zh" else "zh")
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

    def work_area_height() -> int:
        """Height of the screen without the taskbar."""
        try:
            rect = (ctypes.c_long * 4)()
            if ctypes.windll.user32.SystemParametersInfoW(0x30, 0, ctypes.byref(rect), 0):  # SPI_GETWORKAREA
                return rect[3] - rect[1]
        except Exception:
            pass
        return root.winfo_screenheight()

    def center():
        root.update_idletasks()  # center the window, slightly above the middle, and above the taskbar
        free = work_area_height() - root.winfo_height() - px(50)  # (50: title bar and frame)
        root.geometry(f"+{(root.winfo_screenwidth() - root.winfo_width()) // 2}+{max(0, free // 3)}")

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
        tk.Label(top, text=f"v{config.VERSION}", font=("Segoe UI", 10), fg="#94a3b8",
                 bg=C["header"]).pack(side="left", anchor="s", padx=(px(8), 0), pady=(0, px(4)))
        body = tk.Frame(frame, bg=C["bg"])
        body.pack(fill="both", padx=px(28), pady=(px(22), px(26)))
        tk.Label(body, text="Choose your language", font=("Segoe UI", 13, "bold"), fg=C["text"],
                 bg=C["bg"]).pack(anchor="w")
        tk.Label(body, text="請選擇介面語言", font=("Microsoft JhengHei UI", 11), fg=C["muted"],
                 bg=C["bg"]).pack(anchor="w", pady=(px(2), px(16)))

        def pick(lang):
            config.set_lang(lang)
            show_panel()

        default = config.system_lang()
        for lang, text, font in (("en", "English", "Segoe UI"), ("zh", "中文(繁體)", "Microsoft JhengHei UI")):
            rim, b = make_button(body, text, lambda lang=lang: pick(lang),
                                 "primary" if lang == default else "secondary")
            b.config(font=(font, 13), pady=px(10), width=24)
            rim.pack(fill="x", pady=(0, px(10)))
        tk.Label(body, text="You can change this later in the control panel.\n之後可以在控制台右上角切換。",
                 font=("Microsoft JhengHei UI", 9), fg=C["muted"], bg=C["bg"],
                 justify="left").pack(anchor="w", pady=(px(4), 0))

    PAGES = ("home", "protection", "tools", "settings")

    def show_panel():
        """Show the control panel at one fixed size that fits every page in both languages (English text is
        wider), so switching the page or the language doesn't resize the window."""
        chosen, sizes = config.LANG, []
        root.withdraw()
        for lang in ("en", "zh"):
            config.LANG = lang
            build()
            for page in PAGES:
                show_page(page)
                root.update_idletasks()
                sizes.append((root.winfo_reqwidth(), root.winfo_reqheight()))
        config.LANG = chosen
        w["page"] = "home"
        build()
        # a taller screen gives the progress area a few more lines (the self-check reports a dozen)
        height = max(s[1] for s in sizes)
        height += max(0, min(px(100), work_area_height() - px(50) - height))  # (50: title bar and frame)
        root.geometry(f"{max(s[0] for s in sizes)}x{height}")
        refresh()
        center()
        root.deiconify()
        set_window_icons(root, icon)
        if auto_update:  # opened from the "new version available" prompt
            root.after(300, lambda: run_bg(install.install))
        elif config.auto_update_check():  # only if the user allowed it: GitHub sees this computer's IP address
            threading.Thread(target=lambda: q.put(("update", updates.check_for_update())), daemon=True).start()

    def build():
        """The whole window: header, the current page, and the progress area under it."""
        if "frame" in w:
            w["frame"].destroy()
        buttons.clear()
        pw.clear()
        # one font for both languages (JhengHei has its own Latin letters): with the same line heights
        # every row stays exactly where it is when the language is switched
        w["font"] = FONT = "Microsoft JhengHei UI"
        root.title(tr("RansomGuard 控制台", "RansomGuard Control Panel"))
        w["frame"] = frame = tk.Frame(root, bg=C["bg"])
        frame.pack(fill="both", expand=True)

        hdr = tk.Frame(frame, bg=C["header"])
        hdr.pack(fill="x")
        top = tk.Frame(hdr, bg=C["header"])
        top.pack(fill="x", padx=px(22), pady=(px(12), 0))
        tk.Label(top, text="RansomGuard", font=(FONT, 17, "bold"), fg="#ffffff",
                 bg=C["header"]).pack(side="left")
        tk.Label(top, text=f"v{config.VERSION}", font=(FONT, 10), fg="#94a3b8",
                 bg=C["header"]).pack(side="left", anchor="s", padx=(px(8), 0), pady=(0, px(4)))
        # language switch: the button shows the *other* language
        rim, b = make_button(top, tr("English", "中文(繁體)"), on_lang, "header")
        b.config(font=(FONT, 10), padx=px(10), pady=px(2), width=10)  # same width in both languages
        rim.pack(side="right")
        tk.Label(hdr, text=tr("偵測勒索病毒行為，發現異常時自動切斷網路",
                              "Detects ransomware behavior and cuts off the network automatically"),
                 font=(FONT, 10), fg="#cbd5e1", bg=C["header"]).pack(anchor="w", padx=px(22), pady=(px(2), px(12)))

        body = tk.Frame(frame, bg=C["bg"])
        body.pack(fill="both", expand=True, padx=px(22), pady=(px(16), px(14)))
        w["host"] = tk.Frame(body, bg=C["bg"])  # the page
        w["host"].pack(fill="x")

        # progress of what the user does (not the log file), the same on every page; it takes up the room the page
        # leaves in the fixed-size window
        bar = tk.Frame(body, bg=C["bg"])
        bar.pack(fill="x", pady=(px(14), px(4)))
        tk.Label(bar, text=tr("執行進度", "Progress"), font=(FONT, 9, "bold"), fg=C["muted"],
                 bg=C["bg"]).pack(side="left")
        w["busy"] = tk.Label(bar, text=tr("執行中...", "Working...") if w.get("working") else "", font=(FONT, 9),
                             fg=C["ok"], bg=C["bg"])
        w["busy"].pack(side="right")
        w["out"] = out = scrolledtext.ScrolledText(
            body, width=56, height=3, font=(FONT, 10), wrap="word", relief="flat", bd=0,
            bg=C["card"], fg=C["text"], highlightthickness=1, highlightbackground=C["border"],
            highlightcolor=C["border"], padx=px(10), pady=px(8))
        out.pack(fill="both", expand=True)
        out.tag_config("hint", foreground=C["muted"])
        out.tag_config("err", foreground=C["bad"])
        if not w["lines"] or w.get("intro"):
            intro()  # (again in the new language)
        else:
            lines, w["lines"] = w["lines"], []
            for msg, tag in lines:
                write(msg, tag)
        show_page(w["page"])

    def show_page(name):
        """Put a page in the window: the home page, or the details of one of its rows."""
        w["page"] = name
        for child in w["host"].winfo_children():
            child.destroy()
        pw.clear()
        buttons[:] = [b for b in buttons if b.winfo_exists()]
        {"home": page_home, "protection": page_protection, "tools": page_tools,
         "settings": page_settings}[name](w["host"])
        if "status" in w:  # what is already known shows at once
            show_status(w["status"])
        if "backup" in w:
            show_backup(w["backup"])

    def page_home(host):
        """One status, the one thing to do now, and the rows that lead to everything else."""
        F = w["font"]
        card = tk.Frame(host, bg=C["card"], highlightthickness=1, highlightbackground=C["border"])
        card.pack(fill="x")
        inner = tk.Frame(card, bg=C["card"])
        inner.pack(fill="x", padx=px(20), pady=(px(16), px(18)))
        line = tk.Frame(inner, bg=C["card"])
        line.pack(fill="x")
        dot = tk.Label(line, text="●", font=(F, 15), fg=C["off"], bg=C["card"])
        dot.pack(side="left")
        title = tk.Label(line, text=tr("讀取中...", "Loading..."), font=(F, 17, "bold"), fg=C["text"], bg=C["card"])
        title.pack(side="left", padx=(px(6), 0))
        # two lines tall, so a note that wraps in one language doesn't move what is under it
        note = tk.Label(inner, text=" ", font=(F, 10), fg=C["muted"], bg=C["card"], anchor="nw", justify="left",
                        height=2, wraplength=px(430))
        note.pack(fill="x", pady=(px(4), px(10)))
        rim, action = make_button(inner, "…", lambda: None, "secondary")
        action.config(state="disabled", padx=px(18))
        rim.pack(anchor="w")
        pw["hero"] = (dot, title, note, action)

        menu = tk.Frame(host, bg=C["card"], highlightthickness=1, highlightbackground=C["border"])
        menu.pack(fill="x", pady=(px(14), 0))
        new = w.get("new")
        rows = (
            (tr("防護", "Protection"), tr("監控、暫停、恢復網路", "Monitoring, pause, restore network"), None,
             lambda: show_page("protection")),
            (tr("備份", "Backup"), tr("讀取中...", "Loading..."), "backup", on_backup),
            (tr("工具", "Tools"), tr(f"有新版本 v{new}", f"Version {new} is available") if new else
             tr("自我檢查、更新、紀錄檔", "Self-check, updates, log"), "new" if new else None, lambda: show_page("tools")),
            (tr("設定", "Settings"), tr("監控的資料夾、自動更新、解除安裝", "Watched folders, automatic updates, uninstall"),
             None, lambda: show_page("settings")))
        # the names take the width of the longest one, so the summaries line up from row to row
        name_width = max(tkfont.Font(family=w["font"], size=11, weight="bold").measure(r[0]) for r in rows)
        for i, (name, summary, kind, open_it) in enumerate(rows):
            if i:
                tk.Frame(menu, bg=C["border"], height=1).pack(fill="x", padx=px(16))
            menu_row(menu, name, summary, kind, open_it, name_width)

    def menu_row(menu, name, summary, kind, open_it, name_width):
        """A row of the home page: name, a short summary, ›. The whole row opens it, and the whole row (padding
        included) turns gray under the mouse: one frame holds it all."""
        F, hover = w["font"], "#f5f7fb"
        row = tk.Frame(menu, bg=C["card"])
        row.pack(fill="x")
        row.columnconfigure(1, weight=1)
        row.columnconfigure(0, minsize=name_width + px(30))
        # (no padding or border of its own: its width is then exactly the measured one)
        label = tk.Label(row, text=name, font=(F, 11, "bold"), fg=C["text"], bg=C["card"], anchor="w", bd=0, padx=0)
        label.grid(row=0, column=0, sticky="w", padx=(px(18), px(12)), pady=px(11))
        mid = tk.Frame(row, bg=C["card"])
        mid.grid(row=0, column=1, sticky="w")
        parts = [row, label, mid]
        if kind == "backup":  # its state, with a light
            dot = tk.Label(mid, text="●", font=(F, 10), fg=C["off"], bg=C["card"])
            dot.pack(side="left")
            parts.append(dot)
        text = tk.Label(mid, text=summary, font=(F, 10), bg=C["card"], fg="#2563eb" if kind == "new" else C["muted"])
        text.pack(side="left", padx=(px(4), 0) if kind == "backup" else 0)
        parts.append(text)
        if kind == "backup":
            pw["backup"] = (dot, text)
        arrow = tk.Label(row, text="›", font=(F, 15), fg=C["muted"], bg=C["card"])
        arrow.grid(row=0, column=2, sticky="e", padx=(px(8), px(18)))
        parts.append(arrow)
        label.rg_text, label.rg_open = name, open_it  # (lets a screenshot script open it)

        def follow_mouse(_=None):
            # moving between the parts of the row leaves one and enters the next: look where the mouse is now,
            # so the row doesn't blink white in between
            def paint():
                if not row.winfo_exists():
                    return
                under = str(row.winfo_containing(*row.winfo_pointerxy()) or "")
                # the row itself or a part inside it; not just the same start (".!frame" is not ".!frame3")
                inside = under == str(row) or under.startswith(str(row) + ".")
                color = hover if inside else C["card"]
                if row.cget("bg") != color:
                    for p in parts:
                        p.config(bg=color)
            row.after_idle(paint)
        for p in parts:
            p.config(cursor="hand2")
            p.bind("<Button-1>", lambda _: open_it())
            p.bind("<Enter>", follow_mouse)
            p.bind("<Leave>", follow_mouse)

    def nb(text):
        """Chinese text with no-break spaces: Tk breaks lines at spaces, and in Chinese the only ones are those
        around Latin words and numbers ("30 分鐘或 2 小時" broke after the 2)."""
        return text.replace(" ", " ") if config.LANG == "zh" else text

    def page_title(host, title):
        row = tk.Frame(host, bg=C["bg"])
        row.pack(fill="x", pady=(0, px(4)))
        rim, b = make_button(row, tr("‹ 返回", "‹ Back"), lambda: show_page("home"), "link", track=False)
        b.config(font=(w["font"], 10), padx=px(8), pady=px(2))
        rim.pack(side="left")
        heading = tk.Label(row, text=title, font=(w["font"], 13, "bold"), fg=C["text"], bg=C["bg"])
        heading.pack(side="left", padx=(px(8), 0))

    def item(host, key, text, cmd, about, name="secondary", pair=None):
        """A button (or two side by side) with what it does written under it."""
        row = tk.Frame(host, bg=C["bg"])
        row.pack(fill="x", pady=(px(10), 0))
        for i, (k, t, c) in enumerate([(key, text, cmd)] + ([pair] if pair else [])):
            rim, pw[k] = make_button(row, t, c, name)
            if pair:
                row.columnconfigure(i, weight=1, uniform="pair")
                rim.grid(row=0, column=i, sticky="ew", padx=(0, px(4)) if i == 0 else (px(4), 0))
            else:
                rim.pack(fill="x")
        tk.Label(host, text=nb(about), font=(w["font"], 9), fg=C["muted"], bg=C["bg"], anchor="w", justify="left",
                 wraplength=px(470)).pack(fill="x", pady=(px(3), 0))

    def page_protection(host):
        page_title(host, tr("防護", "Protection"))
        item(host, "install", tr("安裝並開始監控", "Install and start monitoring"), on_install,
             tr("用目前這個版本安裝並開始背景監控，之後每次登入都會自動啟動。不會連網。",
                "Installs background monitoring with this version and starts it; it starts every time you sign in. "
                "Doesn't connect to the internet."))
        item(host, "stop", tr("暫停／停止監控", "Pause or stop monitoring"), on_stop,
             tr("大量整理檔案前暫停檔案偵測 30 分鐘或 2 小時（誘餌檔照常監控），或停止監控到重新開機。",
                "Pauses file detection for 30 minutes or 2 hours before bulk work (canary files are still watched), "
                "or stops monitoring until Windows restarts."))
        item(host, "restore", tr("恢復網路並重新開啟監控", "Restore network and restart monitoring"), on_restore,
             tr("誤判後使用：恢復網路與被暫停的程式（先經 Defender 檢查），並重新開始監控。",
                "After a false alarm: turns the network back on, resumes paused programs Defender finds clean and "
                "restarts monitoring."))

    def page_tools(host):
        page_title(host, tr("工具", "Tools"))
        item(host, "selfcheck", tr("自我檢查", "Self-check"), on_selfcheck,
             tr("確認防護真的在運作，並在暫存資料夾演練一次（不會斷網）。約 10 秒。",
                "Makes sure protection really works, with a drill in a temporary folder (the network isn't cut). "
                "About 10 seconds."))
        item(host, "update", update_label(), lambda: run_bg(lambda rep: w.__setitem__("offer", updates.check_updates(rep))),
             tr("連到 GitHub 檢查有沒有新版本，有的話會詢問是否更新。", "Asks GitHub whether there is a newer version and "
                "offers to update if there is."), "primary" if w.get("new") else "secondary")
        item(host, "preview", tr("預覽警告畫面", "Preview warning"), on_preview,
             tr("顯示觸發時的全螢幕警告，不會切斷網路。", "Shows the full-screen warning, without cutting the network."))
        item(host, "log", tr("開啟紀錄檔", "Open log"), on_log,
             tr("紀錄檔記錄偵測到的檔案與程式，保留 30 天。", "The log lists detected files and programs, kept for 30 days."),
             pair=("clear", tr("清除紀錄檔", "Clear log"), on_clear_log))

    def page_settings(host):
        page_title(host, tr("設定", "Settings"))
        item(host, "folders", tr("監控的資料夾…", "Watched folders…"), on_watch_folders,
             tr("除了桌面、文件、圖片、下載、影片、音樂，另外加入要監控的資料夾，例如 D 槽、隨身碟或 NAS。",
                "Besides Desktop, Documents, Pictures, Downloads, Videos and Music, add folders to watch, such as "
                "another drive, a USB drive or a NAS."))
        def check(text, value, command, about):
            """A setting that is on or off, with what it does written under it."""
            var = tk.BooleanVar(value=value)
            row = tk.Frame(host, bg=C["bg"])
            row.pack(fill="x", pady=(px(14), 0))
            tk.Checkbutton(row, text=text, variable=var, command=command, font=(w["font"], 11), fg=C["text"],
                           bg=C["bg"], activebackground=C["bg"], selectcolor=C["card"], highlightthickness=0, bd=0,
                           cursor="hand2").pack(side="left")
            tk.Label(host, text=nb(about), font=(w["font"], 9), fg=C["muted"], bg=C["bg"], anchor="w",
                     justify="left", wraplength=px(470)).pack(fill="x", pady=(px(3), 0))
            return var

        w["auto"] = check(tr("自動檢查新版本", "Check for updates automatically"), config.auto_update_check(),
                          on_auto_update,
                          tr("每 6 小時以及開啟控制台時連到 GitHub 檢查新版本；GitHub 會看到這台電腦的 IP 位址。預設關閉。",
                             "Asks GitHub for new versions every 6 hours and when the control panel opens; GitHub "
                             "sees this computer's IP address. Off by default."))
        w["tray"] = check(tr("網路被切斷時在時鐘旁顯示提示", "Show a notice by the clock when the network is cut"),
                          tray.tray_enabled(), lambda: config.set_setting("tray_icon", bool(w["tray"].get())),
                          tr("偵測到疑似勒索病毒、網路被切斷時，時鐘旁會出現紅點盾牌和通知，點它開啟控制台查看偵測報告。"
                             "平常（包括暫停偵測時）不會出現。",
                             "When possible ransomware is detected and the network is cut, a shield with a red dot and a "
                             "notification appear by the clock; click for the control panel and the detection report. "
                             "Nothing shows otherwise, also while detection is paused."))
        item(host, "uninstall", tr("解除安裝", "Uninstall"), on_uninstall,
             tr("移除背景監控、捷徑、誘餌檔、程式資料夾，以及紀錄檔和設定。",
                "Removes background monitoring, the shortcut, the canary files, the program folder, and the log "
                "and settings."), "danger")

    root.protocol("WM_DELETE_WINDOW", on_close)
    if config._LANG_ARG or config.saved_lang():
        show_panel()
    else:
        choose_lang()
        center()
        root.after(100, lambda: set_window_icons(root, icon))  # after Tk has shown (mapped) the window
    pump()
    root.mainloop()
