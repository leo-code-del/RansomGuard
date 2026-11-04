"""The control panel window."""
import ctypes
import os
import subprocess
import sys
import threading
from pathlib import Path

from . import canary, config, folders, install, network, response, storage, updates, winapi
from .config import log, tr
from .winapi import norm


def status_info():
    """The control panel's two status cards: ((text, light, note), (text, light, note));
    light is ok / warn / bad / off."""
    s = install.task_state()
    unprotected = tr("目前沒有勒索病毒防護", "No ransomware protection right now")
    mon = {"Running": (tr("執行中", "Running"), "ok",
                       tr("每次登入 Windows 都會自動啟動", "Starts every time you sign in to Windows")),
           "Ready": (tr("已停止", "Stopped"), "warn", unprotected),
           "Disabled": (tr("已停用", "Disabled"), "warn", unprotected),
           "": (tr("尚未安裝", "Not installed"), "off",
                tr("按「安裝並開始監控」", "Click \"Install and start monitoring\""))
           }.get(s, (s, "warn", ""))
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
         "ok": "#16a34a", "warn": "#d97706", "bad": "#dc2626", "off": "#9ca3af"}
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
    w = {}  # widgets on screen now; the whole window is rebuilt when the language changes

    def make_button(parent, text, cmd, name, tip_text=None, track=True):
        """track: disable it while an action runs (not for buttons of a dialog, which may be gone by then)."""
        rim = tk.Frame(parent)  # 1px border (a tk button's own border can only be black on Windows)
        b = tk.Button(rim, text=text, command=cmd, font=(w["font"], 11), relief="flat", bd=0,
                      highlightthickness=0, cursor="hand2", padx=px(12), pady=px(7))
        b.pack(fill="both", padx=1, pady=1)
        if track:
            buttons.append(b)

        # bound once and reading the current style, so restyling (show_status) doesn't stack handlers
        def enter(_):
            if str(b["state"]) == "normal":
                hover = STYLES[b.rg_style][1]
                b.config(bg=hover)
                rim.config(bg=C["border"] if b.rg_style == "secondary" else hover)
        b.bind("<Enter>", enter, add="+")
        b.bind("<Leave>", lambda _: style(b, b.rg_style), add="+")
        style(b, name)
        if tip_text:
            tip(b, tip_text)
        return rim, b

    def style(b, name):
        b.rg_style = name
        bg, hover, fg, dim = STYLES[name]
        b.master.config(bg=C["border"] if name == "secondary" else bg)
        b.config(bg=bg, fg=fg, activebackground=hover, activeforeground=fg, disabledforeground=dim)

    def tip(widget, text):
        """A short description shown while the mouse rests on a widget."""
        state = {}

        def show():
            state.pop("job", None)
            win = state["win"] = tk.Toplevel(root)
            win.wm_overrideredirect(True)
            win.wm_attributes("-topmost", True)
            tk.Label(win, text=text, font=(w["font"], 9), bg="#1f2937", fg="#f9fafb", justify="left",
                     wraplength=px(380), padx=px(9), pady=px(6)).pack()
            win.update_idletasks()
            x = min(widget.winfo_rootx() + px(10), widget.winfo_screenwidth() - win.winfo_width() - px(8))
            win.wm_geometry(f"+{x}+{widget.winfo_rooty() + widget.winfo_height() + px(4)}")

        def hide(_=None):
            if "job" in state:
                root.after_cancel(state.pop("job"))
            if "win" in state:
                state.pop("win").destroy()

        def enter(_):
            if "job" not in state and "win" not in state:
                state["job"] = root.after(600, show)
        widget.bind("<Enter>", enter, add="+")
        widget.bind("<Leave>", hide, add="+")
        widget.bind("<ButtonPress>", hide, add="+")

    def show_status(info):
        for (dot, val, detail), (text, level, note) in zip((w["mon"], w["net"]), info):
            dot.config(fg=C[level])
            val.config(text=text, fg=C["bad"] if level == "bad" else C["text"])
            detail.config(text=note or " ")
        # color only what needs the user now: restoring a cut network, starting monitoring that isn't running,
        # a newer version; when everything is fine no button stands out
        cut, running = info[1][1] == "bad", info[0][1] == "ok"
        style(w["install"], "primary" if not cut and not running else "secondary")
        style(w["update"], "primary" if w.get("new") and not cut else "secondary")
        style(w["restore"], "success" if cut else "secondary")

    def update_label():
        new = w.get("new")
        return tr(f"更新到 v{new}", f"Update to v{new}") if new else tr("檢查版本更新", "Check for updates")

    def offer_update(new):
        """A newer version is known (found by the automatic check or the button): name it, then ask."""
        w["new"] = new
        w["update"].config(text=update_label())
        style(w["update"], "primary")
        if messagebox.askyesno("RansomGuard", tr(
                f"有新版本 v{new}（目前是 v{config.VERSION}）。\n\n要現在更新嗎？\n"
                "選「否」會繼續用目前的版本監控，之後隨時可以再按「檢查版本更新」。",
                f"Version {new} is available (you have v{config.VERSION}).\n\nUpdate now?\n"
                "With \"No\" monitoring continues with this version; you can click \"Check for updates\" "
                "again any time.")):
            run_bg(install.install)

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
                elif kind == "update":  # the automatic check found a newer version when the window opened
                    if msg and not w.get("working"):
                        offer_update(msg)
                    elif msg:  # busy now: just name it on the button
                        w["new"] = msg
                        w["update"].config(text=update_label())
                else:
                    for b in buttons:
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
        if storage.network_cut(storage.load_state()) and not messagebox.askyesno(
                tr("恢復網路", "Restore network"),
                tr("請先確認這次是測試或誤判，而不是真的中了勒索病毒。\n\n確定要恢復網路嗎？",
                   "First make sure this was a test or a false alarm, not a real ransomware "
                   "infection.\n\nRestore the network?"),
                icon="warning"):
            return
        run_bg(network.restore_network)

    def on_stop():
        if messagebox.askyesno(tr("停止監控", "Stop monitoring"),
                               tr("停止後電腦就沒有勒索病毒防護，直到你按「安裝並開始監控」或重新開機。\n確定要停止嗎？",
                                  "This computer will have no ransomware protection until you click \"Install "
                                  "and start monitoring\" or restart Windows.\nStop monitoring?")):
            run_bg(lambda rep: (install.stop_monitor_until_restart(),
                                rep(tr("監控已停止，重新開機後會自動再啟動。",
                                       "Monitoring stopped. It starts again by itself when Windows restarts."))))

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
        label(tr("另外監控的資料夾（例如 D 槽、隨身碟、NAS）", "Also watched (e.g. another drive, a USB drive, a NAS)"),
              bold=True)
        lb = tk.Listbox(pad, font=(F, 10), height=6, width=54, relief="flat", bd=0, highlightthickness=1,
                        highlightbackground=C["border"], activestyle="none", selectbackground="#dbeafe",
                        selectforeground=C["text"])
        lb.pack(fill="x", pady=(px(4), px(8)))
        for d in folders.extra_watch_dirs():
            lb.insert("end", str(d))

        def add():
            path = filedialog.askdirectory(parent=dlg, title=title, mustexist=True)
            if not path:
                return
            path = os.path.normpath(path)
            problem = folders.watch_problem(path)
            if problem:
                messagebox.showwarning(title, f"{path}\n\n{problem}", parent=dlg)
            elif norm(path) not in {norm(p) for p in lb.get(0, "end")}:
                lb.insert("end", path)

        def remove():
            for i in reversed(lb.curselection()):
                lb.delete(i)
        row = tk.Frame(pad, bg=C["bg"])
        row.pack(fill="x")
        make_button(row, tr("新增資料夾…", "Add folder…"), add, "secondary", track=False)[0].pack(side="left")
        make_button(row, tr("移除", "Remove"), remove, "secondary", track=False)[0].pack(side="left", padx=(px(6), 0))
        label(tr("每個監控的資料夾都會放入隱藏的誘餌檔。儲存後背景監控會重新啟動。",
                 "Each watched folder gets hidden canary files. Saving restarts background monitoring."),
              muted=True, gap=(px(12), px(10)))

        def save():
            new = [Path(p) for p in lb.get(0, "end")]
            removed = [d for d in folders.extra_watch_dirs() if norm(d) not in {norm(n) for n in new}]
            dlg.destroy()

            def work(rep):
                folders.save_extra_watch_dirs(new)
                rep(tr(f"已儲存，另外監控 {len(new)} 個資料夾。", f"Saved: {len(new)} more folder(s) watched."))
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

    def show_panel():
        """Show the control panel at one fixed size that fits both languages (English text is wider),
        so switching the language doesn't resize the window or move anything in it."""
        chosen, sizes = config.LANG, []
        root.withdraw()
        for lang in ("en", "zh"):
            config.LANG = lang
            build()
            root.update_idletasks()
            sizes.append((root.winfo_reqwidth(), root.winfo_reqheight()))
        config.LANG = chosen
        build()
        root.geometry(f"{max(s[0] for s in sizes)}x{max(s[1] for s in sizes)}")
        refresh()
        center()
        root.deiconify()
        set_window_icons(root, icon)
        if auto_update:  # opened from the "new version available" prompt
            root.after(300, lambda: run_bg(install.install))
        elif config.auto_update_check():  # only if the user allowed it: GitHub sees this computer's IP address
            threading.Thread(target=lambda: q.put(("update", updates.check_for_update())), daemon=True).start()

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
        tk.Label(top, text=f"v{config.VERSION}", font=(FONT, 10), fg="#94a3b8",
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
                              anchor="nw", justify="left", wraplength=px(200))
            detail.pack(fill="x", padx=px(16), pady=(0, px(8)))
            # wrap at the card's real width: a fixed width cut long notes off when the window got narrower
            detail.bind("<Configure>", lambda e: detail.config(wraplength=max(e.width - px(2), px(80))))
            return dot, val, detail

        w["mon"] = card(0, tr("背景監控", "Background monitoring"))
        w["net"] = card(1, tr("網路", "Network"))

        def section(title):
            row = tk.Frame(body, bg=C["bg"])
            row.pack(fill="x", pady=(px(18), px(6)))
            tk.Label(row, text=title, font=(FONT, 10, "bold"), fg=C["muted"], bg=C["bg"]).pack(side="left")
            return row

        def grid(title, rows):
            """A titled group of buttons, two per row; a row with one button spans both columns.
            rows: [[(key, text, command, tooltip), ...], ...]; returns {key: button}."""
            section(title)
            g = tk.Frame(body, bg=C["bg"])
            g.pack(fill="x")
            g.columnconfigure((0, 1), weight=1, uniform="btn")
            made = {}
            for r, row in enumerate(rows):
                for c, (key, text, cmd, hint) in enumerate(row):
                    rim, made[key] = make_button(g, text, cmd, "secondary", hint)
                    rim.grid(row=r, column=c, columnspan=2 if len(row) == 1 else 1, sticky="ew",
                             pady=(0, px(8)), padx=(0, 0) if len(row) == 1 else ((0, px(4)) if c == 0 else (px(4), 0)))
            return made

        # protection: what keeps (or stops) the computer protected
        w.update(grid(tr("防護", "Protection"), [
            [("install", tr("安裝並開始監控", "Install and start monitoring"),
              lambda: run_bg(lambda rep: install.install(rep, update=False)),
              tr("用目前這個版本安裝並開始背景監控，不會連網。",
                 "Installs background monitoring with this version and starts it. Doesn't connect to the internet.")),
             ("stop", tr("停止監控", "Stop monitoring"), on_stop,
              tr("暫時停止背景監控，重新開機後會自動再啟動。",
                 "Stops background monitoring for now; it starts again when Windows restarts."))],
            [("restore", tr("恢復網路並重新開啟監控", "Restore network and restart monitoring"), on_restore,
              tr("誤判時使用：重新啟用網路、恢復 Defender 確認沒問題的被暫停程式，並重新開始監控。",
                 "After a false alarm: turns the network back on, resumes paused programs Defender finds clean "
                 "and restarts monitoring."))]]))
        # tools: everything else, each pair belongs together
        w.update(grid(tr("工具", "Tools"), [
            [("update", update_label(), lambda: run_bg(lambda rep: w.__setitem__("offer", updates.check_updates(rep))),
              tr("連到 GitHub 檢查有沒有新版本，有的話會詢問是否更新。", "Asks GitHub whether there is a newer version and "
                 "offers to update if there is.")),
             ("preview", tr("預覽警告畫面", "Preview warning"), on_preview,
              tr("顯示觸發時的全螢幕警告，不會切斷網路。", "Shows the full-screen warning, without cutting the network."))],
            [("log", tr("開啟紀錄檔", "Open log"), on_log,
              tr("紀錄檔記錄偵測到的檔案與程式，保留 30 天。", "The log lists detected files and programs, kept for 30 days.")),
             ("clear", tr("清除紀錄檔", "Clear log"), on_clear_log,
              tr("清空紀錄檔。", "Empties the log."))]]))

        # progress of the action that runs (not the log file)
        w["busy"] = tk.Label(section(tr("執行進度", "Progress")), text="", font=(FONT, 10),
                             fg=C["ok"], bg=C["bg"])
        w["busy"].pack(side="right")
        w["out"] = out = scrolledtext.ScrolledText(
            body, width=60, height=5, font=(FONT, 10), wrap="word", relief="flat", bd=0,
            bg=C["card"], fg=C["text"], highlightthickness=1, highlightbackground=C["border"],
            highlightcolor=C["border"], padx=px(10), pady=px(8))
        out.pack(fill="both", expand=True)  # takes up any spare room of the fixed-size window
        out.tag_config("hint", foreground=C["muted"])
        out.tag_config("err", foreground=C["bad"])
        write(tr("按上方按鈕執行操作，進度會顯示在這裡。滑鼠停在按鈕上可以看到說明。",
                 "Click a button above; progress is shown here. Rest the mouse on a button for what it does."),
              "hint")

        foot = tk.Frame(body, bg=C["bg"])
        foot.pack(fill="x", pady=(px(10), 0))
        w["auto"] = tk.BooleanVar(value=config.auto_update_check())
        cb = tk.Checkbutton(foot, text=tr("自動檢查新版本", "Check for updates automatically"), variable=w["auto"],
                            command=on_auto_update, font=(FONT, 10), fg=C["text"], bg=C["bg"],
                            activebackground=C["bg"], selectcolor=C["card"], highlightthickness=0, bd=0,
                            cursor="hand2")
        cb.pack(side="left")
        rim, b = make_button(foot, tr("監控的資料夾…", "Watched folders…"), on_watch_folders, "link",
                             tr("加入其他要監控的資料夾，例如 D 槽、隨身碟或 NAS。", "Add more folders to watch, such as "
                                "another drive, a USB drive or a NAS."))
        b.config(font=(FONT, 10), padx=px(8), pady=px(4))
        rim.pack(side="left", padx=(px(10), 0))
        tip(cb, tr("開啟後，每 6 小時以及開啟控制台時會連到 GitHub 檢查新版本（GitHub 會看到這台電腦的 IP 位址）。預設關閉。",
                   "When on, RansomGuard asks GitHub for new versions every 6 hours and when the control panel "
                   "opens (GitHub sees this computer's IP address). Off by default."))
        rim, b = make_button(foot, tr("解除安裝", "Uninstall"), on_uninstall, "danger",
                             tr("移除背景監控、捷徑、誘餌檔、程式資料夾，以及紀錄檔和設定。",
                                "Removes background monitoring, the shortcut, the canary files, the program folder, "
                                "and the log and settings."))
        b.config(font=(FONT, 10), padx=px(10), pady=px(4), width=10)  # same width in both languages
        rim.pack(side="right")

    root.protocol("WM_DELETE_WINDOW", on_close)
    if config._LANG_ARG or config.saved_lang():
        show_panel()
    else:
        choose_lang()
        center()
        root.after(100, lambda: set_window_icons(root, icon))  # after Tk has shown (mapped) the window
    pump()
    root.mainloop()
