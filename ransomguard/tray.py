"""The background monitor's notification-area icon. Its dot says the state - green protected, orange file
detection paused, red network cut - and so does its tooltip; a click opens the control panel, its menu can pause
file detection. The monitor shows it itself, so no icon means no monitoring. It never blinks, and it can be
turned off in the control panel's settings."""
import ctypes
import os
import subprocess
import sys
import threading
import time
from ctypes import wintypes

from . import config, install, storage
from .config import log, tr


def tray_enabled() -> bool:
    """Shown unless the user turned it off in the control panel."""
    return config.load_settings().get("tray_icon") is not False


def tray_state(paused_until: float, cut: bool, now=None):
    """(icon: ok / paused / cut, tooltip). A cut network comes first."""
    now = time.time() if now is None else now
    if cut:
        return "cut", tr("RansomGuard：網路已切斷", "RansomGuard: network cut off")
    if paused_until > now:
        at = time.strftime("%H:%M", time.localtime(paused_until))
        return "paused", tr(f"RansomGuard：檔案偵測暫停到 {at}", f"RansomGuard: file detection paused until {at}")
    return "ok", tr("RansomGuard：已受到保護", "RansomGuard: protected")


def tray_icon_file(state: str) -> str:
    """tray-<state>.ico: packed into the exe, or next to the program folder when run from source."""
    base = getattr(sys, "_MEIPASS", None) or str(config.ROOT)
    return os.path.join(base, f"tray-{state}.ico")


def open_control_panel():
    """The control panel; it runs with this monitor's administrator rights, so no prompt appears."""
    if config.FROZEN:
        install.spawn_installed("--gui")  # the installed exe, as a fresh program
    else:
        exe, args = install.launcher()
        subprocess.Popen(f'"{exe}" {args} --gui', cwd=str(config.ROOT))


class _NOTIFYICONDATAW(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.DWORD), ("hWnd", wintypes.HWND), ("uID", wintypes.UINT),
                ("uFlags", wintypes.UINT), ("uCallbackMessage", wintypes.UINT), ("hIcon", wintypes.HICON),
                ("szTip", wintypes.WCHAR * 128), ("dwState", wintypes.DWORD), ("dwStateMask", wintypes.DWORD),
                ("szInfo", wintypes.WCHAR * 256), ("uVersion", wintypes.UINT), ("szInfoTitle", wintypes.WCHAR * 64),
                ("dwInfoFlags", wintypes.DWORD), ("guidItem", ctypes.c_byte * 16), ("hBalloonIcon", wintypes.HICON)]


_LRESULT = ctypes.c_ssize_t
_WNDPROC = ctypes.WINFUNCTYPE(_LRESULT, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)


class _WNDCLASSEXW(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.UINT), ("style", wintypes.UINT), ("lpfnWndProc", _WNDPROC),
                ("cbClsExtra", ctypes.c_int), ("cbWndExtra", ctypes.c_int), ("hInstance", wintypes.HINSTANCE),
                ("hIcon", wintypes.HICON), ("hCursor", wintypes.HANDLE), ("hbrBackground", wintypes.HBRUSH),
                ("lpszMenuName", wintypes.LPCWSTR), ("lpszClassName", wintypes.LPCWSTR), ("hIconSm", wintypes.HICON)]


def _user32():
    """user32 and shell32 with the signatures used here (handles are pointer-sized)."""
    u, s = ctypes.WinDLL("user32", use_last_error=True), ctypes.WinDLL("shell32", use_last_error=True)
    H, U, P = wintypes.HANDLE, wintypes.UINT, ctypes.c_void_p
    for dll, name, res, args in (
            (u, "RegisterClassExW", wintypes.ATOM, [ctypes.POINTER(_WNDCLASSEXW)]),
            (u, "CreateWindowExW", wintypes.HWND, [wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
                                                   ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                                   wintypes.HWND, wintypes.HMENU, wintypes.HINSTANCE, P]),
            (u, "DefWindowProcW", _LRESULT, [wintypes.HWND, U, wintypes.WPARAM, wintypes.LPARAM]),
            (u, "DestroyWindow", wintypes.BOOL, [wintypes.HWND]),
            (u, "GetMessageW", wintypes.BOOL, [ctypes.POINTER(wintypes.MSG), wintypes.HWND, U, U]),
            (u, "TranslateMessage", wintypes.BOOL, [ctypes.POINTER(wintypes.MSG)]),
            (u, "DispatchMessageW", _LRESULT, [ctypes.POINTER(wintypes.MSG)]),
            (u, "PostMessageW", wintypes.BOOL, [wintypes.HWND, U, wintypes.WPARAM, wintypes.LPARAM]),
            (u, "PostQuitMessage", None, [ctypes.c_int]),
            (u, "RegisterWindowMessageW", U, [wintypes.LPCWSTR]),
            (u, "ChangeWindowMessageFilterEx", wintypes.BOOL, [wintypes.HWND, U, wintypes.DWORD, P]),
            (u, "SetTimer", ctypes.c_size_t, [wintypes.HWND, ctypes.c_size_t, U, P]),
            (u, "LoadImageW", H, [wintypes.HINSTANCE, wintypes.LPCWSTR, U, ctypes.c_int, ctypes.c_int, U]),
            (u, "DestroyIcon", wintypes.BOOL, [wintypes.HICON]),
            (u, "GetSystemMetrics", ctypes.c_int, [ctypes.c_int]),
            (u, "CreatePopupMenu", wintypes.HMENU, []),
            (u, "AppendMenuW", wintypes.BOOL, [wintypes.HMENU, U, ctypes.c_size_t, wintypes.LPCWSTR]),
            (u, "SetMenuDefaultItem", wintypes.BOOL, [wintypes.HMENU, U, U]),
            (u, "TrackPopupMenu", ctypes.c_int, [wintypes.HMENU, U, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                                 wintypes.HWND, P]),
            (u, "DestroyMenu", wintypes.BOOL, [wintypes.HMENU]),
            (u, "GetCursorPos", wintypes.BOOL, [ctypes.POINTER(wintypes.POINT)]),
            (u, "SetForegroundWindow", wintypes.BOOL, [wintypes.HWND]),
            (s, "Shell_NotifyIconW", wintypes.BOOL, [wintypes.DWORD, ctypes.POINTER(_NOTIFYICONDATAW)])):
        fn = getattr(dll, name)
        fn.restype, fn.argtypes = res, args
    return u, s


class Tray:
    """The icon, run by a thread of its own with a hidden window that receives its clicks."""
    CALLBACK = 0x8000 + 1  # WM_APP + 1: what the icon sends the window
    REFRESH_MS = 2000      # how often the state is looked at (the icon changes only when it does)
    OPEN, PAUSE, RESUME = 1, 2, 3  # menu commands

    def __init__(self, state):
        """state(): the current (icon, tooltip), as tray_state() gives it."""
        self.state = state
        self.hwnd = None
        self.shown = None      # the (icon, tooltip) on screen; None while there is no icon
        self.icons = {}
        self.ready = threading.Event()
        self.thread = None
        self.taskbar_created = -1  # set once the window exists (creating it already calls _wndproc)
        self.opened = 0.0          # when a click last opened the control panel

    def start(self):
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        self.ready.wait(5)

    def stop(self):
        if self.hwnd:
            self.user32.PostMessageW(self.hwnd, 0x0010, 0, 0)  # WM_CLOSE: the thread takes the icon down
        if self.thread:
            self.thread.join(5)

    # ---- on the icon's own thread
    def _run(self):
        try:
            self.user32, self.shell32 = _user32()
            self._proc = _WNDPROC(self._wndproc)  # kept: the window calls it
            cls = _WNDCLASSEXW(cbSize=ctypes.sizeof(_WNDCLASSEXW), lpfnWndProc=self._proc,
                               lpszClassName=f"RansomGuardTray{os.getpid()}")
            if not self.user32.RegisterClassExW(ctypes.byref(cls)):
                raise OSError(ctypes.get_last_error(), "RegisterClassExW")
            # a hidden top-level window (not a message-only one: those don't get TaskbarCreated)
            self.hwnd = self.user32.CreateWindowExW(0, cls.lpszClassName, "RansomGuard", 0, 0, 0, 0, 0,
                                                    None, None, None, None)
            if not self.hwnd:
                raise OSError(ctypes.get_last_error(), "CreateWindowExW")
            self.taskbar_created = self.user32.RegisterWindowMessageW("TaskbarCreated")
            # the monitor runs with administrator rights and Explorer without: Windows (UIPI) would hold back the
            # icon's clicks and the taskbar-restarted message unless this window lets just those two in
            for allowed in (self.CALLBACK, self.taskbar_created):
                self.user32.ChangeWindowMessageFilterEx(self.hwnd, allowed, 1, None)  # MSGFLT_ALLOW
            size = self.user32.GetSystemMetrics(49)  # SM_CXSMICON: already scaled for the display
            for name in ("ok", "paused", "cut"):
                # IMAGE_ICON, LR_LOADFROMFILE
                self.icons[name] = self.user32.LoadImageW(None, tray_icon_file(name), 1, size, size, 0x10)
            self._refresh()
            self.user32.SetTimer(self.hwnd, 1, self.REFRESH_MS, None)
        except Exception:
            log.exception(tr("無法顯示通知區域圖示", "Could not show the notification-area icon"))
            self.ready.set()
            return
        self.ready.set()
        msg = wintypes.MSG()
        while self.user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            self.user32.TranslateMessage(ctypes.byref(msg))
            self.user32.DispatchMessageW(ctypes.byref(msg))
        self._notify(2)  # NIM_DELETE
        for icon in self.icons.values():
            if icon:
                self.user32.DestroyIcon(icon)

    def _notify(self, what, icon=None, tip="") -> bool:
        """NIM_ADD (0), NIM_MODIFY (1) or NIM_DELETE (2) the icon."""
        data = _NOTIFYICONDATAW(cbSize=ctypes.sizeof(_NOTIFYICONDATAW), hWnd=self.hwnd, uID=1)
        if what != 2:
            data.uFlags = 0x1 | 0x2 | 0x4  # NIF_MESSAGE | NIF_ICON | NIF_TIP
            data.uCallbackMessage, data.hIcon, data.szTip = self.CALLBACK, self.icons.get(icon), tip[:127]
        ok = bool(self.shell32.Shell_NotifyIconW(what, ctypes.byref(data)))
        if what == 2:
            self.shown = None
        return ok

    def _refresh(self, again=False):
        """Show, change or remove the icon as the state and the setting say; again: Explorer restarted and the icon
        has to be added anew."""
        if not tray_enabled():
            if self.shown:
                self._notify(2)
            return
        config.init_lang()  # the language most recently chosen in the control panel
        now = self.state()
        if self.shown is None or again:
            if self._notify(0, *now):
                self.shown = now
        elif now != self.shown and self._notify(1, *now):
            self.shown = now

    def _menu(self):
        menu = self.user32.CreatePopupMenu()
        try:
            self.user32.AppendMenuW(menu, 0, self.OPEN, tr("開啟控制台", "Open the control panel"))
            self.user32.SetMenuDefaultItem(menu, self.OPEN, 0)
            self.user32.AppendMenuW(menu, 0x800, 0, None)  # MF_SEPARATOR
            if storage.detection_paused_until():
                self.user32.AppendMenuW(menu, 0, self.RESUME, tr("立即恢復偵測", "Resume detection now"))
            else:
                self.user32.AppendMenuW(menu, 0, self.PAUSE, tr("暫停檔案偵測 30 分鐘", "Pause file detection for 30 minutes"))
            pos = wintypes.POINT()
            self.user32.GetCursorPos(ctypes.byref(pos))
            self.user32.SetForegroundWindow(self.hwnd)  # or the menu doesn't close when clicking elsewhere
            # TPM_RETURNCMD | TPM_NONOTIFY | TPM_RIGHTBUTTON: returns the chosen command
            return self.user32.TrackPopupMenu(menu, 0x100 | 0x80 | 0x2, pos.x, pos.y, 0, self.hwnd, None)
        finally:
            self.user32.DestroyMenu(menu)

    def _do(self, command):
        if command == self.OPEN:
            if time.monotonic() - self.opened > 3:  # a double click opens it once
                self.opened = time.monotonic()
                open_control_panel()
        elif command == self.PAUSE:
            storage.pause_detection(30)
        elif command == self.RESUME:
            storage.resume_detection()
        self._refresh()

    def _wndproc(self, hwnd, msg, wparam, lparam):
        try:
            if msg == self.CALLBACK:
                event = lparam & 0xFFFF
                if event == 0x0202:  # WM_LBUTTONUP: open the control panel
                    self._do(self.OPEN)
                elif event == 0x0205:  # WM_RBUTTONUP: the menu
                    self._do(self._menu())
                return 0
            if msg == 0x0113:  # WM_TIMER
                self._refresh()
                return 0
            if msg == self.taskbar_created:  # Explorer restarted: every icon is gone
                self._refresh(again=True)
                return 0
            if msg == 0x0010:  # WM_CLOSE
                self.user32.DestroyWindow(hwnd)
                return 0
            if msg == 0x0002:  # WM_DESTROY
                self.user32.PostQuitMessage(0)
                return 0
        except Exception:
            log.exception(tr("通知區域圖示發生錯誤", "Error in the notification-area icon"))
        return self.user32.DefWindowProcW(hwnd, msg, wparam, lparam)
