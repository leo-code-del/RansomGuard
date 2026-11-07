"""A notice by the clock while the network is cut: the background monitor puts a shield with a red dot in the
notification area, with a Windows notification when it appears; clicking either opens the control panel (with
the detection report). Normally, also while file detection is paused, nothing shows there. It never blinks, and
it can be turned off in the control panel's settings."""
import ctypes
import os
import subprocess
import sys
import threading
import time
from ctypes import wintypes

from . import config, install
from .config import log, tr


def tray_enabled() -> bool:
    """Shown (when the network is cut) unless the user turned it off in the control panel."""
    return config.load_settings().get("tray_icon") is not False


def tray_message(cut: bool):
    """What the notice says while the network is cut: (tooltip, notification title, notification text); None
    otherwise, when nothing shows."""
    if not cut:
        return None
    return (tr("RansomGuard：網路已切斷，點這裡開啟控制台", "RansomGuard: network cut off - click for the control panel"),
            tr("RansomGuard：網路已切斷", "RansomGuard: network cut off"),
            tr("偵測到疑似勒索病毒，網路已自動切斷。點這裡開啟控制台查看偵測報告。",
               "Possible ransomware was detected and the network was cut off. Click here to see the detection report "
               "in the control panel."))


def tray_icon_file() -> str:
    """tray-cut.ico: packed into the exe, or in the program folder when run from source."""
    base = getattr(sys, "_MEIPASS", None) or str(config.ROOT)
    return os.path.join(base, "tray-cut.ico")


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
            (s, "Shell_NotifyIconW", wintypes.BOOL, [wintypes.DWORD, ctypes.POINTER(_NOTIFYICONDATAW)])):
        fn = getattr(dll, name)
        fn.restype, fn.argtypes = res, args
    return u, s


class Tray:
    """The notice, run by a thread of its own with a hidden window that receives its clicks."""
    CALLBACK = 0x8000 + 1  # WM_APP + 1: what the icon sends the window
    REFRESH_MS = 2000      # how often the state is looked at

    def __init__(self, state):
        """state(): what to show now, as tray_message() gives it (None: nothing)."""
        self.state = state
        self.hwnd = None
        self.shown = None      # the message on screen; None while nothing shows
        self.icon = None
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

    # ---- on the notice's own thread
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
            self.icon = self.user32.LoadImageW(None, tray_icon_file(), 1, size, size, 0x10)  # IMAGE_ICON, from file
            self._refresh()
            self.user32.SetTimer(self.hwnd, 1, self.REFRESH_MS, None)
        except Exception:
            log.exception(tr("無法在時鐘旁顯示提示", "Could not show the notice by the clock"))
            self.ready.set()
            return
        self.ready.set()
        msg = wintypes.MSG()
        while self.user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            self.user32.TranslateMessage(ctypes.byref(msg))
            self.user32.DispatchMessageW(ctypes.byref(msg))
        self._notify(2)  # NIM_DELETE
        if self.icon:
            self.user32.DestroyIcon(self.icon)

    def _notify(self, what, message=None, announce=False) -> bool:
        """NIM_ADD (0), NIM_MODIFY (1) or NIM_DELETE (2) the icon; announce: with a Windows notification."""
        data = _NOTIFYICONDATAW(cbSize=ctypes.sizeof(_NOTIFYICONDATAW), hWnd=self.hwnd, uID=1)
        if what != 2:
            tip, title, text = message
            data.uFlags = 0x1 | 0x2 | 0x4  # NIF_MESSAGE | NIF_ICON | NIF_TIP
            data.uCallbackMessage, data.hIcon, data.szTip = self.CALLBACK, self.icon, tip[:127]
            if announce:
                data.uFlags |= 0x10  # NIF_INFO
                data.szInfoTitle, data.szInfo, data.dwInfoFlags = title[:63], text[:255], 0x2  # NIIF_WARNING
        ok = bool(self.shell32.Shell_NotifyIconW(what, ctypes.byref(data)))
        if what == 2:
            self.shown = None
        return ok

    def _refresh(self, again=False):
        """Show the notice when the network is cut (with a notification the first time), remove it otherwise;
        again: Explorer restarted, so it is added anew (without a second notification)."""
        config.init_lang()  # the language most recently chosen in the control panel
        message = self.state() if tray_enabled() else None
        if message is None:
            if self.shown:
                self._notify(2)
            return
        if self.shown is None or again:
            if self._notify(0, message, announce=not again):
                self.shown = message
        elif message != self.shown and self._notify(1, message):
            self.shown = message

    def _open(self):
        if time.monotonic() - self.opened > 3:  # a double click opens it once
            self.opened = time.monotonic()
            open_control_panel()

    def _wndproc(self, hwnd, msg, wparam, lparam):
        try:
            if msg == self.CALLBACK:
                # WM_LBUTTONUP, WM_RBUTTONUP, NIN_BALLOONUSERCLICK (the notification clicked)
                if lparam & 0xFFFF in (0x0202, 0x0205, 0x0405):
                    self._open()
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
            log.exception(tr("時鐘旁的提示發生錯誤", "Error in the notice by the clock"))
        return self.user32.DefWindowProcW(hwnd, msg, wparam, lparam)
