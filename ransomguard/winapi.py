"""Windows plumbing: running PowerShell and system programs by absolute path, kernel32 calls,
process information, the single-instance lock, message boxes and the user's known folders."""
import base64
import ctypes
import functools
import os
import re
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

from . import config
from .config import log, tr


def _system32() -> Path:
    """Absolute path of the system folder. External programs always run by absolute path, so a fake
    powershell.exe planted in the current folder can't run with this program's administrator rights."""
    if config.IS_WINDOWS:
        buf = ctypes.create_unicode_buffer(260)
        if ctypes.windll.kernel32.GetSystemDirectoryW(buf, 260):
            return Path(buf.value)
    return Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"


SYS32 = _system32()
POWERSHELL = str(SYS32 / "WindowsPowerShell" / "v1.0" / "powershell.exe")


def sys_exe(name: str) -> str:
    return str(SYS32 / name) if config.IS_WINDOWS else name


def fix_console_encoding():
    # When output goes to a file or pipe (not a console), the default encoding may not support Chinese and print crashes
    for s in (sys.stdout, sys.stderr):
        reconfigure = getattr(s, "reconfigure", None)
        if reconfigure is not None and not s.isatty():
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except ValueError:
                pass


def is_admin() -> bool:
    if not config.IS_WINDOWS:
        return getattr(os, "geteuid", lambda: -1)() == 0
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


class _PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", ctypes.c_uint32), ("cntUsage", ctypes.c_uint32),
                ("th32ProcessID", ctypes.c_uint32), ("th32DefaultHeapID", ctypes.c_size_t),
                ("th32ModuleID", ctypes.c_uint32), ("cntThreads", ctypes.c_uint32),
                ("th32ParentProcessID", ctypes.c_uint32), ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", ctypes.c_uint32), ("szExeFile", ctypes.c_wchar * 260)]


@functools.lru_cache(maxsize=None)
def kernel32():
    """kernel32 with the signatures this program uses. Handles are pointer-sized: without a restype ctypes
    would cut them to 32 bits."""
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    H, D, B, S = ctypes.c_void_p, ctypes.c_uint32, ctypes.c_bool, ctypes.c_wchar_p
    for name, res, args in (
            ("OpenProcess", H, [D, B, D]),
            ("CloseHandle", B, [H]),
            ("CreateJobObjectW", H, [H, S]),
            ("SetInformationJobObject", B, [H, ctypes.c_int, H, D]),
            ("AssignProcessToJobObject", B, [H, H]),
            ("CreateMutexW", H, [H, B, S]),
            ("WaitForSingleObject", D, [H, D]),
            ("QueryFullProcessImageNameW", B, [H, D, S, ctypes.POINTER(D)]),
            ("CreateToolhelp32Snapshot", H, [D, D]),
            ("Process32FirstW", B, [H, ctypes.POINTER(_PROCESSENTRY32W)]),
            ("Process32NextW", B, [H, ctypes.POINTER(_PROCESSENTRY32W)]),
            ("GetProcessIoCounters", B, [H, ctypes.POINTER(ctypes.c_uint64 * 6)]),
            ("GetProcessTimes", B, [H] + [ctypes.POINTER(ctypes.c_uint64)] * 4),
            ("MoveFileExW", B, [S, S, D]),
            ("SetFileAttributesW", B, [S, D]),
            ("GetTickCount64", ctypes.c_uint64, [])):
        fn = getattr(k32, name)
        fn.restype, fn.argtypes = res, args
    return k32


def process_path(pid: int) -> str:
    """Full path of a process's program file ("" if it can't be read or has exited)."""
    k32 = kernel32()
    h = k32.OpenProcess(0x1000, False, pid)  # QUERY_LIMITED_INFORMATION
    if not h:
        return ""
    buf = ctypes.create_unicode_buffer(1024)
    n = ctypes.c_uint32(len(buf))
    ok = k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(n))
    k32.CloseHandle(h)
    return buf.value if ok else ""


def delete_at_restart(path):
    kernel32().MoveFileExW(str(path), None, 4)  # MOVEFILE_DELAY_UNTIL_REBOOT


_JOB = None
_MUTEX = None


def kill_with_me(proc):
    """Put a child process in a Job Object: it exits when this program exits (even when killed),
    so no orphaned PowerShell is left running in the background."""
    global _JOB
    if not config.IS_WINDOWS:
        return
    k32 = kernel32()
    if _JOB is None:
        class BASIC(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64),
                        ("PerJobUserTimeLimit", ctypes.c_int64),
                        ("LimitFlags", ctypes.c_uint32),
                        ("MinimumWorkingSetSize", ctypes.c_size_t),
                        ("MaximumWorkingSetSize", ctypes.c_size_t),
                        ("ActiveProcessLimit", ctypes.c_uint32),
                        ("Affinity", ctypes.c_size_t),
                        ("PriorityClass", ctypes.c_uint32),
                        ("SchedulingClass", ctypes.c_uint32)]

        class EXTENDED(ctypes.Structure):
            _fields_ = [("BasicLimitInformation", BASIC),
                        ("IoInfo", ctypes.c_uint64 * 6),
                        ("ProcessMemoryLimit", ctypes.c_size_t),
                        ("JobMemoryLimit", ctypes.c_size_t),
                        ("PeakProcessMemoryUsed", ctypes.c_size_t),
                        ("PeakJobMemoryUsed", ctypes.c_size_t)]
        job = k32.CreateJobObjectW(None, None)
        info = EXTENDED()
        info.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        # 9 = JobObjectExtendedLimitInformation
        if not job or not k32.SetInformationJobObject(job, 9, ctypes.byref(info),
                                                      ctypes.sizeof(info)):
            log.warning(tr("無法建立 Job Object（錯誤 %d）", "Could not create Job Object (error %d)"),
                        ctypes.get_last_error())
            return
        _JOB = job
    h = k32.OpenProcess(0x0100 | 0x0001, False, proc.pid)  # SET_QUOTA | TERMINATE
    if not h or not k32.AssignProcessToJobObject(_JOB, h):
        log.warning(tr("無法把子程序 %s 放進 Job Object（錯誤 %d）",
                       "Could not add child process %s to Job Object (error %d)"),
                    proc.pid, ctypes.get_last_error())
    if h:
        k32.CloseHandle(h)


def restart_if_borrowed_files() -> bool:
    """A one-file exe normally runs as the child of its own unpacker, which names the unpacked folder
    _MEI<its PID><digit>. If another program started this exe with its own environment (control panels
    before 1.5.2 did when reopening after an update), this process runs on that program's unpacked
    files, which vanish when it exits. Start again as a fresh program in that case (only once);
    returns True if this process should exit."""
    if not (config.IS_WINDOWS and config.FROZEN) or os.environ.get("RG_FRESH_START"):
        return False
    name = os.path.basename(getattr(sys, "_MEIPASS", ""))
    if not re.fullmatch(r"_MEI\d+", name) or re.fullmatch(rf"_MEI{os.getppid()}\d", name):
        return False  # not a folder name we understand, or unpacked by our own parent: fine
    env = fresh_env()
    env["RG_FRESH_START"] = "1"
    subprocess.Popen([sys.executable, *sys.argv[1:]], env=env)
    return True


def fresh_env() -> dict:
    """This environment without PyInstaller's unpacking variables, so a one-file exe started with it
    unpacks its own files instead of reusing (and later losing) ours."""
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("_PYI_") and k not in ("_MEIPASS2", "RG_FRESH_START")}
    env["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
    return env


def exit_with_launcher():
    """A one-file .exe is really two processes: the outer one unpacks, the inner one is this program. Task
    Scheduler only ends the outer one, so exit together with it; otherwise the monitor becomes an
    orphan that can't be stopped."""
    if not (config.IS_WINDOWS and config.FROZEN):
        return
    parent = process_path(os.getppid())
    if not parent or norm(parent) != norm(sys.executable):
        return  # parent is not this program (e.g. a onedir build); nothing to do
    k32 = kernel32()
    h = k32.OpenProcess(0x00100000, False, os.getppid())  # SYNCHRONIZE
    if not h:
        return

    def wait():
        k32.WaitForSingleObject(h, 0xFFFFFFFF)
        log.info(tr("外層程序已結束，監控跟著結束", "Launcher process exited, so monitoring exits too"))
        os._exit(0)
    threading.Thread(target=wait, daemon=True).start()


def single_instance() -> bool:
    """Allow only one real monitor at a time; return False if one is already running."""
    global _MUTEX
    if not config.IS_WINDOWS:
        return True
    _MUTEX = kernel32().CreateMutexW(None, False, "Global\\RansomGuardMonitor")
    return ctypes.get_last_error() != 183  # ERROR_ALREADY_EXISTS


def alert(title: str, msg: str):
    """Show a topmost alert box (without blocking the monitor)."""
    if not config.IS_WINDOWS:
        log.info(tr("[警告視窗] %s：%s", "[Alert] %s: %s"), title, msg.replace("\n", " "))
        return

    def _box():
        # MB_ICONERROR | MB_SYSTEMMODAL | MB_TOPMOST
        ctypes.windll.user32.MessageBoxW(None, msg, title, 0x10 | 0x1000 | 0x40000)
    threading.Thread(target=_box).start()


def ps_encoded_args(script: str, *opts: str) -> list:
    """Run a PowerShell script with -EncodedCommand (no file needed)."""
    enc = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    return [POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", *opts,
            "-EncodedCommand", enc]


def norm(path) -> str:
    return os.path.normcase(os.path.abspath(str(path)))


_KNOWN_FOLDERS = {
    "Desktop":   "B4BFCC3A-DB2C-424C-B029-7FE99A87C641",
    "Documents": "FDD39AD0-238F-46AF-ADB4-6C85480369C7",
    "Pictures":  "33E28130-4E1E-4676-835A-98395C3BC3BB",
    "Downloads": "374DE290-123F-4565-9164-39C4925E467B",
    "Videos":    "18989B1D-99B5-455B-841C-AB7C74E4DDFC",
    "Music":     "4BD8D571-6D19-48D3-BE97-422220080E43",
}


def _known_folder(name: str):
    """Actual Windows path of Documents, Pictures etc. (including OneDrive redirection)."""
    if config.IS_WINDOWS:
        try:
            class GUID(ctypes.Structure):
                _fields_ = [("Data1", ctypes.c_ulong), ("Data2", ctypes.c_ushort),
                            ("Data3", ctypes.c_ushort), ("Data4", ctypes.c_ubyte * 8)]
            g = GUID.from_buffer_copy(uuid.UUID(_KNOWN_FOLDERS[name]).bytes_le)
            p = ctypes.c_wchar_p()
            if ctypes.windll.shell32.SHGetKnownFolderPath(ctypes.byref(g), 0, None,
                                                          ctypes.byref(p)) == 0 and p.value:
                path = Path(p.value)
                ctypes.windll.ole32.CoTaskMemFree(p)
                return path
        except Exception:
            pass
    return Path.home() / name


def process_list() -> list:
    """[(pid, parent pid, program name)] of every running process."""
    k32 = kernel32()
    snap = k32.CreateToolhelp32Snapshot(0x2, 0)  # TH32CS_SNAPPROCESS
    if not snap or snap == ctypes.c_void_p(-1).value:
        return []
    procs = []
    e = _PROCESSENTRY32W(dwSize=ctypes.sizeof(_PROCESSENTRY32W))
    ok = k32.Process32FirstW(snap, ctypes.byref(e))
    while ok:
        procs.append((e.th32ProcessID, e.th32ParentProcessID, e.szExeFile))
        ok = k32.Process32NextW(snap, ctypes.byref(e))
    k32.CloseHandle(snap)
    return procs


def process_started(pid: int):
    """When a process started (a FILETIME number), or None if it can't be read."""
    k32 = kernel32()
    h = k32.OpenProcess(0x1000, False, pid)  # QUERY_LIMITED_INFORMATION
    if not h:
        return None
    t = [ctypes.c_uint64() for _ in range(4)]  # creation, exit, kernel, user
    ok = k32.GetProcessTimes(h, *(ctypes.byref(x) for x in t))
    k32.CloseHandle(h)
    return t[0].value if ok else None


CREATE_NO_WINDOW = 0x08000000


def _ps(cmd: str, timeout=60):
    full = "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; " + cmd
    r = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-Command", full],
        capture_output=True, timeout=timeout, creationflags=CREATE_NO_WINDOW)
    return (r.returncode, r.stdout.decode("utf-8", "replace").strip(),
            r.stderr.decode("utf-8", "replace").strip())


def _run(args):
    try:
        subprocess.run(args, capture_output=True, timeout=30,
                       creationflags=CREATE_NO_WINDOW if config.IS_WINDOWS else 0)
    except Exception as ex:
        log.error(tr("執行 %s 失敗：%s", "Failed to run %s: %s"), args, ex)


def _ps_quote(s: str) -> str:
    return "'" + str(s).replace("'", "''") + "'"


def boot_time() -> float:
    """When Windows last started (seconds since the epoch)."""
    return time.time() - kernel32().GetTickCount64() / 1000 if config.IS_WINDOWS else 0.0
