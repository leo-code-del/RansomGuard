"""Shared by the test files: the program as one namespace (`rg`), the safety net every test file installs
(setUpModule) and helpers. Run the tests from the project folder:

    python -m unittest discover -s tests -v

Everything happens in temporary folders; nothing touches the real Documents/Desktop, the real canary files, the
network or the installed program. setUpModule() enforces this: whatever a test doesn't replace itself fails loudly
instead of reaching the real thing. Strings that look like destructive commands only live in the test files, never
on a command line, so an installed RansomGuard won't react to them.
"""
import importlib
import io
import logging
import os
import shutil
import sys
import tempfile
import unittest
import urllib.request
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


MODULES = [importlib.import_module(f"ransomguard.{name}") for name in (
    "config", "winapi", "storage", "folders", "canary", "detection", "processes", "response", "defender",
    "network", "install", "updates", "backup", "selftest", "tray", "gui", "app")]


class _Namespace:
    """What mock.patch.object reads as the target's __dict__: the current value of each name."""

    def __init__(self, program):
        self.program = program

    def __getitem__(self, name):
        try:
            return getattr(self.program, name)
        except AttributeError:
            raise KeyError(name) from None


class Program:
    """The whole program as one namespace, as the tests knew it when it was a single file. Reading a name finds
    the module that defines it; replacing it (mock.patch.object) replaces it in that module. The modules refer
    to each other as `module.name`, so the replacement takes effect everywhere, as it did before the split."""

    _homes = {}  # decided once, before anything is replaced: a replacement no longer says where it belongs

    @classmethod
    def _home(cls, name):
        if name not in cls._homes:
            found = [m for m in MODULES if name in vars(m)]
            if not found:
                raise AttributeError(name)
            # a function or class lives where it was defined; other names (constants, imported standard
            # modules) exist in one module only, or are the same object everywhere
            cls._homes[name] = next((m for m in found if getattr(vars(m)[name], "__module__", None) == m.__name__),
                                    found[0])
        return cls._homes[name]

    def __getattr__(self, name):
        return getattr(self._home(name), name)

    def __setattr__(self, name, value):
        setattr(self._home(name), name, value)

    @property
    def __dict__(self):
        return _Namespace(self)


rg = Program()

rg.log.addHandler(logging.NullHandler())
rg.log.propagate = False
rg.init_lang("en")

REAL = {name: getattr(rg, name)
        for name in ("fullscreen_alert", "set_paused", "_known_folder", "state_dir", "secure_state_dir", "Tray")}
SANDBOX = Path(tempfile.mkdtemp(prefix="rg_sandbox_"))
TEST_PID = os.getpid()  # saved now: some tests replace os.getpid
# the interpreter itself; in a venv, sys.executable is a small launcher that starts this as a child process
BASE_PYTHON = getattr(sys, "_base_executable", None) or sys.executable
_guards = []


class NoTray:
    """The notification-area icon, not shown: what the monitor gets in the tests. `made` keeps every one."""
    made = []

    def __init__(self, state):
        self.state, self.started, self.stopped = state, False, False
        NoTray.made.append(self)

    def start(self):
        self.started = True

    def stop(self):
        self.stopped = True


def forbidden(what):
    def call(*args, **kwargs):
        raise AssertionError(f"a test reached the real {what}; replace it in that test")
    return call


def sandbox_app_dir():
    d = SANDBOX / "LocalAppData" / "RansomGuard"
    d.mkdir(parents=True, exist_ok=True)
    return d


def own_descendant(pid):
    """True if pid is a child, grandchild... of this test process."""
    parents = {p: parent for p, parent, _ in rg.process_list()}
    for _ in range(10):
        pid = parents.get(pid)
        if pid is None:
            return False
        if pid == TEST_PID:
            return True
    return False


def guarded_set_paused(pid, paused):
    if not own_descendant(pid):
        raise AssertionError(f"a test tried to pause or resume PID {pid}, which it didn't start")
    return REAL["set_paused"](pid, paused)


def setUpModule():
    """Safety net for the whole suite: user folders, the app folder and the install folder point into a
    temporary sandbox, and everything that would change the real computer is forbidden: PowerShell
    (network adapters, firewall, scheduled tasks), ipconfig / netsh / shutdown, the internet, the
    full-screen warning and pausing any process the tests didn't start. (The installed exe can't be
    started either: INSTALL_EXE points into the sandbox.) A message box would wait for a click, so
    alert() does nothing. Tests replace these as they need. Each test file calls it (and tearDownModule)."""
    SANDBOX.mkdir(parents=True, exist_ok=True)
    for name, value in (
            ("app_dir", sandbox_app_dir),
            ("_known_folder", lambda name: SANDBOX / "User" / name),
            ("INSTALL_DIR", SANDBOX / "Program Files" / "RansomGuard"),
            ("INSTALL_EXE", SANDBOX / "Program Files" / "RansomGuard" / "RansomGuard.exe"),
            ("_ps", forbidden("PowerShell (network adapters, firewall, scheduled tasks)")),
            ("_run", forbidden("system commands (ipconfig, netsh, shutdown)")),
            ("fullscreen_alert", forbidden("full-screen warning")),
            ("set_paused", guarded_set_paused),
            # the administrators-only state folder follows the (sandboxed or per-test) app folder; changing
            # permissions is tested separately with icacls replaced
            ("state_dir", lambda: rg.app_dir()),
            ("secure_state_dir", lambda: None),
            ("alert", lambda title, msg: None),
            ("notice", lambda title, msg: None),
            ("Tray", NoTray),  # the notification-area icon would show on the screen
            # the backup check reads File History's record and folder: the sandbox's, never this computer's
            ("_file_history_registry_time", lambda: None),
            ("_file_history_folder", lambda: SANDBOX / "FileHistory" / "Configuration")):
        _guards.append(mock.patch.object(rg, name, value))
    _guards.append(mock.patch.object(urllib.request, "urlopen", forbidden("internet")))
    for g in _guards:
        g.start()


def tearDownModule():
    for g in reversed(_guards):
        g.stop()
    _guards.clear()
    shutil.rmtree(SANDBOX, ignore_errors=True)

ZIP_HEAD = b"PK\x03\x04\x14\x00\x06\x00"
OLE_HEAD = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def random_bytes(n=8192):
    return os.urandom(n)


def real_zip(n=8192, comment=b""):
    """A real ZIP-based file (an Office document, say) holding n random bytes."""
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("word/document.xml", b"<w:document>" + b"<w:p>text</w:p>" * 50 + b"</w:document>")
        z.writestr("word/media/image1.png", os.urandom(n))
        z.comment = comment
    return buf.getvalue()


def real_pdf(n=8192):
    return b"%PDF-1.7\n" + os.urandom(n) + b"\nxref\n0 1\ntrailer\n<< /Size 1 >>\nstartxref\n9\n%%EOF\n"


def encrypt_end(path, n=4096):
    """Encrypt only the end of a file, leaving its header alone (partial encryption)."""
    with open(path, "r+b") as f:
        size = f.seek(0, os.SEEK_END)
        f.seek(max(0, size - n))
        f.write(os.urandom(min(n, size)))


def overwrite(path, data):
    """Replace a file's content in place, as ransomware encrypting an open file does. (Canary files are hidden,
    and Windows refuses to open a hidden file for "create new" writing such as Path.write_bytes.)"""
    with open(path, "r+b") as f:
        f.truncate(0)
        f.write(data)


class TempDirTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="rg_test_"))
        # a cleanup, not tearDown: cleanups run last-registered first, so the folder is removed after the
        # processes a test started (and registered for cleanup later) have been ended and no longer lock files
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)

    def patch(self, name, value):
        p = mock.patch.object(rg, name, value)
        p.start()
        self.addCleanup(p.stop)

    def file(self, name, data):
        p = self.dir / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        return str(p)


# ---------------------------------------------------------------- the monitor loop (run)
class StubProcessMonitor:
    instances = []

    def __init__(self, on_hit, kill):
        self.on_hit, self.kill, self.starts, self.stopped, self.dead = on_hit, kill, 0, False, False
        StubProcessMonitor.instances.append(self)

    def start(self):
        self.starts += 1
        self.dead = False

    def alive(self):
        return not self.dead

    def stop(self):
        self.stopped = True
