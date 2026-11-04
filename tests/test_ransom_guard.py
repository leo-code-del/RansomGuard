"""Tests for RansomGuard. Run from the project folder:

    python -m unittest discover -s tests -v

Everything happens in temporary folders; nothing touches the real Documents/Desktop, the real
canary files, the network or the installed program. setUpModule() enforces this: whatever a test
doesn't replace itself fails loudly instead of reaching the real thing. Strings that look like
destructive commands only live in this file, never on a command line, so an installed RansomGuard
won't react to them.
"""
import argparse
import base64
import hashlib
import io
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import importlib  # noqa: E402

MODULES = [importlib.import_module(f"ransomguard.{name}") for name in (
    "config", "winapi", "storage", "folders", "canary", "detection", "processes", "response", "defender",
    "network", "install", "updates", "gui", "app")]


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

REAL = {name: getattr(rg, name) for name in ("fullscreen_alert", "set_paused", "_known_folder", "state_dir",
                                              "secure_state_dir")}
SANDBOX = Path(tempfile.mkdtemp(prefix="rg_sandbox_"))
TEST_PID = os.getpid()  # saved now: some tests replace os.getpid
# the interpreter itself; in a venv, sys.executable is a small launcher that starts this as a child process
BASE_PYTHON = getattr(sys, "_base_executable", None) or sys.executable
_guards = []


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
    alert() does nothing. Tests replace these as they need."""
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
            ("alert", lambda title, msg: None)):
        _guards.append(mock.patch.object(rg, name, value))
    _guards.append(mock.patch.object(urllib.request, "urlopen", forbidden("internet")))
    for g in _guards:
        g.start()


def tearDownModule():
    for g in reversed(_guards):
        g.stop()
    shutil.rmtree(SANDBOX, ignore_errors=True)

ZIP_HEAD = b"PK\x03\x04\x14\x00\x06\x00"
OLE_HEAD = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def random_bytes(n=8192):
    return os.urandom(n)


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

    def file(self, name, data):
        p = self.dir / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        return str(p)


# ---------------------------------------------------------------- broken files
class BrokenFileTests(TempDirTest):
    def test_valid_files_are_not_broken(self):
        cases = {
            "a.docx": ZIP_HEAD + random_bytes(),
            "b.pdf": b"%PDF-1.7\n" + random_bytes(),
            "c.jpg": b"\xff\xd8\xff\xe0" + random_bytes(),
            "d.png": b"\x89PNG\r\n\x1a\n" + random_bytes(),
            "e.mp4": b"\x00\x00\x00\x20ftypisom" + random_bytes(),
            "f.zip": ZIP_HEAD + random_bytes(),
        }
        for name, data in cases.items():
            self.assertIsNone(rg.broken_reason(self.file(name, data)), name)

    def test_encrypted_files_are_broken(self):
        for name in ("a.docx", "b.pdf", "c.jpg", "d.png", "e.xlsx", "f.mp4", "g.zip"):
            self.assertIsNotNone(rg.broken_reason(self.file(name, random_bytes())), name)

    def test_header_overwritten_but_rest_intact_is_broken(self):
        data = os.urandom(16) + random_bytes()
        self.assertIsNotNone(rg.broken_reason(self.file("a.docx", data)))

    def test_misnamed_but_real_files_are_not_broken(self):
        cases = {
            "webp_named.jpg": b"RIFF\x00\x00\x00\x00WEBPVP8 " + random_bytes(),
            "png_named.jpg": b"\x89PNG\r\n\x1a\n" + random_bytes(),
            "html_export.xls": b"<html><body><table>" + b"<tr><td>1</td><td>2</td></tr>" * 300,
            "rtf_saved.doc": b"{\\rtf1\\ansi " + b"hello world " * 400,
            "password_protected.docx": OLE_HEAD + random_bytes(),
            "password_protected.xlsx": OLE_HEAD + random_bytes(),
            "id3_tagged.flac": b"ID3\x04\x00\x00" + random_bytes(),
            "big.wav": b"RF64\xff\xff\xff\xffWAVE" + random_bytes(),
            "fragment.mp4": b"\x00\x00\x00\x18stypmsdh" + random_bytes(),
            "csv_export.xls": b"date,amount,memo\n" + b"2026-01-01,100,coffee\n" * 300,
        }
        for name, data in cases.items():
            self.assertIsNone(rg.broken_reason(self.file(name, data)), name)

    def test_git_lfs_pointer_is_not_broken(self):
        pointer = (b"version https://git-lfs.github.com/spec/v1\n"
                   b"oid sha256:4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d17e2393\n"
                   b"size 12345\n")
        for name in ("logo.png", "photo.jpg", "doc.pdf"):
            self.assertIsNone(rg.broken_reason(self.file(name, pointer)), name)

    def test_text_files(self):
        self.assertIsNotNone(rg.broken_reason(self.file("notes.txt", random_bytes(8192))))
        self.assertIsNone(rg.broken_reason(self.file("small.txt", random_bytes(1000))))
        b64 = base64.b64encode(random_bytes(9000))
        self.assertIsNone(rg.broken_reason(self.file("embedded.svg", b"<svg>" + b64 + b"</svg>")))
        self.assertIsNone(rg.broken_reason(self.file("code.py", b"print('hello')\n" * 1000)))

    def test_mpeg_ts_video_is_not_typescript(self):
        packet = b"\x47" + random_bytes(187)
        self.assertIsNone(rg.broken_reason(self.file("clip.ts", packet * 50)))

    def test_empty_zero_and_unknown_files(self):
        self.assertIsNone(rg.broken_reason(self.file("empty.docx", b"")))
        self.assertIsNone(rg.broken_reason(self.file("zeros.mp4", b"\0" * 100000)))
        self.assertIsNone(rg.broken_reason(self.file("data.bin", random_bytes())))
        self.assertIsNone(rg.broken_reason(str(self.dir / "missing.docx")))


# ---------------------------------------------------------------- extensions
class ExtensionTests(unittest.TestCase):
    def test_ransomware_renames_are_suspicious(self):
        self.assertTrue(rg.suspicious_ext("moved", r"C:\d\report.docx", r"C:\d\report.docx.locked"))
        self.assertTrue(rg.suspicious_ext("moved", r"C:\d\photo.jpg", r"C:\d\photo.jpg.id-8F2A.[mail@x.cc].eking"))
        self.assertTrue(rg.suspicious_ext("moved", r"C:\d\a.pdf", r"C:\d\a.pdf.encrypted"))
        self.assertTrue(rg.suspicious_ext("created", r"C:\d\budget.xlsx.crypt", ""))
        self.assertTrue(rg.suspicious_ext("moved", r"C:\d\a.txt", r"C:\d\a.wncry"))
        # letters appended straight onto the extension, with no separating dot
        self.assertTrue(rg.suspicious_ext("moved", r"C:\d\photo.jpg", r"C:\d\photo.jpgcrypt"))
        self.assertTrue(rg.suspicious_ext("moved", r"C:\d\note.txt", r"C:\d\note.txtlocked"))

    def test_everyday_names_are_not_suspicious(self):
        benign_created = [
            r"C:\proj\dist\main.js.map", r"C:\proj\dist\style.css.map", r"C:\proj\dist\index.d.ts.map",
            r"C:\dl\movie.mkv.!qB", r"C:\dl\song.mp3.!ut", r"C:\dl\file.zip.aria2",
            r"C:\dl\backup.zip.001", r"C:\dl\backup.7z.002", r"C:\dl\big.rar.r00",
            r"C:\proj\app.py.orig", r"C:\proj\app.c.rej", r"C:\proj\.app.py.swp",
            r"C:\proj\data.tar.zst", r"C:\proj\__snapshots__\a.test.ts.snap",
            r"C:\dl\setup.zip.sha256", r"C:\dl\iso.iso.sha512", r"C:\dl\file.pdf.crdownload",
            r"C:\proj\report.docx", r"C:\proj\x.tar.gz",
        ]
        for p in benign_created:
            self.assertFalse(rg.suspicious_ext("created", p, ""), p)
        benign_moved = [
            (r"C:\dl\a.zip.crdownload", r"C:\dl\a.zip"),
            (r"C:\pics\a.jpg", r"C:\pics\a.jpg_original"),  # exiftool keeps the original this way
            (r"C:\d\a.docx", r"C:\d\a.pdf"),
            (r"C:\d\a.docx", r"C:\d\a"),
            (r"C:\d\a.JPG", r"C:\d\a.jpg"),
            (r"C:\d\a.txt", r"C:\d\a.txt.bak"),
        ]
        for s, d in benign_moved:
            self.assertFalse(rg.suspicious_ext("moved", s, d), f"{s} -> {d}")


# ---------------------------------------------------------------- ransom notes
class RansomNoteTests(unittest.TestCase):
    def test_ransom_notes(self):
        for n in ("HOW_TO_DECRYPT.txt", "README_RANSOM.html", "如何解密.txt", "RESTORE_MY_FILES.hta",
                  "!!!_HOW_TO_RECOVER_FILES_!!!.txt", "YOUR_FILES_ARE_ENCRYPTED.html", "解密說明.txt",
                  "decrypt_instructions.png", "restore-your-files.url"):
            self.assertTrue(rg.is_ransom_note(n), n)

    def test_not_ransom_notes(self):
        for n in ("RansomGuard.exe", "RansomGuard.lnk", "RansomGuard.exe - Shortcut.lnk", "RansomGuard (1).exe",
                  "ransom_guard.py", "decrypt.py", "aes_decrypt.c", "Encrypt_Decrypt_Lab.pdf",
                  "test_decrypt.js", "decrypt_utils.java", "ransomware_report.docx", "report.docx"):
            self.assertFalse(rg.is_ransom_note(n), n)


# ---------------------------------------------------------------- dangerous commands
def ps_encoded(cmd):
    return base64.b64encode(cmd.encode("utf-16-le")).decode()


class DangerousCommandTests(unittest.TestCase):
    def test_attacks_are_caught(self):
        cases = [
            ("vssadmin.exe", "vssadmin delete shadows /all /quiet"),
            ("vssadmin.exe", "vssadmin.exe Delete Shadows /For=C: /Quiet"),
            ("vssadmin.exe", "vssadmin resize shadowstorage /for=c: /on=c: /maxsize=401MB"),
            ("WMIC.exe", "wmic shadowcopy delete"),
            ("cmd.exe", 'cmd.exe /c "vssadmin delete shadows /all /quiet & bcdedit /set {default} recoveryenabled No"'),
            ("bcdedit.exe", "bcdedit /set {default} bootstatuspolicy ignoreallfailures"),
            ("wbadmin.exe", "wbadmin delete catalog -quiet"),
            ("wevtutil.exe", "wevtutil cl System"),
            ("powershell.exe", "powershell -c Set-MpPreference -DisableRealtimeMonitoring $true"),
            ("powershell.exe", "powershell -enc " + ps_encoded("Get-WmiObject Win32_ShadowCopy | Remove-WmiObject")),
            ("pwsh.exe", "pwsh -EncodedCommand " + ps_encoded("vssadmin delete shadows /all")),
        ]
        for name, cmd in cases:
            self.assertIsNotNone(rg.dangerous_process(name, cmd), f"{name}: {cmd}")

    def test_text_that_merely_mentions_commands_is_ignored(self):
        cases = [
            # git commit / search tools whose arguments only *mention* the commands (this cut the network once)
            ("bash.exe", 'bash -c "git commit -m \'detect vssadmin delete shadows\'"'),
            ("git.exe", 'git commit -m "block wevtutil cl and vssadmin delete shadows"'),
            ("rg.exe", "rg vssadmin.*delete shadows src"),
            ("python.exe", "python test.py --pattern vssadmin delete shadows"),
            ("Code.exe", r"Code.exe C:\notes\vssadmin delete shadows.txt"),
            ("notepad.exe", r"notepad.exe C:\notes\wbadmin delete catalog.txt"),
        ]
        for name, cmd in cases:
            self.assertIsNone(rg.dangerous_process(name, cmd), f"{name}: {cmd}")

    def test_harmless_uses_of_the_tools(self):
        for name, cmd in [("vssadmin.exe", "vssadmin list shadows"), ("bcdedit.exe", "bcdedit /enum"),
                          ("wevtutil.exe", "wevtutil qe System /c:5"), ("powershell.exe", "powershell Get-MpPreference"),
                          ("cmd.exe", "cmd /c dir")]:
            self.assertIsNone(rg.dangerous_process(name, cmd), f"{name}: {cmd}")


# ---------------------------------------------------------------- event handler
from watchdog.events import (FileCreatedEvent, FileDeletedEvent,  # noqa: E402
                             FileModifiedEvent, FileMovedEvent)


class HandlerTests(TempDirTest):
    def setUp(self):
        super().setUp()
        (self.dir / "docs").mkdir()
        self.canaries = rg.plant_canaries([self.dir / "docs"])
        self.fired = []
        self.h = rg.make_handler(self.canaries, self.fired.append, dry_run=True)

    def test_canaries_are_planted(self):
        self.assertEqual(sorted(p.name for p in self.canaries), sorted(rg.CANARY_NAMES))
        self.assertTrue(all(p.read_bytes() == rg.canary_bytes(p) for p in self.canaries))
        self.assertEqual({p.read_bytes()[:4] for p in self.canaries}, {b"PK\x03\x04"})
        self.assertTrue(all(os.stat(p).st_file_attributes & 0x2 for p in self.canaries), "canaries are hidden")
        self.assertFalse([n for n in rg.CANARY_NAMES if "canary" in n.lower()], "names don't give them away")
        self.assertTrue({rg.norm(p) for p in self.canaries} <= {rg.norm(p) for p in rg.canary_record()})

    def test_a_users_own_file_with_a_canary_name_is_never_touched(self):
        mine = self.dir / "mine"
        mine.mkdir()
        own = mine / rg.CANARY_NAMES[1]
        own.write_bytes(b"my real budget")
        planted = rg.plant_canaries([mine])
        self.assertEqual(own.read_bytes(), b"my real budget")
        self.assertNotIn(rg.norm(own), {rg.norm(p) for p in planted})
        self.assertNotIn(rg.norm(own), {rg.norm(p) for p in rg.canary_record()})
        rg.remove_canaries(only_in=[mine])
        self.assertEqual(own.read_bytes(), b"my real budget", "and never deleted")
        self.assertEqual(sorted(p.name for p in mine.iterdir()), [rg.CANARY_NAMES[1]])

    def test_canary_deleted(self):
        self.h.on_any_event(FileDeletedEvent(str(self.canaries[0])))
        self.assertEqual(len(self.fired), 1)

    def test_canary_moved(self):
        self.h.on_any_event(FileMovedEvent(str(self.canaries[0]), str(self.dir / "x.docx")))
        self.assertEqual(len(self.fired), 1)

    def test_canary_modified(self):
        c = self.canaries[0]
        self.h.on_any_event(FileModifiedEvent(str(c)))  # same content (e.g. metadata change): no trigger
        self.assertEqual(self.fired, [])
        overwrite(c, random_bytes())
        self.h.on_any_event(FileModifiedEvent(str(c)))
        self.assertEqual(len(self.fired), 1)

    def test_canary_overwritten_by_move(self):
        self.h.on_any_event(FileMovedEvent(str(self.dir / "other.docx"), str(self.canaries[1])))
        self.assertEqual(len(self.fired), 1)

    def test_canary_check_finds_missing_or_changed(self):
        self.assertIsNone(rg.check_canaries(self.canaries))
        self.canaries[0].unlink()
        self.assertIn("missing", rg.check_canaries(self.canaries))

    def test_broken_file_threshold(self):
        for i in range(rg.BROKEN_THRESHOLD - 1):
            self.h.on_any_event(FileModifiedEvent(self.file(f"f{i}.docx", random_bytes())))
        self.assertEqual(self.fired, [])
        self.h.on_any_event(FileModifiedEvent(self.file("last.docx", random_bytes())))
        self.assertEqual(len(self.fired), 1)

    def test_same_file_many_events_counts_once(self):
        p = self.file("one.docx", random_bytes())
        for _ in range(50):
            self.h.on_any_event(FileModifiedEvent(p))
        self.assertEqual(self.fired, [])

    def test_extension_threshold(self):
        for i in range(rg.EXT_CHANGE_THRESHOLD - 1):
            self.h.on_any_event(FileMovedEvent(f"{self.dir}\\r{i}.docx", f"{self.dir}\\r{i}.docx.locked"))
        self.assertEqual(self.fired, [])
        self.h.on_any_event(FileMovedEvent(f"{self.dir}\\z.docx", f"{self.dir}\\z.docx.locked"))
        self.assertEqual(len(self.fired), 1)

    def test_ransom_notes_need_several_folders(self):
        for _ in range(5):  # many notes in one folder: still one folder
            self.h.on_any_event(FileCreatedEvent(self.file("a/HOW_TO_DECRYPT.txt", b"pay")))
        self.h.on_any_event(FileCreatedEvent(self.file("b/HOW_TO_DECRYPT.txt", b"pay")))
        self.assertEqual(self.fired, [])
        self.h.on_any_event(FileCreatedEvent(self.file("c/HOW_TO_DECRYPT.txt", b"pay")))
        self.assertEqual(len(self.fired), 1)

    def test_window_expires(self):
        now = [1000.0]
        with mock.patch.object(rg.time, "time", lambda: now[0]):
            for i in range(rg.BROKEN_THRESHOLD - 1):
                self.h.on_any_event(FileModifiedEvent(self.file(f"old{i}.docx", random_bytes())))
            now[0] += rg.WINDOW_SEC + 1
            self.h.on_any_event(FileModifiedEvent(self.file("new.docx", random_bytes())))
        self.assertEqual(self.fired, [])

    def test_repeated_events_for_an_unchanged_file_read_it_once(self):
        p = self.file("notes.txt", b"plain text\n" * 1000)
        reads = []
        real = rg.broken_reason
        with mock.patch.object(rg, "broken_reason", lambda path, st=None: reads.append(path) or real(path, st)):
            for _ in range(3):  # Windows usually reports a save two or three times
                self.h.on_any_event(FileModifiedEvent(p))
            self.assertEqual(len(reads), 1)
            Path(p).write_bytes(random_bytes())  # really changed: checked again right away
            self.h.on_any_event(FileModifiedEvent(p))
            self.assertEqual(len(reads), 2)
            with mock.patch.object(rg, "RECHECK_SEC", 0):  # and an unchanged file is read again later
                self.h.on_any_event(FileModifiedEvent(p))
            self.assertEqual(len(reads), 3)

    def test_temp_and_office_lock_files_ignored(self):
        for i in range(20):
            self.h.on_any_event(FileModifiedEvent(self.file(f"~$doc{i}.docx", random_bytes())))
            self.h.on_any_event(FileModifiedEvent(self.file(f"dl{i}.zip.crdownload", random_bytes())))
        self.assertEqual(self.fired, [])

    def test_bad_event_does_not_crash(self):
        self.h.on_any_event(FileModifiedEvent(b"\xff\xfe-bytes-path"))  # undecodable bytes path
        self.h.on_any_event(FileModifiedEvent(""))
        self.assertEqual(self.fired, [])

    def test_canary_modified_while_not_running_is_reported_and_reset(self):
        c = self.canaries[0]
        overwrite(c, b"tampered")
        with mock.patch.object(rg, "alert") as alert:
            again = rg.plant_canaries([c.parent])
        alert.assert_called_once()
        self.assertEqual(Path(again[0]).read_bytes(), rg.canary_bytes(again[0]))

    def test_canary_files_are_real_office_files_that_never_change(self):
        import zipfile
        from xml.dom import minidom
        # the content must stay byte for byte the same in every version (and with every Python that builds it):
        # otherwise an update would report every installed canary file as modified
        self.assertEqual(hashlib.sha256(rg.CANARY_DOCX).hexdigest(),
                         "379c0bfee8db3ce62250e8c65ef5c37fdbc2726fc2382a99452eb6d1573c1e7b")
        self.assertEqual(hashlib.sha256(rg.CANARY_XLSX).hexdigest(),
                         "e3de85d72ecc82201c17ba04d12ac02cf23a865d09985b0d2f4f9b540441fc34")
        for data, main in ((rg.CANARY_DOCX, "word/document.xml"), (rg.CANARY_XLSX, "xl/worksheets/sheet1.xml")):
            z = zipfile.ZipFile(io.BytesIO(data))
            for part in z.namelist():
                minidom.parseString(z.read(part))
            self.assertIn("請直接關閉，不要修改", z.read(main).decode("utf-8"))
        self.assertEqual(rg.canary_bytes(r"C:\d\!!!_canary_do_not_delete.XLSX"), rg.CANARY_XLSX)
        self.assertEqual(rg.canary_bytes(r"C:\d\zzz_canary_do_not_delete.docx"), rg.CANARY_DOCX)

    def test_old_plain_text_canaries_are_accepted_then_upgraded(self):
        for c in self.canaries:
            overwrite(c, rg.LEGACY_CANARY_BYTES)
        self.assertIsNone(rg.check_canaries(self.canaries))
        self.h.on_any_event(FileModifiedEvent(str(self.canaries[0])))
        self.assertEqual(self.fired, [])
        with mock.patch.object(rg, "alert") as alert:
            rg.plant_canaries([self.dir / "docs"])  # test mode: another monitor may be watching, keep them
            self.assertEqual(self.canaries[0].read_bytes(), rg.LEGACY_CANARY_BYTES)
            rg.plant_canaries([self.dir / "docs"], upgrade=True)
        alert.assert_not_called()
        self.assertTrue(all(c.read_bytes() == rg.canary_bytes(c) for c in self.canaries))

    def test_remove_canaries_handles_recorded_and_legacy_ones(self):
        documents = self.dir / "Documents"
        documents.mkdir()
        for n in rg.LEGACY_CANARY_NAMES:  # the visible ones of versions before 1.7.5
            (documents / n).write_bytes(b"old")
        with mock.patch.object(rg, "_known_folder", lambda name: self.dir / name):
            rg.remove_canaries()
        self.assertEqual(list((self.dir / "docs").iterdir()), [])
        self.assertEqual(list(documents.iterdir()), [])
        self.assertEqual(rg.canary_record(), [])


# ---------------------------------------------------------------- end to end with a real file watcher
class EndToEndTests(TempDirTest):
    def watch(self):
        from watchdog.observers import Observer
        self.fired = []
        canaries = rg.plant_canaries([self.dir])
        h = rg.make_handler(canaries, self.fired.append, dry_run=True)
        obs = Observer()
        obs.schedule(h, str(self.dir), recursive=True)
        obs.start()
        self.addCleanup(lambda: (obs.stop(), obs.join()))
        time.sleep(0.5)
        return canaries

    def wait_for(self, cond, timeout=10):
        end = time.time() + timeout
        while time.time() < end and not cond():
            time.sleep(0.1)

    def test_simulated_ransomware_is_caught(self):
        self.watch()
        work = self.dir / "work"
        work.mkdir()
        for i in range(15):
            (work / f"doc{i}.docx").write_bytes(ZIP_HEAD + random_bytes())
        time.sleep(0.5)
        for i in range(15):  # encrypt in place, then rename like real ransomware does
            p = work / f"doc{i}.docx"
            p.write_bytes(random_bytes())
            p.rename(work / f"doc{i}.docx.locked")
        self.wait_for(lambda: self.fired)
        self.assertTrue(self.fired, "simulated ransomware was not detected")

    def test_deleting_a_canary_is_caught(self):
        canaries = self.watch()
        canaries[0].unlink()
        self.wait_for(lambda: self.fired)
        self.assertTrue(self.fired)

    def test_everyday_work_does_not_trigger(self):
        self.watch()
        photos, build, dl = self.dir / "photos", self.dir / "build", self.dir / "dl"
        for d in (photos, build, dl):
            d.mkdir()
        for i in range(150):  # copy a photo album
            (photos / f"IMG_{i:04}.jpg").write_bytes(b"\xff\xd8\xff\xe1" + random_bytes(20000))
        for i in range(40):  # a JS build with source maps
            (build / f"chunk{i}.js").write_text("console.log(1);\n" * 50)
            (build / f"chunk{i}.js.map").write_text('{"version":3,"sources":[]}')
        for i in range(12):  # torrent / multi-part downloads
            (dl / f"ep{i}.mkv.!qB").write_bytes(b"\x1a\x45\xdf\xa3" + random_bytes(4096))
            (dl / f"archive.zip.{i + 1:03}").write_bytes(random_bytes(4096))
        for i in range(12):  # browser downloads finishing
            p = dl / f"report{i}.pdf.crdownload"
            p.write_bytes(b"%PDF-1.5\n" + random_bytes(4096))
            p.rename(dl / f"report{i}.pdf")
        for i in range(10):  # web exports that are really HTML
            (dl / f"statement{i}.xls").write_text("<html><table>" + "<tr><td>1</td></tr>" * 400 + "</table></html>")
        time.sleep(3)
        self.assertEqual(self.fired, [], self.fired[:1])


# ---------------------------------------------------------------- settings / state robustness
class SettingsTests(TempDirTest):
    def setUp(self):
        super().setUp()
        p = mock.patch.object(rg, "app_dir", lambda: self.dir)
        p.start()
        self.addCleanup(p.stop)
        self.addCleanup(rg.init_lang, "en")
        self.saved_arg = rg._LANG_ARG
        rg._LANG_ARG = None
        self.addCleanup(setattr, rg, "_LANG_ARG", self.saved_arg)

    def test_corrupt_files_fall_back_to_defaults(self):
        for content in ("not json", "[1, 2]", '"text"', "null", "", '{"lang": 5}', '{"lang": "fr"}'):
            (self.dir / "settings.json").write_text(content, encoding="utf-8")
            (self.dir / "state.json").write_text(content, encoding="utf-8")
            self.assertIsInstance(rg.load_settings(), dict, content)
            self.assertIsInstance(rg.load_state(), dict, content)
            rg.init_lang()
            self.assertIn(rg.LANG, ("zh", "en"), content)
            self.assertFalse(rg.network_cut(rg.load_state()) and content in ("not json", "", "null"))

    def test_set_lang_keeps_other_settings(self):
        (self.dir / "settings.json").write_text('{"other": 1}', encoding="utf-8")
        rg.set_lang("zh")
        self.assertEqual(rg.load_settings(), {"other": 1, "lang": "zh"})
        rg.set_lang("en")
        rg.init_lang()
        self.assertEqual(rg.LANG, "en")

    def test_language_switch_translates(self):
        rg.init_lang("zh")
        self.assertEqual(rg.tr("中", "en"), "中")
        rg.init_lang("en")
        self.assertEqual(rg.tr("中", "en"), "en")


# ---------------------------------------------------------------- network cut / restore (simulated adapters)
class FakeNetwork:
    """Stands in for the PowerShell network commands, so nothing real is touched."""

    def __init__(self, adapters=("Ethernet", "Wi-Fi"), disable_works=True, enable_fails=()):
        self.up = set(adapters)
        self.disabled = set()
        self.disable_works = disable_works
        self.enable_fails = set(enable_fails)
        self.firewall_blocked = False
        self.task = "Running"
        self.commands = []

    def ps(self, cmd, timeout=60):
        self.commands.append(cmd)
        if "Status -ne 'Disabled'} | ForEach-Object" in cmd:
            return 0, "\n".join(sorted(self.up)), ""
        if "Disable-NetAdapter" in cmd:
            if self.disable_works:
                self.disabled |= self.up
                self.up = set()
            return 0, "", ""
        if ".Count" in cmd:
            return 0, str(len(self.up)), ""
        if "Get-NetFirewallProfile" in cmd:
            return 0, json.dumps([{"Name": "Domain", "Enabled": "True", "In": "Block", "Out": "Allow"}]), ""
        if "Set-NetFirewallProfile -All" in cmd:
            self.firewall_blocked = True
            return 0, "", ""
        if "Set-NetFirewallProfile -Name" in cmd:
            self.firewall_blocked = False
            return 0, "", ""
        if "Enable-NetAdapter" in cmd:
            out = []
            for a in sorted(self.disabled):
                if a in self.enable_fails:
                    out.append(f"FAIL\t{a}\tdevice not found")
                else:
                    out.append(f"OK\t{a}")
                    self.up.add(a)
            self.disabled -= self.up
            return 0, "\n".join(out), ""
        if "Get-ScheduledTask" in cmd:
            return 0, self.task, ""
        if "Start-ScheduledTask" in cmd:
            self.task = "Running"
        if "Stop-ScheduledTask" in cmd:
            self.task = "Ready"
        return 0, "", ""


class NetworkTests(TempDirTest):
    def setUp(self):
        super().setUp()
        for name, value in (("app_dir", lambda: self.dir), ("is_admin", lambda: True), ("_run", lambda a: None),
                            ("IS_WINDOWS", True)):
            p = mock.patch.object(rg, name, value)
            p.start()
            self.addCleanup(p.stop)
        p = mock.patch.object(rg.time, "sleep")
        p.start()
        self.addCleanup(p.stop)

    def use(self, net):
        p = mock.patch.object(rg, "_ps", net.ps)
        p.start()
        self.addCleanup(p.stop)
        return net

    def test_cut_and_restore(self):
        net = self.use(FakeNetwork())
        self.assertTrue(rg.disconnect_network())
        st = rg.load_state()
        self.assertEqual(st["disabled_adapters"], ["Ethernet", "Wi-Fi"])
        self.assertTrue(st["triggered_at"])
        self.assertTrue(rg.network_cut(st))
        msgs = []
        self.assertTrue(rg.restore_network(msgs.append))
        self.assertEqual(net.up, {"Ethernet", "Wi-Fi"})
        self.assertEqual(rg.load_state(), {})
        self.assertEqual(net.task, "Running")

    def test_firewall_fallback_when_adapters_stay_up(self):
        net = self.use(FakeNetwork(disable_works=False))
        self.assertFalse(rg.disconnect_network())
        self.assertTrue(net.firewall_blocked)
        self.assertIn("firewall", rg.load_state())
        self.assertTrue(rg.restore_network(lambda m: None))
        self.assertFalse(net.firewall_blocked)

    def test_partial_restore_keeps_state(self):
        net = self.use(FakeNetwork(enable_fails=("Wi-Fi",)))
        rg.disconnect_network()
        self.assertEqual(net.disabled, {"Ethernet", "Wi-Fi"})
        msgs = []
        self.assertFalse(rg.restore_network(msgs.append))
        self.assertTrue(rg.network_cut(rg.load_state()), "state must stay so the user can retry")
        self.assertTrue(any("ncpa.cpl" in m for m in msgs))

    def test_second_cut_keeps_first_adapter_list(self):
        net = self.use(FakeNetwork())
        rg.disconnect_network()
        net.up.add("USB Ethernet")  # an adapter re-enabled or plugged in while the warning is open
        rg.disconnect_network()
        self.assertEqual(rg.load_state()["disabled_adapters"], ["Ethernet", "USB Ethernet", "Wi-Fi"])

    def test_restore_needs_admin(self):
        self.use(FakeNetwork())
        with mock.patch.object(rg, "is_admin", lambda: False):
            self.assertFalse(rg.restore_network(lambda m: None))

    def test_restore_resumes_paused_programs(self):
        self.use(FakeNetwork())
        rg.disconnect_network()
        st = rg.load_state()
        st["paused"] = [{"pid": 7, "name": "a.exe", "path": r"C:\x\a.exe", "paused": True, "result": "paused"}]
        rg.save_state(st)
        got = []
        with mock.patch.object(rg, "resume_paused", lambda paused, report: got.append(paused)):
            self.assertTrue(rg.restore_network(lambda m: None))
        self.assertEqual(got, [st["paused"]])
        self.assertEqual(rg.load_state(), {})


# ---------------------------------------------------------------- install / update
class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


class UpdateTests(TempDirTest):
    def setUp(self):
        super().setUp()
        for name, value in (("INSTALL_DIR", self.dir), ("INSTALL_EXE", self.dir / "RansomGuard.exe"),
                            ("VERSION", "1.2.0")):
            p = mock.patch.object(rg, name, value)
            p.start()
            self.addCleanup(p.stop)
        rg.INSTALL_EXE.write_bytes(b"old version")
        self.payload = b"MZ new version " + random_bytes(1000)

    def serve(self, tag="v1.5.0", digest=None, url="https://github.com/leo-code-del/RansomGuard/releases/download/v1.5.0/RansomGuard.exe",
              payload=None, api_error=None):
        digest = digest if digest is not None else "sha256:" + hashlib.sha256(self.payload).hexdigest()
        release = {"tag_name": tag, "assets": [{"name": "RansomGuard.exe", "digest": digest, "size": len(self.payload),
                                                "browser_download_url": url}]}

        def urlopen(req, timeout=None):
            u = req.full_url
            if "api.github.com" in u:
                if api_error:
                    raise api_error
                return FakeResponse(json.dumps(release).encode())
            return FakeResponse(payload if payload is not None else self.payload)
        return mock.patch.object(urllib.request, "urlopen", urlopen)

    def test_newer_release_is_installed(self):
        with self.serve():
            self.assertEqual(rg.fetch_update(lambda m: None), "1.5.0")
        self.assertEqual(rg.INSTALL_EXE.read_bytes(), self.payload)

    def test_same_or_older_release_is_skipped(self):
        for tag in ("v1.2.0", "v1.1.9", "1.0"):
            with self.serve(tag=tag):
                self.assertIsNone(rg.fetch_update(lambda m: None), tag)
        self.assertEqual(rg.INSTALL_EXE.read_bytes(), b"old version")

    def test_version_compare_is_numeric(self):
        self.assertGreater(rg.version_tuple("1.10.0"), rg.version_tuple("1.9.9"))
        self.assertEqual(rg.version_tuple("v2.0"), (2, 0))

    def test_tampered_or_unverifiable_downloads_are_rejected(self):
        for kw in ({"payload": b"MZ evil"}, {"digest": ""}, {"digest": "md5:abc"},
                   {"url": "https://evil.example.com/RansomGuard.exe"}):
            with self.serve(**kw):
                self.assertIsNone(rg.fetch_update(lambda m: None), kw)
            self.assertEqual(rg.INSTALL_EXE.read_bytes(), b"old version", kw)

    def test_network_errors_are_handled(self):
        for err in (OSError("no network"), TimeoutError("timed out"), ValueError("bad json")):
            with self.serve(api_error=err):
                self.assertIsNone(rg.fetch_update(lambda m: None))
        self.assertEqual(rg.INSTALL_EXE.read_bytes(), b"old version")

    def test_replace_retries_while_file_is_locked(self):
        real = os.replace
        calls = []

        def flaky(a, b):
            calls.append(1)
            if len(calls) <= 2:
                raise PermissionError("locked by antivirus")
            return real(a, b)
        with mock.patch.object(rg.os, "replace", flaky), mock.patch.object(rg.time, "sleep"):
            rg.replace_install_exe(lambda: rg.INSTALL_EXE.write_bytes(b"new"))
        self.assertEqual(rg.INSTALL_EXE.read_bytes(), b"new")

    def test_failed_write_restores_the_old_exe(self):
        def boom():
            raise OSError("disk full")
        with self.assertRaises(OSError):
            rg.replace_install_exe(boom)
        self.assertEqual(rg.INSTALL_EXE.read_bytes(), b"old version")

    def test_spawned_exe_gets_a_fresh_pyinstaller_environment(self):
        seen = {}
        env = {"PATH": "x", "_PYI_APPLICATION_HOME_DIR": r"C:\Temp\_MEI123", "_PYI_PARENT_PROCESS_LEVEL": "1",
               "_MEIPASS2": r"C:\Temp\_MEI123"}
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(rg.subprocess, "Popen", lambda args, **kw: seen.update(args=args, **kw)):
            rg.spawn_installed("--gui")
        self.assertEqual(seen["args"], [str(rg.INSTALL_EXE), "--gui"])
        self.assertEqual(seen["env"].get("PYINSTALLER_RESET_ENVIRONMENT"), "1")
        self.assertFalse([k for k in seen["env"] if k.startswith("_PYI_") or k == "_MEIPASS2"])
        self.assertEqual(seen["env"]["PATH"], "x")

    def test_restart_only_when_running_on_borrowed_files(self):
        def restarted(meipass, ppid, env=None):
            calls = []
            with mock.patch.object(rg, "FROZEN", True), mock.patch.object(rg, "IS_WINDOWS", True), \
                    mock.patch.object(rg.sys, "_MEIPASS", meipass, create=True), \
                    mock.patch.object(rg.os, "getppid", lambda: ppid), \
                    mock.patch.dict(os.environ, env or {}), \
                    mock.patch.object(rg.subprocess, "Popen", lambda args, **kw: calls.append(kw["env"])):
                os.environ.pop("RG_FRESH_START", None) if not env else None
                return rg.restart_if_borrowed_files(), calls
        self.assertEqual(restarted(r"C:\Temp\_MEI223522", 22352), (False, []))  # unpacked by our parent
        did, calls = restarted(r"C:\Temp\_MEI224922", 1220)                      # someone else's files
        self.assertTrue(did)
        self.assertEqual(calls[0]["RG_FRESH_START"], "1")
        self.assertEqual(restarted(r"C:\Temp\_MEI224922", 1220, {"RG_FRESH_START": "1"}), (False, []))  # once only
        self.assertEqual(restarted(r"C:\Temp\custom_dir", 1220), (False, []))   # unknown folder name

    def test_failed_install_restarts_the_previous_monitor(self):
        started = []

        def broken(report, update=True):
            raise FileNotFoundError("base_library.zip")
        with mock.patch.object(rg, "stop_monitor", lambda: None), mock.patch.object(rg, "_install", broken), \
                mock.patch.object(rg, "task_state", lambda: "Ready"), \
                mock.patch.object(rg, "start_monitor", lambda: started.append(1) or True):
            with self.assertRaises(FileNotFoundError):
                rg.install(lambda m: None)
        self.assertEqual(started, [1])

    def uninstall(self):
        msgs = []
        with mock.patch.object(rg, "stop_monitor", lambda: None), mock.patch.object(rg, "_ps", lambda c: (0, "", "")), \
                mock.patch.object(rg, "task_state", lambda: ""), mock.patch.object(rg, "remove_canaries", lambda: None), \
                mock.patch.object(rg, "desktop_lnk", lambda: self.dir / "RansomGuard.lnk"):
            rg.uninstall(msgs.append)
        return msgs

    def test_health_check_is_installed_and_removed(self):
        cmds = []
        with mock.patch.object(rg, "_ps", lambda c: cmds.append(c) or (0, "", "")):
            rg.install_health_check(lambda m: None)
        js = rg.INSTALL_DIR / "health_check.js"
        self.assertEqual(js.read_bytes()[:2], b"\xff\xfe")  # UTF-16 with BOM, so Chinese text survives
        self.assertIn('var TASK = "RansomGuard";', js.read_text(encoding="utf-16"))
        self.assertIn("wscript.exe", cmds[0])
        self.assertIn(str(js), cmds[0])
        self.assertIn("-Trigger $t1, $t2", cmds[0])
        self.assertIn("RunLevel Limited", cmds[0])
        cmds.clear()
        with mock.patch.object(rg, "stop_monitor", lambda: None), \
                mock.patch.object(rg, "_ps", lambda c: cmds.append(c) or (0, "", "")), \
                mock.patch.object(rg, "task_state", lambda: ""), mock.patch.object(rg, "remove_canaries", lambda: None), \
                mock.patch.object(rg, "desktop_lnk", lambda: self.dir / "RansomGuard.lnk"):
            rg.uninstall(lambda m: None)
        self.assertTrue(any("Unregister-ScheduledTask" in c and rg.HEALTH_TASK in c for c in cmds))

    def health(self, task, state=None):
        """Run the real health check script (read-only) in test mode against a scheduled task."""
        js = self.dir / "health_check.js"
        js.write_text(rg.HEALTH_JS, encoding="utf-16")
        app = self.dir / "app"
        app.mkdir(exist_ok=True)
        (app / "state.json").write_text(json.dumps(state or {}), encoding="utf-8")
        env = dict(os.environ, RG_HEALTH_TEST="1", RG_HEALTH_TASK=task, RG_HEALTH_APPDIR=str(app),
                   RG_HEALTH_STATE=str(app))
        r = subprocess.run([os.path.join(os.environ["SystemRoot"], "System32", "cscript.exe"), "//Nologo", str(js)],
                           capture_output=True, env=env, timeout=60)
        return r.stdout.decode("ascii", "replace").strip()

    def test_health_check_script(self):
        self.assertEqual(self.health("RansomGuard_no_such_task_" + os.urandom(3).hex()), "removed")
        defrag = r"\Microsoft\Windows\Defrag\ScheduledDefrag"  # exists, not running, its program exists
        if self.health(defrag) == "removed":
            self.skipTest("this Windows has no defrag task")
        self.assertEqual(self.health(defrag), "stopped")
        self.assertEqual(self.health(defrag, {"triggered_at": "2026-11-02 10:00:00"}), "ok")  # stopped on purpose

    def test_uninstall_removes_the_whole_folder(self):
        for name in ("icon.ico", "RansomGuard.old-1234abcd.exe"):
            (rg.INSTALL_DIR / name).write_bytes(b"x")
        self.uninstall()
        self.assertFalse(rg.INSTALL_DIR.exists())

    def test_uninstall_with_a_file_still_running(self):
        running = rg.INSTALL_DIR / "RansomGuard.old-running.exe"
        shutil.copy2(os.path.join(os.environ["SystemRoot"], "System32", "PING.EXE"), running)
        proc = subprocess.Popen([str(running), "-n", "30", "127.0.0.1"], stdout=subprocess.DEVNULL)
        self.addCleanup(proc.wait)
        self.addCleanup(proc.kill)
        msgs = self.uninstall()
        self.assertFalse(rg.INSTALL_EXE.exists())
        self.assertTrue(any("next restart" in m for m in msgs), msgs)

    def test_cleanup_old_files(self):
        appdir = self.dir / "app"
        appdir.mkdir()
        old = [rg.INSTALL_DIR / "RansomGuard.old-1234abcd.exe", rg.INSTALL_DIR / "RansomGuard.old-5678ef90.exe",
               appdir / "alert.json", appdir / "alert.ps1"]
        keep = [appdir / "guard.log", appdir / "settings.json", appdir / "state.json"]
        for p in old + keep:
            p.write_bytes(b"x")
        running = rg.INSTALL_DIR / "RansomGuard.old-running.exe"
        shutil.copy2(os.path.join(os.environ["SystemRoot"], "System32", "PING.EXE"), running)
        proc = subprocess.Popen([str(running), "-n", "30", "127.0.0.1"], stdout=subprocess.DEVNULL)
        self.addCleanup(proc.wait)
        self.addCleanup(proc.kill)
        with mock.patch.object(rg, "app_dir", lambda: appdir):
            rg.cleanup_old_files()  # must not fail on the one that is still running
        self.assertFalse(any(p.exists() for p in old))
        self.assertTrue(all(p.exists() for p in keep))
        self.assertTrue(rg.INSTALL_EXE.exists())

    def test_replacing_a_running_exe(self):
        shutil.copy2(os.path.join(os.environ["SystemRoot"], "System32", "PING.EXE"), rg.INSTALL_EXE)
        proc = subprocess.Popen([str(rg.INSTALL_EXE), "-n", "30", "127.0.0.1"], stdout=subprocess.DEVNULL)
        self.addCleanup(proc.wait)
        self.addCleanup(proc.kill)
        rg.replace_install_exe(lambda: rg.INSTALL_EXE.write_bytes(b"new"))
        self.assertEqual(rg.INSTALL_EXE.read_bytes(), b"new")


class UpdateNotificationTests(UpdateTests):
    def test_check_for_update(self):
        with mock.patch.object(rg, "FROZEN", True):
            with self.serve(tag="v1.5.0"):
                self.assertEqual(rg.check_for_update(), "1.5.0")
            with self.serve(tag="v1.2.0"):
                self.assertIsNone(rg.check_for_update())
            with self.serve(api_error=OSError("offline")):
                self.assertIsNone(rg.check_for_update())
        with self.serve(tag="v1.5.0"):  # running from source: never offers the exe
            self.assertIsNone(rg.check_for_update())

    def test_check_for_updates_button(self):
        # the button reports what it found and returns the newer version; it never installs by itself
        def check(**serve):
            msgs = []
            with mock.patch.object(rg, "FROZEN", True), self.serve(**serve):
                return rg.check_updates(msgs.append), msgs[-1]
        self.assertEqual(check(tag="v1.5.0"), ("1.5.0", "Version 1.5.0 is available (you have v1.2.0)."))
        self.assertEqual(check(tag="v1.2.0"), (None, "You have the latest version (v1.2.0)."))
        new, msg = check(api_error=OSError("offline"))
        self.assertIsNone(new)
        self.assertTrue(msg.startswith("[Failed] Could not reach GitHub"))
        self.assertEqual(rg.INSTALL_EXE.read_bytes(), b"old version", "checking must not install anything")
        msgs = []  # running from source: GitHub isn't even asked (urlopen is forbidden in the tests)
        self.assertIsNone(rg.check_updates(msgs.append))
        self.assertIn("git pull", msgs[-1])

    def run_watcher(self, versions, answer, seconds=1.0):
        asked, launched = [], []
        stop = threading.Event()
        checks = iter(versions)
        with mock.patch.object(rg, "UPDATE_CHECK_DELAY", 0), mock.patch.object(rg, "UPDATE_CHECK_INTERVAL", 0.05), \
                mock.patch.object(rg, "auto_update_check", lambda: True), \
                mock.patch.object(rg, "check_for_update", lambda: next(checks, versions[-1])), \
                mock.patch.object(rg, "ask_update", lambda v: asked.append(v) or answer), \
                mock.patch.object(rg.subprocess, "Popen", lambda args, **kw: launched.append(args)):
            t = threading.Thread(target=rg.update_watcher, args=(stop,))
            t.start()
            time.sleep(seconds)
            stop.set()
            t.join(5)
        self.assertFalse(t.is_alive(), "update watcher did not stop")
        return asked, launched

    def test_watcher_asks_once_per_version(self):
        asked, launched = self.run_watcher([None, "1.5.0", "1.5.0", "1.5.0", "1.6.0"], answer=False)
        self.assertEqual(asked, ["1.5.0", "1.6.0"])
        self.assertEqual(launched, [])

    def test_watcher_opens_the_control_panel_to_update(self):
        asked, launched = self.run_watcher(["1.5.0"], answer=True, seconds=0.3)
        self.assertEqual(asked, ["1.5.0"])
        self.assertEqual(launched, [[str(rg.INSTALL_EXE), "--update"]])

    def test_automatic_update_checks_are_off_unless_turned_on(self):
        # every check shows GitHub the computer's IP address, so none happens by default
        checks, stop = [], threading.Event()
        with mock.patch.object(rg, "app_dir", lambda: self.dir), mock.patch.object(rg, "UPDATE_CHECK_DELAY", 0), \
                mock.patch.object(rg, "UPDATE_CHECK_INTERVAL", 0.05), \
                mock.patch.object(rg, "check_for_update", lambda: checks.append(1)):
            self.assertFalse(rg.auto_update_check())
            t = threading.Thread(target=rg.update_watcher, args=(stop,))
            t.start()
            time.sleep(0.3)
            self.assertEqual(checks, [], "no automatic check while it is off")
            rg.set_setting("auto_update_check", True)  # turned on in the control panel: applies at once
            time.sleep(0.3)
            stop.set()
            t.join(5)
            self.assertTrue(checks)
            self.assertEqual(rg.load_settings()["auto_update_check"], True)

    def test_uninstall_deletes_the_log_and_settings(self):
        app = self.dir / "LocalAppData" / "RansomGuard"
        app.mkdir(parents=True)
        for name in ("guard.log", "guard.log.1", "state.json", "settings.json"):
            (app / name).write_text("x", encoding="utf-8")
        msgs = []
        with mock.patch.object(rg, "app_dir", lambda: app):
            rg.remove_app_data(msgs.append)
        self.assertFalse(app.exists())
        self.assertIn("Deleted the log and settings", msgs[0])


# ---------------------------------------------------------------- the log's privacy: kept 30 days, can be cleared
class LogPrivacyTests(TempDirTest):
    def stamp(self, days_ago):
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - days_ago * 86400)) + ",000"

    def test_entries_older_than_30_days_are_removed(self):
        log_file = self.dir / "guard.log"
        log_file.write_text(
            f"{self.stamp(40)} [INFO] old: C:\\Users\\someone\\secret.docx\n"
            f"{self.stamp(35)} [ERROR] old failure\nTraceback (most recent call last):\n  old detail\n"
            f"{self.stamp(2)} [INFO] recent entry\nTraceback (most recent call last):\n  recent detail\n"
            f"{self.stamp(0)} [INFO] today\n", encoding="utf-8")
        old_part = self.dir / "guard.log.2"
        old_part.write_text("old part", encoding="utf-8")
        os.utime(old_part, (time.time() - 40 * 86400,) * 2)
        recent_part = self.dir / "guard.log.1"
        recent_part.write_text("recent part", encoding="utf-8")
        rg.prune_log(log_file)
        text = log_file.read_text(encoding="utf-8")
        self.assertNotIn("old", text)
        self.assertTrue(text.startswith(self.stamp(2)[:10]))
        self.assertIn("recent detail", text)
        self.assertIn("today", text)
        self.assertFalse(old_part.exists())
        self.assertTrue(recent_part.exists())
        rg.prune_log(self.dir / "missing.log")  # no log yet: nothing to do

    def test_the_running_monitor_prunes_its_own_open_log(self):
        # the monitor can run for weeks, so it prunes daily although it has the log open itself
        log_file = self.dir / "guard.log"
        log_file.write_text(f"{self.stamp(40)} [INFO] old entry\n", encoding="utf-8")
        handler = logging.FileHandler(log_file, encoding="utf-8")
        self.addCleanup(handler.close)
        rg.log.addHandler(handler)
        self.addCleanup(rg.log.removeHandler, handler)
        handler.emit(logging.makeLogRecord({"msg": f"{self.stamp(0)} [INFO] recent entry"}))
        handler.flush()
        with mock.patch.object(rg, "app_dir", lambda: self.dir):
            rg.prune_own_log()
        self.assertNotIn("old entry", log_file.read_text(encoding="utf-8"))
        handler.emit(logging.makeLogRecord({"msg": "after"}))  # the handler reopens the file by itself
        handler.flush()
        self.assertTrue(log_file.read_text(encoding="utf-8").rstrip().endswith("after"))

    def test_clear_log_empties_it_while_another_handle_keeps_writing(self):
        log_file = self.dir / "guard.log"
        (self.dir / "guard.log.1").write_text("older part", encoding="utf-8")
        handler = logging.FileHandler(log_file, encoding="utf-8")  # like the background monitor's open log
        self.addCleanup(handler.close)
        handler.emit(logging.makeLogRecord({"msg": "C:\\Users\\someone\\secret.docx"}))
        handler.flush()
        with mock.patch.object(rg, "app_dir", lambda: self.dir):
            self.assertTrue(rg.clear_log())
        self.assertEqual(log_file.read_text(encoding="utf-8"), "")
        self.assertFalse((self.dir / "guard.log.1").exists())
        handler.emit(logging.makeLogRecord({"msg": "after"}))
        handler.flush()
        self.assertEqual(log_file.read_text(encoding="utf-8").strip(), "after")


# ---------------------------------------------------------------- process monitor (real WMI, harmless marker)
class ProcessMonitorTests(unittest.TestCase):
    def test_new_process_is_seen(self):
        marker = "rgtest-" + os.urandom(4).hex()
        hits = []
        got = threading.Event()
        with mock.patch.object(rg, "DANGEROUS_CMDS", [(rg.re.compile(marker), "test", "test")]):
            pm = rg.ProcessMonitor(lambda r: (hits.append(r), got.set()), kill=False)
            pm.start()
            self.addCleanup(pm.stop)
            time.sleep(4)  # let the WMI subscription start
            # without administrator rights only WMI polling (every 0.5 s) can see it. It lives ~1 s: the
            # polling catches ~0.4 s processes on an idle computer, but its interval stretches when the
            # computer is busy (e.g. Defender scanning the files other tests write), and 0.4 s then failed
            subprocess.run(f'cmd.exe /c ""{sys.executable}" -c "import time; time.sleep(1)" & rem {marker}"')
            got.wait(15)
        self.assertTrue(hits, "process monitor did not report the marked process")
        self.assertIn("cmd.exe", hits[0])

    def test_stop_monitor_recognizes_old_and_new_process_monitors(self):
        old_script = ("\n[Console]::OutputEncoding = [System.Text.Encoding]::UTF8\n"
                      "$q = \"SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'\"\n")
        self.assertEqual(rg.ps_encoded_args(old_script)[-1][:120], rg.ps_encoded_args(rg.PROC_PS1)[-1][:120])


# ---------------------------------------------------------------- pausing the program that writes the most
WIN = os.environ.get("SystemRoot", r"C:\Windows")


class PauseTests(TempDirTest):
    def patch(self, name, value):
        p = mock.patch.object(rg, name, value)
        p.start()
        self.addCleanup(p.stop)

    def fake_writers(self, rows, paths):
        """write_counters() sees `rows` [(pid, name)] each write 100 times / 1 MB during the sample."""
        counters = iter([{}, {pid: (name, 100, 10 ** 6) for pid, name in rows}])
        self.patch("write_counters", lambda: next(counters))
        self.patch("process_path", lambda pid: paths.get(pid, ""))
        self.calls = []
        self.patch("set_paused", lambda pid, paused: self.calls.append((pid, paused)) or True)
        p = mock.patch.object(rg.time, "sleep")
        p.start()
        self.addCleanup(p.stop)

    def test_heaviest_writers(self):
        kb = 1024
        before = {1: ("a.exe", 100, 0), 2: ("b.exe", 0, 0), 3: ("old.exe", 0, 0), 4: ("quiet.exe", 0, 0)}
        after = {1: ("a.exe", 200, 900 * kb),
                 2: ("b.exe", 500, 5000 * kb),       # the most data comes first
                 3: ("new.exe", 30, 300 * kb),       # PID reused by another program: everything counts
                 4: ("quiet.exe", 10, 10000 * kb),   # too few writes
                 5: ("started.exe", 50, 400 * kb),   # started during the sample
                 6: ("small.exe", 500, 100 * kb)}    # too little data
        self.assertEqual([r[0] for r in rg.heaviest_writers(before, after)], [2, 1, 5, 3])
        self.assertEqual(rg.heaviest_writers(before, after)[1], (1, "a.exe", 100, 900 * kb))

    def test_windows_processes_are_trusted_only_in_their_own_folder(self):
        self.assertTrue(rg.trusted_process("svchost.exe", rf"{WIN}\System32\svchost.exe"))
        self.assertTrue(rg.trusted_process("Explorer.EXE", rf"{WIN}\explorer.exe"))
        self.assertTrue(rg.trusted_process("MsMpEng.exe", ""))  # protected: its path can't be read
        self.assertFalse(rg.trusted_process("svchost.exe", r"C:\Users\u\AppData\Local\Temp\svchost.exe"))
        self.assertFalse(rg.trusted_process("svchost.exe", WIN + r"x\svchost.exe"))
        self.assertFalse(rg.trusted_process("powershell.exe",
                                            rf"{WIN}\System32\WindowsPowerShell\v1.0\powershell.exe"))

    def test_heaviest_writers_are_paused_but_not_windows(self):
        self.fake_writers([(1, "svchost.exe"), (2, "evil.exe"), (3, "a.exe"), (4, "b.exe"), (5, "c.exe")],
                          {1: rf"{WIN}\System32\svchost.exe", 2: r"C:\Users\u\evil.exe"})
        self.patch("PAUSE_MAX", 3)
        found = rg.pause_writers(dry_run=False)
        self.assertEqual([p["pid"] for p in found], [2, 3, 4])  # at most PAUSE_MAX
        self.assertEqual(self.calls, [(2, True), (3, True), (4, True)])
        self.assertEqual(found[0], {"pid": 2, "name": "evil.exe", "path": r"C:\Users\u\evil.exe",
                                    "paused": True, "result": "paused"})

    def test_test_mode_pauses_nothing(self):
        self.fake_writers([(2, "evil.exe")], {2: r"C:\Users\u\evil.exe"})
        found = rg.pause_writers(dry_run=True)
        self.assertEqual(self.calls, [])
        self.assertEqual([(p["pid"], p["paused"]) for p in found], [(2, False)])

    def test_trigger_pauses_saves_and_asks_defender(self):
        evil = {"pid": 7, "name": "evil.exe", "path": r"C:\x\evil.exe", "paused": True, "result": "paused"}
        alerts, asked, done = [], [], threading.Event()
        self.patch("app_dir", lambda: self.dir)
        self.patch("IS_WINDOWS", True)
        self.patch("pause_writers", lambda dry_run: [evil])
        self.patch("disconnect_network", lambda: True)
        self.patch("fullscreen_alert", lambda reason, status, paused=(): alerts.append((status, paused)))
        self.patch("ask_defender", lambda paths: (asked.append(paths), done.set()))
        self.addCleanup(rg.init_lang, "en")
        rg.respond("test", dry_run=False)
        done.wait(5)
        self.assertEqual(rg.load_state()["paused"], [evil])
        self.assertEqual(asked, [[r"C:\x\evil.exe"]])
        self.assertEqual(alerts, [("cut", [evil])])

    def test_trigger_cuts_the_network_even_if_the_state_cannot_be_saved(self):
        cut = []
        self.patch("app_dir", lambda: self.dir)
        self.patch("IS_WINDOWS", True)
        self.patch("pause_writers", lambda dry_run: [{"pid": 7, "name": "e.exe", "path": "", "paused": True,
                                                      "result": "paused"}])
        self.patch("save_state", mock.Mock(side_effect=OSError("disk full")))
        self.patch("disconnect_network", lambda: cut.append(1) or True)
        self.patch("fullscreen_alert", lambda reason, status, paused=(): None)
        self.patch("ask_defender", lambda paths: None)
        self.addCleanup(rg.init_lang, "en")
        rg.respond("test", dry_run=False)
        self.assertEqual(cut, [1])

    def test_false_alarm_resumes_only_clean_programs(self):
        paused = [{"pid": 1, "name": "ok.exe", "path": r"C:\a\ok.exe"},
                  {"pid": 2, "name": "bad.exe", "path": r"C:\a\bad.exe"},
                  {"pid": 3, "name": "gone.exe", "path": r"C:\a\gone.exe"},  # its PID now belongs to another program
                  {"pid": 4, "name": "unknown.exe", "path": ""}]
        self.fake_writers([], {1: r"C:\a\ok.exe", 2: r"C:\a\bad.exe", 3: r"C:\b\new.exe", 4: r"C:\c.exe"})
        self.patch("defender_scan", lambda path: {r"C:\a\ok.exe": 0, r"C:\a\bad.exe": 2}[path])
        msgs = []
        rg.resume_paused(paused, msgs.append)
        self.assertEqual(self.calls, [(1, False)])
        self.assertEqual(len(msgs), 5)
        self.assertIn("bad.exe (PID 2) stays paused", msgs[2])

    def fake_tree(self, tree, started):
        """tree: {pid: (parent pid, name, path)}; started: {pid: start time}."""
        self.patch("process_list", lambda: [(pid, parent, name) for pid, (parent, name, _) in tree.items()])
        self.patch("process_path", lambda pid: tree[pid][2] if pid in tree else "")
        self.patch("process_started", lambda pid: started.get(pid))
        self.calls = []
        self.patch("set_paused", lambda pid, paused: self.calls.append((pid, paused)) or True)

    def test_program_behind_a_destructive_command_is_paused(self):
        # explorer -> evil.exe -> cmd.exe -> (vssadmin, already stopped)
        tree = {30: (1, "explorer.exe", rf"{WIN}\explorer.exe"), 40: (30, "evil.exe", r"C:\Users\u\evil.exe"),
                50: (40, "cmd.exe", rf"{WIN}\System32\cmd.exe")}
        self.fake_tree(tree, {30: 100, 40: 200, 50: 300})
        found = rg.pause_ancestors(50, dry_run=False)
        self.assertEqual([p["pid"] for p in found], [50, 40])  # stops at explorer.exe
        self.assertEqual(self.calls, [(50, True), (40, True)])

    def test_a_reused_pid_is_not_taken_for_a_parent(self):
        tree = {40: (30, "unrelated.exe", r"C:\x\unrelated.exe"), 50: (40, "cmd.exe", rf"{WIN}\System32\cmd.exe")}
        self.fake_tree(tree, {40: 900, 50: 300})  # "parent" 40 started after its child: the real one has exited
        self.assertEqual([p["pid"] for p in rg.pause_ancestors(50, dry_run=False)], [50])

    def test_ancestors_stop_at_this_program_and_in_test_mode_nothing_is_paused(self):
        me = os.getpid()
        tree = {me: (1, "RansomGuard.exe", r"C:\x\RansomGuard.exe"), 50: (me, "cmd.exe", rf"{WIN}\System32\cmd.exe")}
        self.fake_tree(tree, {me: 100, 50: 300})
        found = rg.pause_ancestors(50, dry_run=True)
        self.assertEqual([(p["pid"], p["paused"]) for p in found], [(50, False)])
        self.assertEqual(self.calls, [])

    def test_programs_paused_behind_a_command_are_recorded_at_once(self):
        # also after a first trigger, when no respond() follows to record them
        evil = {"pid": 40, "name": "evil.exe", "path": r"C:\x\evil.exe", "paused": True, "result": "paused"}
        hits = []
        self.patch("app_dir", lambda: self.dir)
        self.patch("pause_ancestors", lambda ppid, dry_run: [dict(evil)])
        self.addCleanup(rg._early_paused.clear)
        marker = "rgtest-" + os.urandom(4).hex()
        with mock.patch.object(rg, "DANGEROUS_CMDS", [(rg.re.compile(marker), "test", "test")]), \
                mock.patch.object(rg.os, "kill", lambda pid, sig: None):
            pm = rg.ProcessMonitor(hits.append, kill=True)
            pm._check(100, 40, "cmd.exe", f"cmd /c {marker}")
            pm._check(101, 40, "cmd.exe", f"cmd /c {marker}")  # the same program again
        self.assertEqual(len(hits), 2)
        self.assertEqual(rg.load_state()["paused"], [evil])
        rg.record_paused([{**evil, "pid": 41}, {**evil, "pid": 42, "paused": False}])
        self.assertEqual([p["pid"] for p in rg.load_state()["paused"]], [40, 41])

    def test_trigger_reports_programs_paused_early_once(self):
        evil = {"pid": 40, "name": "evil.exe", "path": r"C:\x\evil.exe", "paused": True, "result": "paused"}
        alerts = []
        self.patch("app_dir", lambda: self.dir)
        self.patch("IS_WINDOWS", True)
        self.patch("pause_writers", lambda dry_run: [dict(evil), {**evil, "pid": 41, "name": "other.exe"}])
        self.patch("disconnect_network", lambda: True)
        self.patch("fullscreen_alert", lambda reason, status, paused=(): alerts.append(paused))
        self.patch("ask_defender", lambda paths: None)
        self.addCleanup(rg.init_lang, "en")
        rg._early_paused.append(evil)
        rg.respond("test", dry_run=False)
        self.assertEqual([p["pid"] for p in alerts[0]], [40, 41])
        self.assertEqual(rg._early_paused, [])

    def test_real_chain_of_parents_is_paused(self):
        # this test -> A -> B, all harmless Python processes; B's parent chain is paused up to this test.
        # BASE_PYTHON, not a venv's launcher, which would add a process to each level
        code_b = "import time; time.sleep(60)"
        code_a = ("import subprocess, sys, time\n"
                  f"b = subprocess.Popen([sys.executable, '-c', {code_b!r}])\n"
                  "print(b.pid, flush=True)\ntime.sleep(60)\n")
        a = subprocess.Popen([BASE_PYTHON, "-c", code_a], stdout=subprocess.PIPE)
        b_pid = int(a.stdout.readline())
        self.addCleanup(a.stdout.close)
        self.addCleanup(a.wait)
        self.addCleanup(a.kill)
        self.addCleanup(lambda: subprocess.run(["taskkill", "/F", "/PID", str(b_pid)], capture_output=True))
        self.assertLess(rg.process_started(a.pid), rg.process_started(b_pid))
        found = rg.pause_ancestors(b_pid, dry_run=False)
        self.assertEqual([p["pid"] for p in found], [b_pid, a.pid])
        self.assertTrue(all(p["paused"] for p in found))
        for p in found:
            self.assertTrue(rg.set_paused(p["pid"], False))

    def test_process_path_of_this_process(self):
        # in a venv, sys.executable is a launcher that starts the real interpreter: this process is the latter
        self.assertEqual(rg.norm(rg.process_path(os.getpid())), rg.norm(BASE_PYTHON))
        self.assertEqual(rg.process_path(0x7FFFFFF0), "")  # no such process

    def test_warning_does_not_flash(self):
        # the background is set once when the window is built; changing it in the timer made it flash
        self.assertEqual(rg.ALERT_PS1.count("BackColor = $script:bright"), 1)
        timer = rg.ALERT_PS1[rg.ALERT_PS1.index("$timer.add_Tick"):]
        self.assertNotIn("BackColor", timer)

    def test_build_script_packs_the_icon(self):
        # without these the exe shows PyInstaller's default icon (v1.5.4 to v1.6.1 were built that way)
        script = (ROOT / "build.bat").read_text(encoding="utf-8")
        self.assertIn(r"--icon ..\icon.ico", script)
        self.assertIn(r'--add-data "..\icon.ico;."', script)
        self.assertIn("check_build.py", script)  # an exe without Tcl/Tk data doesn't start (v1.7.1)

    def test_build_check_finds_a_missing_tcl_tk(self):
        sys.path.insert(0, str(ROOT))
        try:
            import check_build
        except ImportError:
            self.skipTest("PyInstaller is not installed (pip install -r requirements-build.txt)")
        good = ["icon.ico", "tk86t.dll", "tcl86t.dll", "_tcl_data/init.tcl", "_tk_data/tk.tcl", "base_library.zip"]
        self.assertEqual(check_build.missing(good), [])
        v171 = ["icon.ico", "tcl90.dll", "base_library.zip"]  # what the broken v1.7.1 contained
        self.assertEqual(len(check_build.missing(v171)), 3)
        self.assertEqual(check_build.missing([n for n in good if n != "icon.ico"]), ["icon (icon.ico)"])
        modules = {"ransomguard"} | {m.__name__ for m in MODULES}
        self.assertEqual(check_build.missing_modules(modules), [])
        self.assertEqual(check_build.missing_modules(modules - {"ransomguard.gui"}), ["ransomguard.gui"])

    def test_real_writer_is_found_paused_and_resumed(self):
        # a harmless child that keeps overwriting the start of one file in a temp folder
        code = ("import os, sys, time\nprint(os.getpid(), flush=True)\nf = open(sys.argv[1], 'wb', buffering=0)\n"
                "while True:\n    f.seek(0); f.write(b'x' * 65536); time.sleep(0.005)\n")
        p = subprocess.Popen([sys.executable, "-c", code, str(self.dir / "w.bin")], stdout=subprocess.PIPE)
        self.addCleanup(p.stdout.close)
        self.addCleanup(p.wait)
        self.addCleanup(p.kill)
        pid = int(p.stdout.readline())
        with mock.patch.object(rg.os, "getpid", lambda: 0):  # write_counters() skips this program's children
            before = rg.write_counters()
            time.sleep(1)
            after = rg.write_counters()
            self.assertIn(pid, [r[0] for r in rg.heaviest_writers(before, after)])
            self.assertTrue(rg.process_path(pid).lower().endswith(".exe"))
            self.assertTrue(rg.set_paused(pid, True))
            time.sleep(0.3)
            w1 = rg.write_counters()[pid][1]
            time.sleep(0.5)
            self.assertEqual(rg.write_counters()[pid][1], w1, "a paused process must not write")
            self.assertTrue(rg.set_paused(pid, False))
            time.sleep(0.5)
            self.assertGreater(rg.write_counters()[pid][1], w1, "a resumed process writes again")


# ---------------------------------------------------------------- scanning new downloads with Defender
class DownloadScanTests(TempDirTest):
    def setUp(self):
        super().setUp()
        self.dl, self.desk = self.dir / "Downloads", self.dir / "Desktop"
        p = mock.patch.object(rg, "_known_folder", lambda name: self.dir / name)
        p.start()
        self.addCleanup(p.stop)
        self.found = []
        self.s = rg.DownloadScanner(self.found.append)

    def test_which_files_are_scanned(self):
        for path in (self.dl / "setup.exe", self.dl / "sub" / "invoice.js", self.dl / "a.ZIP",
                     self.desk / "tool.msi", self.desk / "Shortcut.lnk"):
            self.assertTrue(self.s.wanted(path), path)
        for path in (self.dl / "photo.jpg", self.dl / "setup.exe.crdownload", self.desk / "project" / "app.js",
                     self.dir / "Documents" / "setup.exe", self.dir / "Downloads2" / "setup.exe"):
            self.assertFalse(self.s.wanted(path), path)

    def test_queue_skips_duplicates_and_overflow(self):
        self.s.add(self.dl / "a.exe")
        self.s.add(self.dl / "A.EXE")
        self.s.add(self.dl / "a.txt")
        self.assertEqual(len(self.s.pending), 1)
        with mock.patch.object(rg, "SCAN_QUEUE_MAX", 3):
            for i in range(5):
                self.s.add(self.dl / f"b{i}.exe")
        self.assertEqual(len(self.s.pending), 3)

    def test_only_threats_are_reported(self):
        codes = {"clean.exe": 0, "evil.exe": 2, "broken.exe": None}
        with mock.patch.object(rg, "wait_until_written", lambda path: True), \
                mock.patch.object(rg, "defender_scan", lambda path, timeout: codes[Path(path).name]):
            for name in codes:
                self.s.scan(str(self.dl / name))
        with mock.patch.object(rg, "wait_until_written", lambda path: False), \
                mock.patch.object(rg, "defender_scan", lambda path, timeout: self.fail("vanished files are not scanned")):
            self.s.scan(str(self.dl / "gone.exe"))
        self.assertEqual(self.found, [str(self.dl / "evil.exe")])

    def test_wait_until_written(self):
        f = Path(self.file("Downloads/a.exe", b"MZ"))
        self.assertTrue(rg.wait_until_written(f, settle=0.05))
        self.assertFalse(rg.wait_until_written(self.dl / "missing.exe", settle=0.05))
        # Firefox's empty placeholder: the finished download is renamed onto it later (and scanned then)
        self.assertFalse(rg.wait_until_written(self.file("Downloads/b.exe", b""), settle=0.05))

    def test_a_file_defender_cannot_scan_is_not_a_threat(self):
        # MpCmdRun exits with 2 both for "threat found" and for "could not scan" (e.g. the file is gone)
        def fake_run(out):
            return lambda *a, **k: subprocess.CompletedProcess(a, 2, out, b"")
        with mock.patch.object(rg.subprocess, "run", fake_run(b"CmdTool: Failed with hr = 0x80070002.")):
            self.assertIsNone(rg.defender_scan(r"C:\gone.exe"))
        with mock.patch.object(rg.subprocess, "run", fake_run(b"Scanning C:\\evil.exe found 1 threats.")):
            self.assertEqual(rg.defender_scan(r"C:\evil.exe"), 2)

    @unittest.skipUnless(rg.MPCMDRUN.is_file(), "Microsoft Defender is not installed")
    def test_real_defender_scan(self):
        rc = rg.defender_scan(self.file("clean.txt", b"just text"))
        if rc is None:
            self.skipTest("Microsoft Defender is installed but not running (e.g. on a CI machine)")
        self.assertEqual(rc, 0)
        self.assertIsNone(rg.defender_scan(str(self.dir / "missing.exe")))

    def test_handler_reports_new_and_renamed_files(self):
        seen = []
        h = rg.make_handler([], lambda r: None, dry_run=True, on_new_file=seen.append)
        h.on_any_event(FileCreatedEvent(str(self.dl / "a.exe")))
        h.on_any_event(FileMovedEvent(str(self.dl / "b.exe.crdownload"), str(self.dl / "b.exe")))
        h.on_any_event(FileModifiedEvent(str(self.dl / "c.exe")))
        self.assertEqual(seen, [str(self.dl / "a.exe"), str(self.dl / "b.exe")])


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


class MonitorLoopTests(TempDirTest):
    def setUp(self):
        super().setUp()
        self.watch = self.dir / "watch"
        self.watch.mkdir()
        self.triggered = []
        StubProcessMonitor.instances = []
        for name, value in (("app_dir", lambda: self.dir), ("IS_WINDOWS", True), ("FROZEN", False),
                            ("is_admin", lambda: True), ("single_instance", lambda: True),
                            ("exit_with_launcher", lambda: None), ("cleanup_old_files", lambda: None),
                            ("ProcessMonitor", StubProcessMonitor), ("DEFENDER_SCAN_DOWNLOADS", False),
                            ("CHECK_INTERVAL", 0),
                            ("respond", lambda reason, dry_run: self.triggered.append((reason, dry_run)))):
            p = mock.patch.object(rg, name, value)
            p.start()
            self.addCleanup(p.stop)

    def start(self):
        self.stop = threading.Event()
        t = threading.Thread(target=rg.run, args=(argparse.Namespace(watch=[str(self.watch)], dry_run=False),
                                                  self.stop), daemon=True)
        t.start()
        self.addCleanup(lambda: (self.stop.set(), t.join(15)))
        time.sleep(1.5)  # canary files planted, file monitor running
        return t

    def wait_for(self, cond, timeout=10):
        end = time.time() + timeout
        while time.time() < end and not cond():
            time.sleep(0.1)

    def test_a_trigger_responds_once_and_monitoring_goes_on(self):
        t = self.start()
        canary = self.watch / rg.CANARY_NAMES[0]
        self.assertEqual(canary.read_bytes(), rg.canary_bytes(canary))
        overwrite(canary, b"encrypted")
        self.wait_for(lambda: self.triggered)
        (self.watch / rg.CANARY_NAMES[1]).unlink()  # a second hit doesn't trigger again
        time.sleep(2)
        self.assertEqual(len(self.triggered), 1)
        self.assertIn("Canary file", self.triggered[0][0])
        # it keeps running, so the scheduled task's every-few-minutes start doesn't start it again, and
        # dangerous commands are still stopped while the network is cut
        self.assertTrue(t.is_alive())
        pm = StubProcessMonitor.instances[0]
        self.assertTrue(pm.kill)
        self.assertFalse(pm.stopped)
        self.stop.set()
        t.join(15)
        self.assertFalse(t.is_alive())
        self.assertTrue(pm.stopped)

    def test_a_stopped_process_monitor_is_restarted(self):
        self.start()
        pm = StubProcessMonitor.instances[0]
        pm.dead = True
        self.wait_for(lambda: pm.starts >= 2)
        self.assertEqual(pm.starts, 2)

    def run_once(self):
        """Start the monitor and let it end right after starting."""
        stop = threading.Event()
        stop.set()
        rg.run(argparse.Namespace(watch=[str(self.watch)], dry_run=False), stop)

    def test_a_stop_by_the_user_holds_until_windows_restarts(self):
        with mock.patch.object(rg, "stop_monitor", lambda: None), mock.patch.object(rg, "boot_time", lambda: 1000.0):
            rg.stop_monitor_until_restart()
            self.assertTrue(rg.stopped_by_user())
            with self.assertRaises(SystemExit) as e:  # the task's next start finds it and leaves at once
                self.run_once()
            self.assertEqual(e.exception.code, 0)
            self.assertFalse(list(self.watch.iterdir()), "no canary files planted")
        with mock.patch.object(rg, "boot_time", lambda: 9000.0):  # Windows restarted since
            self.assertFalse(rg.stopped_by_user())
        with mock.patch.object(rg, "boot_time", lambda: 1000.0), mock.patch.object(rg, "_ps", lambda c: (0, "", "")), \
                mock.patch.object(rg, "task_state", lambda: "Running"), mock.patch.object(rg.time, "sleep"):
            self.assertTrue(rg.start_monitor())  # "Install and start monitoring" / restore clear it
            self.assertFalse(rg.stopped_by_user())

    def test_the_cut_network_is_brought_up_once_per_windows_start(self):
        rg.save_state({"triggered_at": "2026-11-04 10:00:00", "disabled_adapters": ["Wi-Fi"]})
        alerts = []
        with mock.patch.object(rg, "alert", lambda title, msg: alerts.append(msg)), \
                mock.patch.object(rg, "boot_time", lambda: 5000.0):
            self.run_once()
            self.run_once()  # started again by the task a few minutes later
        self.assertEqual(len(alerts), 1)
        with mock.patch.object(rg, "alert", lambda title, msg: alerts.append(msg)), \
                mock.patch.object(rg, "boot_time", lambda: 99000.0):
            self.run_once()  # after a restart: reminded again
        self.assertEqual(len(alerts), 2)
        self.assertEqual(rg.load_state()["disabled_adapters"], ["Wi-Fi"])

    def test_no_start_without_administrator_rights_or_when_already_running(self):
        args = argparse.Namespace(watch=[str(self.watch)], dry_run=False)
        with mock.patch.object(rg, "is_admin", lambda: False), self.assertRaises(SystemExit) as e:
            rg.run(args)
        self.assertEqual(e.exception.code, 1)
        with mock.patch.object(rg, "single_instance", lambda: False), self.assertRaises(SystemExit) as e:
            rg.run(args)
        self.assertEqual(e.exception.code, 0)
        self.assertFalse(list(self.watch.iterdir()), "no canary files planted")

    def test_periodic_check_finds_what_events_missed(self):
        canaries = rg.plant_canaries([self.watch])
        fired = []
        handler = mock.Mock(triggered_at=None, fire=fired.append)
        rg.periodic_check(handler, canaries)
        self.assertEqual(fired, [])
        canaries[0].unlink()
        rg.periodic_check(handler, canaries)
        self.assertIn("found by periodic check", fired[0])
        handler.triggered_at = time.time()  # already triggered: nothing more
        rg.periodic_check(handler, canaries)
        self.assertEqual(len(fired), 1)

    def test_canary_check_ignores_a_vanished_folder_and_locked_files(self):
        canaries = rg.plant_canaries([self.watch])
        with mock.patch.object(Path, "read_bytes", side_effect=PermissionError("locked by antivirus")):
            self.assertIsNone(rg.check_canaries(canaries))
        gone = [self.dir / "unlinked OneDrive" / rg.CANARY_NAMES[0]]
        self.assertIsNone(rg.check_canaries(gone))


# ---------------------------------------------------------------- command line
class CommandLineTests(unittest.TestCase):
    def main(self, *argv, frozen=False, admin=True, install=True):
        calls = []

        def fake_install(report):
            calls.append("install")
            if isinstance(install, Exception):
                raise install
            return install
        with mock.patch.object(rg.sys, "argv", ["RansomGuard", *argv]), mock.patch.object(rg, "FROZEN", frozen), \
                mock.patch.object(rg, "restart_if_borrowed_files", lambda: False), \
                mock.patch.object(rg, "fix_console_encoding", lambda: None), \
                mock.patch.object(rg, "setup_logging", lambda: None), mock.patch.object(rg, "is_admin", lambda: admin), \
                mock.patch.object(rg, "gui", lambda auto_update=False: calls.append(("gui", auto_update))), \
                mock.patch.object(rg, "run", lambda args: calls.append(("run", args.dry_run))), \
                mock.patch.object(rg, "install", fake_install), \
                mock.patch.object(rg, "restore_network", lambda report: calls.append("restore")), \
                mock.patch.object(rg, "fullscreen_alert",
                                  lambda reason, status, wait=False: calls.append(("warning", status, wait))):
            try:
                rg.main()
            except SystemExit as e:
                calls.append(("exit", e.code))
        return calls

    def test_each_option_starts_the_right_mode(self):
        self.assertEqual(self.main(), [("run", False)])                    # ransom_guard.py
        self.assertEqual(self.main(frozen=True), [("gui", False)])         # double-clicked exe
        self.assertEqual(self.main("--monitor", frozen=True), [("run", False)])  # the scheduled task
        self.assertEqual(self.main("--dry-run", frozen=True), [("run", True)])
        self.assertEqual(self.main("--gui"), [("gui", False)])
        self.assertEqual(self.main("--update", frozen=True), [("gui", True)])
        self.assertEqual(self.main("--restore"), ["restore"])
        self.assertEqual(self.main("--test-alert"), [("warning", "test", True)])

    def test_install_needs_administrator_rights_and_reports_failure(self):
        self.assertEqual(self.main("--install"), ["install", ("exit", 0)])
        self.assertEqual(self.main("--install", admin=False), [("exit", 1)])
        self.assertEqual(self.main("--install", install=False), ["install", ("exit", 1)])
        self.assertEqual(self.main("--install", install=OSError("disk full")), ["install", ("exit", 1)])

    def test_language_option(self):
        self.addCleanup(rg.init_lang, "en")
        self.main("--lang", "zh", "--restore")
        self.assertEqual(rg.LANG, "zh")


# ---------------------------------------------------------------- the full-screen warning's content
class WarningTests(unittest.TestCase):
    def show(self, reason, status, paused=(), exit_code=None):
        """Call the real fullscreen_alert() with PowerShell replaced; returns (process, shown info, args, alerts)."""
        seen, alerts = {}, []

        class FakeProc:
            def __init__(self, args, **kw):
                seen["args"], seen["env"] = args, kw["env"]
                self.stderr = io.BytesIO(b"window failed")

            def wait(self, timeout=None):
                if exit_code is None:  # still open = the warning is showing
                    raise subprocess.TimeoutExpired("powershell", timeout)
                return exit_code
        with mock.patch.object(rg, "fullscreen_alert", REAL["fullscreen_alert"]), \
                mock.patch.object(rg.subprocess, "Popen", FakeProc), mock.patch.object(rg, "IS_WINDOWS", True), \
                mock.patch.object(rg, "alert", lambda title, msg: alerts.append(msg)):
            proc = rg.fullscreen_alert(reason, status, paused=paused)
        info = json.loads(base64.b64decode(seen["env"]["RG_ALERT_INFO"]).decode("utf-8"))
        return proc, info, seen["args"], alerts

    def test_warning_names_the_reason_and_the_paused_programs(self):
        evil = {"pid": 7, "name": "evil.exe", "path": r"C:\x\evil.exe", "paused": True, "result": "paused"}
        proc, info, _, alerts = self.show("Canary file was modified", "cut", [evil])
        self.assertIsNotNone(proc)
        self.assertEqual(info["status"], "cut")
        self.assertEqual(info["t"]["net"], "The network has been cut off automatically")
        self.assertIn("Reason: Canary file was modified", info["t"]["detail"])
        self.assertIn("Suspicious programs: evil.exe (PID 7, paused)", info["t"]["detail"])
        self.assertEqual(alerts, [])

    def test_reason_stays_off_the_command_line_and_is_shortened(self):
        # a reason can quote a destructive command, and Defender blocks command lines containing one
        marker = "rgtest-" + os.urandom(4).hex()
        _, info, args, _ = self.show(marker + "x" * 300, "partial")
        self.assertNotIn(marker, " ".join(args))
        self.assertIn(marker, info["t"]["detail"])
        self.assertIn("x" * 140 + "...", info["t"]["detail"])
        self.assertNotIn("x" * 160, info["t"]["detail"])
        self.assertIn("may not be fully cut off", info["t"]["net"])

    def test_test_mode_says_so(self):
        _, info, _, _ = self.show("preview", "test")
        self.assertIn("Test mode", info["t"]["net"])
        self.assertIn("This is a test", info["t"]["hint"])

    def test_a_window_that_fails_falls_back_to_a_message_box(self):
        proc, _, _, alerts = self.show("Canary file was modified", "cut", exit_code=3)
        self.assertIsNone(proc)
        self.assertIn("Canary file was modified", alerts[0])


# ---------------------------------------------------------------- control panel status, keeping offline, scanning
class StatusAndOfflineTests(TempDirTest):
    def setUp(self):
        super().setUp()
        p = mock.patch.object(rg, "app_dir", lambda: self.dir)
        p.start()
        self.addCleanup(p.stop)

    def test_status_cards(self):
        def cards(task, state):
            rg.save_state(state)
            with mock.patch.object(rg, "task_state", lambda: task):
                (_, mon, _), (_, net, _) = rg.status_info()
            return mon, net
        self.assertEqual(cards("Running", {}), ("ok", "ok"))
        self.assertEqual(cards("Ready", {}), ("warn", "ok"))
        self.assertEqual(cards("", {}), ("off", "ok"))
        self.assertEqual(cards("Running", {"triggered_at": "2026-11-02 10:00:00"}), ("ok", "bad"))
        self.assertEqual(cards("Ready", {"firewall": [{"Name": "Domain", "Enabled": "True", "In": "Block",
                                                       "Out": "Allow"}]}), ("warn", "bad"))

    def test_network_turned_back_on_is_cut_again_while_the_warning_is_open(self):
        polls = iter([None, None, None, 0, 0])  # the warning closes after two checks
        cut = []
        with mock.patch.object(rg.time, "sleep"), mock.patch.object(rg, "adapters_up", lambda: "1"), \
                mock.patch.object(rg, "disconnect_network", lambda: cut.append(1)):
            rg.keep_offline(mock.Mock(poll=lambda: next(polls)))
        self.assertEqual(cut, [1])

    def test_download_scanner_worker_keeps_going_after_an_error(self):
        with mock.patch.object(rg, "_known_folder", lambda name: self.dir / name):
            s = rg.DownloadScanner(lambda path: None)
        seen, done = [], threading.Event()

        def scan(path):
            seen.append(Path(path).name)
            if len(seen) == 1:
                raise OSError("scan failed")
            done.set()
        s.scan = scan
        s.start()
        s.add(self.dir / "Downloads" / "a.exe")
        s.add(self.dir / "Downloads" / "b.exe")
        done.wait(5)
        self.assertEqual(seen, ["a.exe", "b.exe"])


# ---------------------------------------------------------------- installing the exe
class InstallTests(TempDirTest):
    def install(self, register_rc=0, update=True):
        exe = self.dir / "Downloads" / "RansomGuard.exe"
        exe.parent.mkdir(exist_ok=True)
        exe.write_bytes(b"MZ the version being installed")
        cmds, msgs = [], []

        def ps(cmd):
            cmds.append(cmd)
            return (register_rc, "", "access denied") if "-TaskName 'RansomGuard' " in cmd else (0, "", "")
        install_dir = self.dir / "Program Files" / "RansomGuard"
        self.checked_github = []
        with mock.patch.object(rg, "FROZEN", True), mock.patch.object(rg.sys, "executable", str(exe)), \
                mock.patch.object(rg, "INSTALL_DIR", install_dir), \
                mock.patch.object(rg, "INSTALL_EXE", install_dir / "RansomGuard.exe"), \
                mock.patch.object(rg, "fetch_update", lambda report: self.checked_github.append(1)), \
                mock.patch.object(rg, "_ps", ps), \
                mock.patch.object(rg, "_run", lambda args: None), mock.patch.object(rg, "start_monitor", lambda: True), \
                mock.patch.object(rg, "desktop_lnk", lambda: self.dir / "Desktop" / "RansomGuard.lnk"):
            ok = rg._install(msgs.append, update)
        return ok, install_dir, cmds

    def test_install_without_update_keeps_the_running_version(self):
        # for users who want to stay on the version they have: GitHub is not even asked
        ok, install_dir, _ = self.install(update=False)
        self.assertTrue(ok)
        self.assertEqual(self.checked_github, [])
        self.assertEqual((install_dir / "RansomGuard.exe").read_bytes(), b"MZ the version being installed")
        self.install()  # the update button does ask
        self.assertEqual(self.checked_github, [1])

    def test_install_copies_the_exe_and_creates_tasks_and_shortcut(self):
        ok, install_dir, cmds = self.install()
        self.assertTrue(ok)
        self.assertEqual((install_dir / "RansomGuard.exe").read_bytes(), b"MZ the version being installed")
        self.assertTrue((install_dir / "icon.ico").exists())
        self.assertTrue((install_dir / "health_check.js").exists())
        task = next(c for c in cmds if "-TaskName 'RansomGuard' " in c)
        self.assertIn(str(install_dir / "RansomGuard.exe"), task)
        self.assertIn("--monitor", task)
        self.assertIn("RunLevel Highest", task)
        # started again every few minutes if something ended it; never ended by that trigger itself
        self.assertIn("-Trigger $t, $t2", task)
        self.assertIn(f"-RepetitionInterval (New-TimeSpan -Minutes {rg.MONITOR_RESTART_MINUTES})", task)
        self.assertIn("$t2.Repetition.StopAtDurationEnd = $false", task)
        self.assertIn("-MultipleInstances IgnoreNew", task)
        self.assertTrue(any(rg.HEALTH_TASK in c for c in cmds))
        shortcut = next(c for c in cmds if "CreateShortcut" in c)
        self.assertIn(str(install_dir / "icon.ico"), shortcut)

    def test_a_failed_task_registration_stops_the_install(self):
        with self.assertRaises(RuntimeError):
            self.install(register_rc=1)


# ---------------------------------------------------------------- state only administrators can change
class StateSecurityTests(TempDirTest):
    def test_a_tampered_state_file_cannot_steer_the_restore(self):
        tampered = {
            "triggered_at": "2026-11-04 10:00:00",
            "disabled_adapters": ["Wi-Fi", 7, "", "x" * 300],
            "firewall": [{"Name": "Domain", "Enabled": "True", "In": "Block", "Out": "Allow"},
                         {"Name": "Domain'; Set-NetFirewallProfile -Enabled False; '", "Enabled": "True",
                          "In": "Block", "Out": "Allow"},
                         {"Name": "Public", "Enabled": "$false", "In": "Block", "Out": "Allow"}, "junk"],
            "paused": [{"pid": 40, "name": "a.exe", "path": r"C:\x\a.exe", "paused": True, "result": "paused"},
                       {"pid": "40"}, {"pid": True}, {"pid": -1}, None],
            "anything": "else"}
        st = rg.clean_state(tampered)
        self.assertEqual(st["disabled_adapters"], ["Wi-Fi"])
        self.assertEqual(st["firewall"], [{"Name": "Domain", "Enabled": "True", "In": "Block", "Out": "Allow"}])
        self.assertEqual([p["pid"] for p in st["paused"]], [40])
        self.assertNotIn("anything", st)
        self.assertEqual(rg.clean_state({}), {})

    def test_state_lives_in_its_own_folder_and_an_old_one_is_moved_over_checked(self):
        state, app = self.dir / "ProgramData", self.dir / "LocalAppData"
        app.mkdir()
        (app / "state.json").write_text(json.dumps({"triggered_at": "t", "firewall": [
            {"Name": "Domain", "Enabled": "False; evil", "In": "Block", "Out": "Allow"}]}), encoding="utf-8")
        with mock.patch.object(rg, "state_dir", lambda: state), mock.patch.object(rg, "app_dir", lambda: app):
            self.assertEqual(rg.load_state(), {"triggered_at": "t", "firewall": []})
            self.assertTrue((state / "state.json").exists())
            self.assertFalse((app / "state.json").exists(), "the copy in the user's folder is gone")
            rg.save_state({"triggered_at": "u"})
            self.assertEqual(rg.load_state(), {"triggered_at": "u"})

    def secure(self, state):
        cmds = []
        with mock.patch.object(rg, "secure_state_dir", REAL["secure_state_dir"]), \
                mock.patch.object(rg, "state_dir", lambda: state), \
                mock.patch.object(rg, "IS_WINDOWS", True), mock.patch.object(rg, "_state_secured", False), \
                mock.patch.object(rg, "_run", lambda args: cmds.append(args)), \
                mock.patch.dict(os.environ, {"USERDOMAIN": "PC", "USERNAME": "someone"}):
            rg.secure_state_dir()
            rg.secure_state_dir()  # once per run
        return cmds

    def junction(self, link, target):
        subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True, check=True)

    def test_the_state_folder_is_handed_to_administrators(self):
        state, elsewhere = self.dir / "RansomGuard", self.dir / "elsewhere"
        state.mkdir()
        elsewhere.mkdir()
        (elsewhere / "precious.txt").write_text("keep", encoding="utf-8")
        (state / "state.json").write_text("{}", encoding="utf-8")
        (state / "planted.txt").write_text("x", encoding="utf-8")  # someone created the folder first
        (state / "folder").mkdir()
        self.junction(state / "link", elsewhere)
        cmds = self.secure(state)
        self.assertEqual(sorted(p.name for p in state.iterdir()), ["state.json"])  # only RansomGuard's own files
        self.assertEqual((elsewhere / "precious.txt").read_text(encoding="utf-8"), "keep", "a link is never followed")
        owner = [c for c in cmds if "/setowner" in c]
        self.assertEqual([c[1] for c in owner], [str(state), str(state / "state.json")])  # owned by Administrators
        self.assertTrue(all(c[c.index("/setowner") + 1] == "*S-1-5-32-544" for c in owner))
        grant = next(c for c in cmds if "/grant:r" in c)
        self.assertIn("/inheritance:r", grant)  # nothing inherited from ProgramData
        self.assertIn("*S-1-5-18:(OI)(CI)F", grant)
        self.assertIn("*S-1-5-32-544:(OI)(CI)F", grant)
        self.assertIn(r"PC\someone:(OI)(CI)RX", grant)  # the user may only read
        self.assertFalse([c for c in cmds if "/T" in c], "never recursive")
        self.assertTrue(all(c[0].lower().endswith("icacls.exe") for c in cmds))

    def test_a_link_in_place_of_the_state_folder_is_removed_not_followed(self):
        state, elsewhere = self.dir / "RansomGuard", self.dir / "System32-like"
        elsewhere.mkdir()
        (elsewhere / "system.dll").write_text("keep", encoding="utf-8")
        self.junction(state, elsewhere)
        cmds = self.secure(state)
        self.assertFalse(rg._is_link(state))
        self.assertTrue(state.is_dir())
        self.assertEqual((elsewhere / "system.dll").read_text(encoding="utf-8"), "keep")
        self.assertFalse([c for c in cmds if str(elsewhere) in " ".join(c)])

    def test_a_tampered_canary_record_deletes_nothing_but_canaries(self):
        victim = self.dir / "important.dll"
        victim.write_text("keep", encoding="utf-8")
        canary = self.dir / rg.CANARY_NAMES[0]
        canary.write_bytes(rg.CANARY_DOCX)
        with mock.patch.object(rg, "app_dir", lambda: self.dir), mock.patch.object(rg, "_known_folder", lambda n: self.dir / n):
            (self.dir / "canaries.json").write_text(json.dumps([str(victim), str(canary)]), encoding="utf-8")
            rg.remove_canaries()
        self.assertTrue(victim.exists())
        self.assertFalse(canary.exists())

    def test_real_state_folder_is_under_programdata(self):
        with mock.patch.object(rg, "IS_WINDOWS", True), mock.patch.dict(os.environ, {"ProgramData": r"C:\ProgramData"}):
            self.assertEqual(REAL["state_dir"](), Path(r"C:\ProgramData\RansomGuard"))


# ---------------------------------------------------------------- folders the user adds in the control panel
class WatchFolderTests(TempDirTest):
    def setUp(self):
        super().setUp()
        for name in ("Desktop", "Documents", "Pictures", "Downloads", "Videos", "Music", "D", "System"):
            (self.dir / name).mkdir()
        for name, value in (("_known_folder", lambda name: self.dir / name), ("app_dir", lambda: self.dir)):
            p = mock.patch.object(rg, name, value)
            p.start()
            self.addCleanup(p.stop)
        # the test folder itself is under %LOCALAPPDATA%\Temp, which may not be watched: point those elsewhere
        p = mock.patch.dict(os.environ, {"SystemRoot": str(self.dir / "System"), "SystemDrive": str(self.dir)[:2],
                                         "LOCALAPPDATA": r"Q:\LocalAppData", "APPDATA": r"Q:\AppData"})
        p.start()
        self.addCleanup(p.stop)

    def test_which_folders_may_be_added(self):
        self.assertEqual(rg.watch_problem(self.dir / "D"), "")
        self.assertIn("doesn't exist", rg.watch_problem(self.dir / "missing"))
        self.assertIn("system drive", rg.watch_problem(str(self.dir)[:2] + "\\"))
        self.assertIn("change too often", rg.watch_problem(self.dir / "System"))
        self.assertIn("watched already", rg.watch_problem(self.dir / "Documents"))
        (self.dir / "Documents" / "Work").mkdir()
        self.assertIn("watched already", rg.watch_problem(self.dir / "Documents" / "Work"))

    def test_added_folders_are_saved_and_checked_again_when_read(self):
        rg.save_extra_watch_dirs([self.dir / "D", self.dir / "System", self.dir / "gone"])
        self.assertEqual(rg.extra_watch_dirs(), [self.dir / "D"])  # what can't be watched is left out
        (self.dir / "watch.json").write_text("not json", encoding="utf-8")
        self.assertEqual(rg.extra_watch_dirs(), [])

    def test_the_monitor_watches_and_plants_canaries_in_added_folders(self):
        rg.save_extra_watch_dirs([self.dir / "D"])
        seen = {}
        with mock.patch.object(rg, "plant_canaries", lambda dirs, upgrade=False: seen.update(dirs=dirs) or []), \
                mock.patch.object(rg, "make_handler", mock.Mock(side_effect=SystemExit(0))), \
                mock.patch.object(rg, "is_admin", lambda: True), mock.patch.object(rg, "single_instance", lambda: True), \
                mock.patch.object(rg, "exit_with_launcher", lambda: None), \
                mock.patch.object(rg, "cleanup_old_files", lambda: None), mock.patch.object(rg, "IS_WINDOWS", True):
            with self.assertRaises(SystemExit):
                rg.run(argparse.Namespace(watch=None, dry_run=False))
        self.assertIn(self.dir / "D", seen["dirs"])
        self.assertIn(self.dir / "Music", seen["dirs"])  # and canaries go into every watched folder


if __name__ == "__main__":
    unittest.main()
