"""Tests for RansomGuard. Run from the project folder:

    python -m unittest discover -s tests -v

Everything happens in temporary folders; nothing touches the real Documents/Desktop, the real
canary files, the network or the installed program. Strings that look like destructive commands
only live in this file, never on a command line, so an installed RansomGuard won't react to them.
"""
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

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import ransom_guard as rg  # noqa: E402

rg.log.addHandler(logging.NullHandler())
rg.log.propagate = False
rg.init_lang("en")

ZIP_HEAD = b"PK\x03\x04\x14\x00\x06\x00"
OLE_HEAD = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def random_bytes(n=8192):
    return os.urandom(n)


class TempDirTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="rg_test_"))

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

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
        self.assertTrue(all(p.read_bytes() == rg.CANARY_BYTES for p in self.canaries))

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
        c.write_bytes(random_bytes())
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
        c.write_bytes(b"tampered")
        with mock.patch.object(rg, "alert") as alert:
            again = rg.plant_canaries([c.parent])
        alert.assert_called_once()
        self.assertEqual(Path(again[0]).read_bytes(), rg.CANARY_BYTES)

    def test_remove_canaries_handles_new_and_legacy_names(self):
        for n in rg.LEGACY_CANARY_NAMES:
            (self.dir / "docs" / n).write_bytes(b"old")
        with mock.patch.object(rg, "default_canary_dirs", lambda: [self.dir / "docs"]):
            rg.remove_canaries()
        self.assertEqual(list((self.dir / "docs").iterdir()), [])


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
                            ("default_canary_dirs", lambda: [self.dir]), ("IS_WINDOWS", True)):
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

    def run_watcher(self, versions, answer, seconds=1.0):
        asked, launched = [], []
        stop = threading.Event()
        checks = iter(versions)
        with mock.patch.object(rg, "UPDATE_CHECK_DELAY", 0), mock.patch.object(rg, "UPDATE_CHECK_INTERVAL", 0.05), \
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
            # lives ~0.4 s: without administrator rights only WMI polling (every 0.5 s) can see it
            subprocess.run(f'cmd.exe /c ""{sys.executable}" -c "import time; time.sleep(0.25)" & rem {marker}"')
            got.wait(15)
        self.assertTrue(hits, "process monitor did not report the marked process")
        self.assertIn("cmd.exe", hits[0])

    def test_stop_monitor_recognizes_old_and_new_process_monitors(self):
        old_script = ("\n[Console]::OutputEncoding = [System.Text.Encoding]::UTF8\n"
                      "$q = \"SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'\"\n")
        self.assertEqual(rg.ps_encoded_args(old_script)[-1][:120], rg.ps_encoded_args(rg.PROC_PS1)[-1][:120])


if __name__ == "__main__":
    unittest.main()
