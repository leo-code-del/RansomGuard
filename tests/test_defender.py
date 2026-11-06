"""Tests: scanning new downloads with Microsoft Defender. Shared helpers and the safety net are in support.py."""
import subprocess
import unittest
from pathlib import Path
from unittest import mock

from watchdog.events import FileCreatedEvent, FileModifiedEvent, FileMovedEvent

import support
from support import TempDirTest, rg

setUpModule, tearDownModule = support.setUpModule, support.tearDownModule  # the safety net


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


if __name__ == "__main__":
    unittest.main()
