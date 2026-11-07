"""Tests: whether files are backed up. Shared helpers and the safety net are in support.py."""
import argparse
import os
import threading
import time
import unittest
from unittest import mock

import support
from support import StubProcessMonitor, TempDirTest, rg

setUpModule, tearDownModule = support.setUpModule, support.tearDownModule  # the safety net


# ---------------------------------------------------------------- whether files are backed up
class BackupTests(TempDirTest):
    def setUp(self):
        super().setUp()
        self.patch("app_dir", lambda: self.dir)
        self.fh = self.dir / "FileHistory"
        self.fh.mkdir()
        self.patch("_file_history_folder", lambda: self.fh)
        self.onedrive = self.dir / "OneDrive"
        self.onedrive.mkdir()
        self.folders = {name: self.dir / name for name in ("Desktop", "Documents", "Pictures")}
        self.patch("_known_folder", lambda name: self.folders.get(name, self.dir / name))
        env = mock.patch.dict(os.environ, {"OneDrive": str(self.onedrive), "OneDriveConsumer": "",
                                           "OneDriveCommercial": ""})
        env.start()
        self.addCleanup(env.stop)
        self.addCleanup(rg.init_lang, "en")
        rg.init_lang("en")

    def file_history(self, days_ago):
        (self.fh / "Config1.xml").write_text("<DataProtectionUserConfig/>")
        catalog = self.fh / "Catalog1.edb"
        catalog.write_bytes(b"x")
        t = time.time() - days_ago * 86400
        os.utime(catalog, (t, t))

    def test_no_backup(self):
        self.assertEqual(rg.file_history(), (False, None))
        self.assertEqual(rg.onedrive_folders(), [])
        self.assertEqual(rg.backup_status(), ("No backup found", "bad", "Encrypted files are lost"))

    def test_file_history(self):
        self.file_history(2)
        configured, last = rg.file_history()
        self.assertTrue(configured)
        self.assertAlmostEqual(last, time.time() - 2 * 86400, delta=60)
        self.assertEqual(rg.backup_status(), ("File History", "ok", "Last backup: 2 days ago"))
        self.file_history(20)  # the backup drive hasn't been connected for a while
        self.assertEqual(rg.backup_status(), ("Out of date", "warn", "Last backup: 20 days ago"))
        with mock.patch.object(rg, "_file_history_registry_time", lambda: time.time() - 3600):
            self.assertEqual(rg.backup_status()[:2], ("File History", "ok"), "Windows' own record comes first")
        with mock.patch.object(rg, "_file_history_registry_time", lambda: time.time() + 10 * 86400):
            self.assertEqual(rg.backup_status()[1], "warn", "a time in the future isn't trusted")

    def test_onedrive(self):
        self.folders["Documents"] = self.onedrive / "Documents"
        self.assertEqual(rg.onedrive_folders(), ["Documents"])
        self.assertEqual(rg.backup_status(), ("Partly", "warn", "OneDrive: Documents only"))
        self.folders.update(Desktop=self.onedrive / "Desktop", Pictures=self.onedrive / "Pictures")
        self.assertEqual(rg.backup_status()[:2], ("OneDrive", "ok"))
        self.folders["Desktop"] = self.dir / "OneDriveOld" / "Desktop"  # a look-alike name is not OneDrive
        self.assertEqual(rg.onedrive_folders(), ["Documents", "Pictures"])

    def test_another_backup_program(self):
        rg.set_setting("other_backup", True)
        self.assertEqual(rg.backup_status()[1], "ok")

    def test_reminders_come_at_most_every_two_weeks(self):
        shown = []
        self.patch("notice", lambda title, msg: shown.append(msg))
        now = time.time()
        self.assertTrue(rg.remind_if_needed(now))
        self.assertIn("No backup found", shown[0])
        self.assertIn("can't bring encrypted files back", shown[0])
        self.assertFalse(rg.remind_if_needed(now + 86400), "not again the next day")
        self.assertFalse(rg.remind_if_needed(now + (rg.REMIND_DAYS - 1) * 86400))
        self.assertTrue(rg.remind_if_needed(now + (rg.REMIND_DAYS + 1) * 86400))
        self.file_history(1)
        self.assertFalse(rg.remind_if_needed(now + 100 * 86400), "backed up: no reminder")
        self.assertEqual(len(shown), 2)

    def test_no_reminder_for_another_backup_program_or_a_damaged_setting(self):
        shown = []
        self.patch("notice", lambda title, msg: shown.append(msg))
        rg.set_setting("other_backup", True)
        self.assertFalse(rg.remind_if_needed())
        rg.set_setting("other_backup", False)
        rg.set_setting("backup_reminded", "yesterday")  # damaged: counts as never reminded
        self.assertTrue(rg.remind_if_needed())
        self.assertEqual(len(shown), 1)

    def test_the_monitor_checks_the_backup_after_it_has_settled(self):
        checks = []
        self.patch("remind_if_needed", lambda: checks.append(1))
        for name, value in (("IS_WINDOWS", True), ("FROZEN", False), ("is_admin", lambda: True),
                            ("single_instance", lambda: True), ("exit_with_launcher", lambda: None),
                            ("cleanup_old_files", lambda: None), ("ProcessMonitor", StubProcessMonitor),
                            ("DEFENDER_SCAN_DOWNLOADS", False), ("CHECK_INTERVAL", 0), ("BACKUP_CHECK_DELAY", 1),
                            ("keep_restart_trigger", lambda: None)):
            self.patch(name, value)
        watch = self.dir / "watch"
        watch.mkdir()
        stop = threading.Event()
        t = threading.Thread(target=rg.run, args=(argparse.Namespace(watch=[str(watch)], dry_run=False), stop),
                             daemon=True)
        t.start()
        self.addCleanup(lambda: (stop.set(), t.join(15)))
        time.sleep(4)
        self.assertEqual(checks, [1], "once, after the delay (then once a day)")


if __name__ == "__main__":
    unittest.main()
