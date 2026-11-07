"""Tests: the control panel's self-check. Shared helpers and the safety net are in support.py."""
import os
import unittest
from unittest import mock

from watchdog.events import FileSystemEventHandler

import support
from support import TempDirTest, overwrite, rg

setUpModule, tearDownModule = support.setUpModule, support.tearDownModule  # the safety net

ADMINS, SYSTEM, USER = "S-1-5-32-544", "S-1-5-18", "S-1-5-21-1-2-3-1001"


class SelfCheckTests(TempDirTest):
    def setUp(self):
        super().setUp()
        self.patch("app_dir", lambda: self.dir)
        self.addCleanup(rg.init_lang, "en")
        rg.init_lang("en")

    def start_line(self, version=None, when="2026-11-07 10:00:00,000"):
        return f"{when} [INFO] RansomGuard {version or rg.VERSION} started monitoring: C:\\Users\\u\\Documents"

    def test_the_scheduled_task(self):
        for state, stopped, expected in (("Running", False, "ok"), ("", False, "fail"), ("Ready", True, "warn"),
                                         ("Ready", False, "fail"), ("Disabled", False, "fail")):
            with mock.patch.object(rg, "task_state", lambda: state), \
                    mock.patch.object(rg, "stopped_by_user", lambda: stopped):
                self.assertEqual(rg.check_task()[0], expected, (state, stopped))

    def test_the_monitor_in_the_log(self):
        procmon = "2026-11-07 10:00:01,000 [INFO] Process monitor started (real-time trace: {})"
        ok = rg.check_monitor_log([self.start_line(), procmon.format("True")])
        self.assertEqual([r for r, _ in ok], ["ok", "ok"])
        older = rg.check_monitor_log([self.start_line("1.0.0"), procmon.format("True")])
        self.assertEqual(older[0][0], "warn")
        self.assertIn("v1.0.0", older[0][1])
        self.assertEqual(rg.check_monitor_log([self.start_line(), procmon.format("False")])[1][0], "warn")
        # a process monitor that started before the last start doesn't count
        self.assertEqual(rg.check_monitor_log([procmon.format("True"), self.start_line()])[1][0], "fail")
        self.assertEqual(rg.check_monitor_log([]), [("warn", rg.check_monitor_log([])[0][1])])
        # a test-mode run after it is not the background monitor
        test_mode = "2026-11-07 11:00:00,000 [INFO] RansomGuard 1.0.0 started monitoring (test mode): C:\\tmp"
        self.assertEqual(rg.check_monitor_log([self.start_line(), procmon.format("True"), test_mode])[0][0], "ok")
        chinese = ["2026-11-07 10:00:00,000 [INFO] RansomGuard 1.0.0 開始監控：C:\\x",
                   "2026-11-07 10:00:01,000 [INFO] 程序監控已啟動（即時追蹤：True）"]
        self.assertEqual([r for r, _ in rg.check_monitor_log(chinese)], ["warn", "ok"], "a log written in Chinese")

    def test_errors_since_the_monitor_started(self):
        old_error = "2026-11-01 10:00:00,000 [ERROR] something long ago"
        self.assertEqual(rg.check_errors([old_error, self.start_line()])[0], "ok", "before this start: not counted")
        result, text = rg.check_errors([old_error, self.start_line(), "2026-11-07 10:05:00,000 [ERROR] disk full"])
        self.assertEqual(result, "warn")
        self.assertIn("disk full", text)

    def test_canary_files(self):
        self.assertEqual(rg.check_canary_files()[0], "fail", "none recorded")
        docs, usb = self.dir / "docs", self.dir / "usb"
        docs.mkdir()
        usb.mkdir()
        planted = rg.plant_canaries([docs, usb])
        self.assertEqual(rg.check_canary_files(), ("ok", "All 6 canary files are intact and hidden"))
        for p in planted:  # an unplugged drive: its canaries aren't checked
            if p.parent == usb:
                rg._set_hidden(p, False)
                p.unlink()
        usb.rmdir()
        self.assertEqual(rg.check_canary_files(), ("ok", "All 3 canary files are intact and hidden"))
        rg._set_hidden(planted[0], False)
        result, text = rg.check_canary_files()
        self.assertEqual(result, "fail")
        self.assertIn("not hidden", text)
        overwrite(planted[0], b"encrypted")
        self.assertIn("modified", rg.check_canary_files()[1])

    def acl(self, out, rc=0):
        (self.dir / "state").mkdir(exist_ok=True)
        with mock.patch.object(rg, "state_dir", lambda: self.dir / "state"), \
                mock.patch.object(rg, "IS_WINDOWS", True), \
                mock.patch.object(rg, "_ps", lambda cmd, timeout=60: (rc, out, "access denied")):
            return rg.check_state_permissions()

    def test_state_folder_permissions(self):
        good = (f"OWNER\t{ADMINS}\nACE\t{SYSTEM}\tFullControl\tFalse\tAllow\n"
                f"ACE\t{ADMINS}\tFullControl\tFalse\tAllow\nACE\t{USER}\tReadAndExecute, Synchronize\tFalse\tAllow")
        self.assertEqual(self.acl(good)[0], "ok")
        result, text = self.acl(good + "\nACE\tS-1-5-32-545\tModify, Synchronize\tFalse\tAllow")
        self.assertEqual(result, "fail")
        self.assertIn("S-1-5-32-545 can change it", text)
        self.assertIn("inherits", self.acl(good + f"\nACE\t{USER}\tReadAndExecute\tTrue\tAllow")[1])
        self.assertIn("owned by", self.acl(good.replace(f"OWNER\t{ADMINS}", f"OWNER\t{USER}"))[1])
        self.assertEqual(self.acl(good + "\nACE\tS-1-1-0\tWrite\tFalse\tDeny")[0], "ok", "a Deny entry is fine")
        self.assertEqual(self.acl("", rc=1)[0], "warn")
        with mock.patch.object(rg, "state_dir", lambda: self.dir / "missing"), mock.patch.object(rg, "IS_WINDOWS", True):
            self.assertEqual(rg.check_state_permissions()[0], "warn", "not created yet")

    def test_a_pause_is_reported(self):
        self.assertNotIn("paused", " ".join(t for _, t in rg.check_network_and_backup()))
        rg.pause_detection(30)
        self.addCleanup(rg.resume_detection)
        results = rg.check_network_and_backup()
        self.assertEqual(results[0][0], "warn")
        self.assertIn("File detection is paused until", results[0][1])

    def test_the_drill_catches_encryption_and_a_canary_change(self):
        record = rg.canary_record()
        results = rg.drill()
        self.assertEqual([r for r, _ in results], ["ok", "ok"], results)
        self.assertIn("simulated encryption of 12 documents, detected within", results[0][1])
        self.assertEqual(rg.canary_record(), record, "the real canary record is left alone")
        leftovers = [p for p in os.listdir(os.environ["TEMP"]) if p.startswith("rg_selfcheck_")]
        self.assertEqual(leftovers, [], "the drill's folder is removed")

    def test_a_drill_that_detects_nothing_fails(self):
        with mock.patch.object(rg, "make_handler", lambda canaries, on_trigger, dry_run: FileSystemEventHandler()):
            results = rg.drill(timeout=0.5)
        self.assertEqual([r for r, _ in results], ["fail", "fail"])
        self.assertIn("not detected", results[0][1])

    def test_the_summary(self):
        lines = []
        for name, value in (("check_task", lambda: ("fail", "not installed")),
                            ("check_monitor_log", lambda lines: [("warn", "older"), ("ok", "procmon")]),
                            ("check_canary_files", lambda: 1 / 0),  # a check that breaks is reported, the rest go on
                            ("check_state_permissions", lambda: ("ok", "safe")),
                            ("check_errors", lambda lines: ("ok", "no errors")),
                            ("check_network_and_backup", lambda: [("ok", "net"), ("warn", "backup")]),
                            ("drill", lambda: [("ok", "drill")])):
            self.patch(name, value)
        results = rg.run_selfcheck(lines.append)
        self.assertEqual(results.count("fail"), 2)
        self.assertIn("[Failed] not installed", lines)
        self.assertTrue(any(line.startswith("[Failed] Could not check") for line in lines))
        self.assertIn("[Check] backup", lines)
        self.assertEqual(lines[-1], "Self-check done: 2 failed, 2 to check (see above).")


if __name__ == "__main__":
    unittest.main()
