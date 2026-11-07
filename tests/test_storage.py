"""Tests: settings, the log's privacy and the state only administrators can change. Shared helpers and the
safety net are in support.py."""
import json
import logging
import os
import subprocess
import time
import unittest
from pathlib import Path
from unittest import mock

import support
from support import REAL, TempDirTest, rg

setUpModule, tearDownModule = support.setUpModule, support.tearDownModule  # the safety net


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

    def test_the_detection_report_is_checked_and_capped(self):
        st = rg.clean_state({"incident": {"reason": "r" * 900, "files": [r"C:\a.docx", 5, "", None, "p" * 2000]
                                          + [rf"C:\f{i}.pdf" for i in range(80)], "extra": "x"}})
        self.assertEqual(len(st["incident"]["reason"]), 500)
        self.assertEqual(st["incident"]["files"][:2], [r"C:\a.docx", "p" * 1024])
        self.assertEqual(len(st["incident"]["files"]), 50)
        self.assertEqual(set(st["incident"]), {"reason", "files"})
        for bad in ({"incident": "text"}, {"incident": {"files": ["a"]}}, {"incident": {"reason": 5}}):
            self.assertNotIn("incident", rg.clean_state(bad))
        self.assertEqual(rg.clean_state({"incident": {"reason": "why", "files": "a.docx"}})["incident"]["files"], [])
        rg.init_lang("en")
        lines = rg.incident_lines({"incident": {"reason": "why", "files": [f"f{i}" for i in range(12)]}}, limit=10)
        self.assertEqual(lines[1], "Files that looked encrypted (12):")
        self.assertEqual(lines[-1], "  ...and 2 more (see the log)")
        self.assertEqual(rg.incident_lines({}), [])

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


if __name__ == "__main__":
    unittest.main()
