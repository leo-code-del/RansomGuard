"""Tests: folders the user adds in the control panel. Shared helpers and the safety net are in support.py."""
import argparse
import os
import unittest
from unittest import mock

import support
from support import TempDirTest, rg

setUpModule, tearDownModule = support.setUpModule, support.tearDownModule  # the safety net


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

    def test_which_subfolders_may_be_excluded(self):
        watched = [self.dir / "Documents", self.dir / "D"]
        build = self.dir / "D" / "repo" / "build"
        build.mkdir(parents=True)
        self.assertEqual(rg.exclude_problem(build, watched), "")
        self.assertIn("watched folder itself", rg.exclude_problem(self.dir / "D", watched),
                      "a whole watched folder can't be left unprotected")
        self.assertIn("isn't watched", rg.exclude_problem(self.dir / "System", watched))
        self.assertIn("doesn't exist", rg.exclude_problem(self.dir / "D" / "missing", watched))
        (self.dir / "Documents2").mkdir()
        self.assertIn("isn't watched", rg.exclude_problem(self.dir / "Documents2", watched),
                      "a look-alike name (Documents2) isn't inside Documents")
        drive = str(self.dir)[:3]  # a whole drive watched (D:\ on the user's computer): its folders can be excluded
        self.assertEqual(rg.exclude_problem(build, [drive]), "")

    def test_excluded_subfolders_are_saved_in_the_state_folder(self):
        self.assertIn("exclude.json", rg.STATE_FILES, "kept when the state folder is secured")
        self.assertEqual(rg.excluded_dirs(), [])
        rg.save_excluded_dirs([self.dir / "D" / "build", "relative\\path"])
        self.assertEqual(rg.excluded_dirs(), [self.dir / "D" / "build"], "only absolute paths")
        (self.dir / "exclude.json").write_text('{"not": "a list"}', encoding="utf-8")
        self.assertEqual(rg.excluded_dirs(), [])

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

    def test_the_monitor_hands_the_excluded_subfolders_to_detection(self):
        rg.save_excluded_dirs([self.dir / "D" / "build"])
        handler = mock.Mock(side_effect=SystemExit(0))
        with mock.patch.object(rg, "plant_canaries", lambda dirs, upgrade=False: []), \
                mock.patch.object(rg, "make_handler", handler), \
                mock.patch.object(rg, "is_admin", lambda: True), mock.patch.object(rg, "single_instance", lambda: True), \
                mock.patch.object(rg, "exit_with_launcher", lambda: None), \
                mock.patch.object(rg, "cleanup_old_files", lambda: None), mock.patch.object(rg, "IS_WINDOWS", True), \
                mock.patch.object(rg, "keep_restart_trigger", lambda: None):
            with self.assertRaises(SystemExit):
                rg.run(argparse.Namespace(watch=None, dry_run=False))
        self.assertEqual(handler.call_args.args[4], [self.dir / "D" / "build"])


if __name__ == "__main__":
    unittest.main()
