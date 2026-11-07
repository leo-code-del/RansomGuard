"""Tests: the background monitor's notification-area icon. Shared helpers and the safety net are in support.py."""
import os
import time
import unittest

import support
from support import REAL, TempDirTest, rg

setUpModule, tearDownModule = support.setUpModule, support.tearDownModule  # the safety net


class TrayTests(TempDirTest):
    def setUp(self):
        super().setUp()
        self.patch("app_dir", lambda: self.dir)
        self.addCleanup(rg.init_lang, "en")
        rg.init_lang("en")

    def test_the_icon_says_the_state(self):
        now = 1_000_000.0
        self.assertEqual(rg.tray_state(0.0, False, now), ("ok", "RansomGuard: protected"))
        icon, tip = rg.tray_state(now + 1800, False, now)
        self.assertEqual(icon, "paused")
        self.assertIn("paused until " + time.strftime("%H:%M", time.localtime(now + 1800)), tip)
        self.assertEqual(rg.tray_state(now - 10, False, now)[0], "ok", "a pause that ended")
        self.assertEqual(rg.tray_state(now + 1800, True, now), ("cut", "RansomGuard: network cut off"),
                         "a cut network comes first")
        self.assertTrue(all(len(rg.tray_state(p, c, now)[1]) < 128 for p in (0, now + 60) for c in (False, True)),
                        "a tooltip has room for 127 characters")

    def test_it_can_be_turned_off(self):
        self.assertTrue(rg.tray_enabled(), "on unless turned off")
        rg.set_setting("tray_icon", False)
        self.assertFalse(rg.tray_enabled())
        rg.set_setting("tray_icon", True)
        self.assertTrue(rg.tray_enabled())

    def test_the_icon_files_exist(self):
        for state in ("ok", "paused", "cut"):
            self.assertTrue(os.path.isfile(rg.tray_icon_file(state)), state)

    def test_the_real_icon_shows_follows_the_state_and_goes(self):
        # shown for about a second; skipped where there is no taskbar to show it in
        state = {"now": ("ok", "RansomGuard: protected")}
        self.patch("tray_enabled", lambda: True)
        icon = REAL["Tray"](lambda: state["now"])
        icon.REFRESH_MS = 100
        icon.start()
        self.addCleanup(icon.stop)
        if icon.shown is None:
            self.skipTest("no notification area here")
        self.assertEqual(icon.shown, state["now"])
        state["now"] = ("cut", "RansomGuard: network cut off")
        end = time.time() + 3
        while time.time() < end and icon.shown != state["now"]:
            time.sleep(0.05)
        self.assertEqual(icon.shown, state["now"])
        self.patch("tray_enabled", lambda: False)  # turned off in the control panel: it goes away by itself
        end = time.time() + 3
        while time.time() < end and icon.shown is not None:
            time.sleep(0.05)
        self.assertIsNone(icon.shown)
        icon.stop()
        self.assertFalse(icon.thread.is_alive())


if __name__ == "__main__":
    unittest.main()
