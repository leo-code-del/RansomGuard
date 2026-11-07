"""Tests: the notice by the clock while the network is cut. Shared helpers and the safety net are in support.py."""
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

    def test_only_a_cut_network_shows(self):
        self.assertIsNone(rg.tray_message(False), "nothing by the clock normally, also while paused")
        tip, title, text = rg.tray_message(True)
        self.assertIn("network cut off", tip)
        self.assertEqual(title, "RansomGuard: network cut off")
        self.assertIn("detection report", text)
        # Windows' limits: tooltip 127, notification title 63, text 255 characters
        for lang in ("en", "zh"):
            rg.init_lang(lang)
            tip, title, text = rg.tray_message(True)
            self.assertTrue(len(tip) < 128 and len(title) < 64 and len(text) < 256, lang)

    def test_it_can_be_turned_off(self):
        self.assertTrue(rg.tray_enabled(), "on unless turned off")
        rg.set_setting("tray_icon", False)
        self.assertFalse(rg.tray_enabled())
        rg.set_setting("tray_icon", True)
        self.assertTrue(rg.tray_enabled())

    def test_the_icon_file_exists(self):
        self.assertTrue(os.path.isfile(rg.tray_icon_file()))

    def wait(self, cond, timeout=3):
        end = time.time() + timeout
        while time.time() < end and not cond():
            time.sleep(0.05)

    def test_the_real_notice_appears_when_cut_and_goes(self):
        # nothing at first; when cut, the icon shows for about a second - without its Windows notification, which
        # would tell whoever runs the tests that the network was cut; skipped where there is no notification area
        class QuietTray(REAL["Tray"]):
            def _notify(self, what, message=None, announce=False):
                return super()._notify(what, message, announce=False)
        state = {"cut": False}
        self.patch("tray_enabled", lambda: True)
        icon = QuietTray(lambda: rg.tray_message(state["cut"]))
        icon.REFRESH_MS = 100
        icon.start()
        self.addCleanup(icon.stop)
        time.sleep(0.4)
        self.assertIsNone(icon.shown, "shown while the network isn't cut")
        state["cut"] = True
        self.wait(lambda: icon.shown is not None)
        if icon.shown is None:
            self.skipTest("no notification area here")
        self.assertIn("network cut off", icon.shown[0])
        state["cut"] = False  # the network restored: it goes by itself
        self.wait(lambda: icon.shown is None)
        self.assertIsNone(icon.shown)
        icon.stop()
        self.assertFalse(icon.thread.is_alive())


if __name__ == "__main__":
    unittest.main()
