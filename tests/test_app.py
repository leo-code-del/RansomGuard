"""Tests: the monitor's main loop and the command line. Shared helpers and the safety net are in support.py."""
import argparse
import os
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

import watchdog.observers

import support
from support import StubProcessMonitor, TempDirTest, overwrite, random_bytes, rg

setUpModule, tearDownModule = support.setUpModule, support.tearDownModule  # the safety net


class MonitorLoopTests(TempDirTest):
    def setUp(self):
        super().setUp()
        self.watch = self.dir / "watch"
        self.watch.mkdir()
        self.triggered = []
        self.restart_trigger_kept = []
        StubProcessMonitor.instances = []
        for name, value in (("app_dir", lambda: self.dir), ("IS_WINDOWS", True), ("FROZEN", False),
                            ("is_admin", lambda: True), ("single_instance", lambda: True),
                            ("exit_with_launcher", lambda: None), ("cleanup_old_files", lambda: None),
                            ("ProcessMonitor", StubProcessMonitor), ("DEFENDER_SCAN_DOWNLOADS", False),
                            ("keep_restart_trigger", lambda: self.restart_trigger_kept.append(1)),
                            ("CHECK_INTERVAL", 0),
                            ("respond", lambda reason, dry_run, files=(): self.triggered.append((reason, dry_run, files)))):
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

    def test_the_files_that_looked_encrypted_reach_the_response(self):
        self.start()
        encrypted = [self.watch / f"photo{i}.jpg" for i in range(rg.BROKEN_THRESHOLD)]
        for p in encrypted:
            p.write_bytes(random_bytes())
        self.wait_for(lambda: self.triggered)
        reason, dry_run, files = self.triggered[0]
        self.assertIn("files that look encrypted", reason)
        self.assertEqual(sorted(rg.norm(f) for f in files), sorted(rg.norm(p) for p in encrypted))

    def test_the_response_does_not_hold_up_the_monitor_that_found_it(self):
        # the response lasts until the warning is closed; meanwhile the process monitor must go on stopping
        # dangerous commands
        release = threading.Event()
        self.addCleanup(release.set)

        def respond(reason, dry_run, files=()):  # like the warning staying open
            self.triggered.append(reason)
            release.wait(30)
        self.patch("respond", respond)
        self.start()
        t0 = time.time()
        StubProcessMonitor.instances[0].on_hit("A process is deleting restore points")
        self.assertLess(time.time() - t0, 1)
        self.wait_for(lambda: self.triggered)
        self.assertEqual(self.triggered, ["A process is deleting restore points"])

    def start_with(self, *dirs):
        """Start the monitor on these folders, with a recorded file monitor."""
        observers = []

        class RecordingObserver(watchdog.observers.Observer):
            def __init__(self, *a, **k):
                super().__init__(*a, **k)
                observers.append(self)
        self.patch("REWATCH_INTERVAL", 0)
        p = mock.patch("watchdog.observers.Observer", RecordingObserver)
        p.start()
        self.addCleanup(p.stop)
        self.stop = threading.Event()
        t = threading.Thread(target=rg.run, args=(argparse.Namespace(watch=[str(d) for d in dirs], dry_run=False),
                                                  self.stop), daemon=True)
        t.start()
        self.addCleanup(lambda: (self.stop.set(), t.join(15)))
        self.wait_for(lambda: observers and observers[-1].is_alive())
        return observers[-1]

    @staticmethod
    def watcher(obs, folder):
        return next((e for e in obs.emitters if rg.norm(e.watch.path) == rg.norm(folder) and e.is_alive()), None)

    def test_a_folder_whose_watcher_stopped_is_watched_again(self):
        usb = self.dir / "usb"
        usb.mkdir()
        obs = self.start_with(self.watch, usb)
        gone = self.watcher(obs, usb)
        gone.stop()  # what happens when a watched USB drive is unplugged
        gone.join(5)
        self.wait_for(lambda: self.watcher(obs, usb) not in (None, gone))
        self.assertIsNotNone(self.watcher(obs, usb), "not watched again")
        self.assertIsNotNone(self.watcher(obs, self.watch), "the other folder stopped being watched")
        overwrite(usb / rg.CANARY_NAMES[0], b"encrypted")
        self.wait_for(lambda: self.triggered)
        self.assertIn("Canary file", self.triggered[0][0])

    def test_another_drive_in_place_of_a_watched_one_is_no_alarm(self):
        # a watched USB drive is unplugged and another one (without canary files) gets the same drive letter
        usb = self.dir / "usb"
        usb.mkdir()
        obs = self.start_with(self.watch, usb)
        gone = self.watcher(obs, usb)
        self.patch("REWATCH_INTERVAL", 3600)  # the new drive is noticed by the periodic check first
        self.patch("CHECK_INTERVAL", 3600)  # no check halfway through the swap (a real drive goes as a whole)
        time.sleep(1.5)
        gone.stop()  # unplugged: the watcher stops
        gone.join(5)
        for name in rg.CANARY_NAMES:  # the other drive has none of the canary files
            canary = usb / name
            rg._set_hidden(canary, False)
            os.replace(canary, self.dir / name)
        self.patch("CHECK_INTERVAL", 0)
        time.sleep(2)  # several periodic checks
        self.assertEqual(self.triggered, [], "a missing canary of a folder that went away triggered")
        self.patch("REWATCH_INTERVAL", 0)
        self.wait_for(lambda: self.watcher(obs, usb) not in (None, gone))
        canary = usb / rg.CANARY_NAMES[0]
        self.assertEqual(canary.read_bytes(), rg.canary_bytes(canary), "the new drive got no canary files")
        time.sleep(1)
        self.assertEqual(self.triggered, [])
        overwrite(canary, b"encrypted")
        self.wait_for(lambda: self.triggered)
        self.assertIn("Canary file", self.triggered[0][0])

    def test_a_folder_that_appears_later_gets_canaries_and_is_watched(self):
        usb = self.dir / "usb"  # not plugged in when the monitor starts
        obs = self.start_with(self.watch, usb)
        usb.mkdir()
        canary = usb / rg.CANARY_NAMES[0]
        self.wait_for(lambda: self.watcher(obs, usb) is not None)
        self.assertEqual(canary.read_bytes(), rg.canary_bytes(canary))
        self.assertIn(str(canary), rg.canary_record())
        time.sleep(0.5)
        self.assertEqual(self.triggered, [], "planting the canary files triggered")
        overwrite(canary, b"encrypted")
        self.wait_for(lambda: self.triggered)
        self.assertIn("Canary file", self.triggered[0][0])

    def run_once(self):
        """Start the monitor and let it end right after starting."""
        stop = threading.Event()
        stop.set()
        rg.run(argparse.Namespace(watch=[str(self.watch)], dry_run=False), stop)

    def test_a_pause_set_in_the_control_panel_applies_within_seconds(self):
        self.start()
        with self.assertLogs(rg.log, "WARNING") as logged:
            rg.pause_detection(30)  # what the control panel does
            self.addCleanup(rg.resume_detection)
            time.sleep(1.5)
            for i in range(rg.BROKEN_THRESHOLD + 4):  # bulk work right after pausing
                (self.watch / f"converted{i}.jpg").write_bytes(random_bytes())
            time.sleep(2)
            self.assertEqual(self.triggered, [], "counted while paused")
            overwrite(self.watch / rg.CANARY_NAMES[0], b"encrypted")  # canary files are still watched
            self.wait_for(lambda: self.triggered)
            self.assertIn("Canary", self.triggered[0][0])
            rg.resume_detection()
            time.sleep(1.5)
        self.assertTrue(any("paused by the user until" in m for m in logged.output), logged.output)
        self.assertTrue(any("File detection resumed" in m for m in logged.output), logged.output)

    def test_the_monitor_puts_the_restart_trigger_back_when_it_starts(self):
        self.start()
        self.wait_for(lambda: self.restart_trigger_kept)
        self.assertEqual(self.restart_trigger_kept, [1])

    def test_the_restart_trigger_is_put_back_or_brought_to_one_minute(self):
        for interval, changed in (("PT1M", False), ("PT5M", True), ("", True)):  # current / older install / taken off
            cmds = []

            def ps(cmd, interval=interval, cmds=cmds):
                cmds.append(cmd)
                return (0, interval, "") if "Repetition.Interval" in cmd else (0, "", "")
            with mock.patch.object(rg, "_ps", ps):
                rg.ensure_restart_trigger()
            sets = [c for c in cmds if "Set-ScheduledTask" in c]
            self.assertEqual(len(sets), 1 if changed else 0, interval)
            if changed:
                self.assertIn(f"-RepetitionInterval (New-TimeSpan -Minutes {rg.MONITOR_RESTART_MINUTES})", sets[0])
                self.assertIn("$r.Repetition.StopAtDurationEnd = $false", sets[0])
                self.assertIn("MSFT_TaskLogonTrigger", sets[0], "the sign-in trigger is kept")
        self.assertEqual(rg.MONITOR_RESTART_MINUTES, 1)
        with mock.patch.object(rg, "_ps", lambda c: (1, "", "no such task")):  # never fails the monitor
            rg.keep_restart_trigger()
        with mock.patch.object(rg, "_ps", mock.Mock(side_effect=OSError("powershell missing"))):
            rg.keep_restart_trigger()

    def test_a_stop_by_the_user_holds_until_windows_restarts(self):
        cmds = []
        with mock.patch.object(rg, "stop_monitor", lambda: None), mock.patch.object(rg, "boot_time", lambda: 1000.0), \
                mock.patch.object(rg, "_ps", lambda c: cmds.append(c) or (0, "", "")):
            rg.stop_monitor_until_restart()
            self.assertTrue(rg.stopped_by_user())
            # the task stops starting it every minute until then (each start would unpack the program to exit again)
            self.assertEqual(len(cmds), 1)
            self.assertIn("Set-ScheduledTask", cmds[0])
            self.assertIn("MSFT_TaskLogonTrigger", cmds[0], "the sign-in trigger is kept")
            self.assertNotIn("RepetitionInterval", cmds[0])
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


if __name__ == "__main__":
    unittest.main()
