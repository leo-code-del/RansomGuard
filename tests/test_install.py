"""Tests: installing, updating and the update notification. Shared helpers and the safety net are in support.py."""
import hashlib
import io
import json
import os
import shutil
import subprocess
import threading
import time
import unittest
import urllib.request
from unittest import mock

import support
from support import TempDirTest, random_bytes, rg

setUpModule, tearDownModule = support.setUpModule, support.tearDownModule  # the safety net


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

    def serve(self, tag="v1.5.0", digest=None,
              url="https://github.com/leo-code-del/RansomGuard/releases/download/v1.5.0/RansomGuard.exe",
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


if __name__ == "__main__":
    unittest.main()
