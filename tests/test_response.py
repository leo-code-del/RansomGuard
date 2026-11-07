"""Tests: what happens on a trigger: pausing programs, the full-screen warning. Shared helpers and the safety net
are in support.py."""
import base64
import io
import json
import os
import subprocess
import sys
import threading
import time
import unittest
from unittest import mock

import support
from support import BASE_PYTHON, MODULES, REAL, ROOT, TempDirTest, rg

setUpModule, tearDownModule = support.setUpModule, support.tearDownModule  # the safety net


# ---------------------------------------------------------------- pausing the program that writes the most
WIN = os.environ.get("SystemRoot", r"C:\Windows")


class PauseTests(TempDirTest):
    def fake_writers(self, rows, paths):
        """write_counters() sees `rows` [(pid, name)] each write 100 times / 1 MB during the sample."""
        counters = iter([{}, {pid: (name, 100, 10 ** 6) for pid, name in rows}])
        self.patch("write_counters", lambda: next(counters))
        self.patch("process_path", lambda pid: paths.get(pid, ""))
        self.calls = []
        self.patch("set_paused", lambda pid, paused: self.calls.append((pid, paused)) or True)
        p = mock.patch.object(rg.time, "sleep")
        p.start()
        self.addCleanup(p.stop)

    def test_heaviest_writers(self):
        kb = 1024
        before = {1: ("a.exe", 100, 0), 2: ("b.exe", 0, 0), 3: ("old.exe", 0, 0), 4: ("quiet.exe", 0, 0)}
        after = {1: ("a.exe", 200, 900 * kb),
                 2: ("b.exe", 500, 5000 * kb),       # the most data comes first
                 3: ("new.exe", 30, 300 * kb),       # PID reused by another program: everything counts
                 4: ("quiet.exe", 10, 10000 * kb),   # too few writes
                 5: ("started.exe", 50, 400 * kb),   # started during the sample
                 6: ("small.exe", 500, 100 * kb)}    # too little data
        self.assertEqual([r[0] for r in rg.heaviest_writers(before, after)], [2, 1, 5, 3])
        self.assertEqual(rg.heaviest_writers(before, after)[1], (1, "a.exe", 100, 900 * kb))

    def test_windows_processes_are_trusted_only_in_their_own_folder(self):
        self.assertTrue(rg.trusted_process("svchost.exe", rf"{WIN}\System32\svchost.exe"))
        self.assertTrue(rg.trusted_process("Explorer.EXE", rf"{WIN}\explorer.exe"))
        self.assertTrue(rg.trusted_process("MsMpEng.exe", ""))  # protected: its path can't be read
        self.assertFalse(rg.trusted_process("svchost.exe", r"C:\Users\u\AppData\Local\Temp\svchost.exe"))
        self.assertFalse(rg.trusted_process("svchost.exe", WIN + r"x\svchost.exe"))
        self.assertFalse(rg.trusted_process("powershell.exe",
                                            rf"{WIN}\System32\WindowsPowerShell\v1.0\powershell.exe"))

    def test_heaviest_writers_are_paused_but_not_windows(self):
        self.fake_writers([(1, "svchost.exe"), (2, "evil.exe"), (3, "a.exe"), (4, "b.exe"), (5, "c.exe")],
                          {1: rf"{WIN}\System32\svchost.exe", 2: r"C:\Users\u\evil.exe"})
        self.patch("PAUSE_MAX", 3)
        found = rg.pause_writers(dry_run=False)
        self.assertEqual([p["pid"] for p in found], [2, 3, 4])  # at most PAUSE_MAX
        self.assertEqual(self.calls, [(2, True), (3, True), (4, True)])
        self.assertEqual(found[0], {"pid": 2, "name": "evil.exe", "path": r"C:\Users\u\evil.exe",
                                    "paused": True, "result": "paused"})

    def test_test_mode_pauses_nothing(self):
        self.fake_writers([(2, "evil.exe")], {2: r"C:\Users\u\evil.exe"})
        found = rg.pause_writers(dry_run=True)
        self.assertEqual(self.calls, [])
        self.assertEqual([(p["pid"], p["paused"]) for p in found], [(2, False)])

    def test_trigger_pauses_saves_and_asks_defender(self):
        evil = {"pid": 7, "name": "evil.exe", "path": r"C:\x\evil.exe", "paused": True, "result": "paused"}
        alerts, asked, done = [], [], threading.Event()
        self.patch("app_dir", lambda: self.dir)
        self.patch("IS_WINDOWS", True)
        self.patch("pause_writers", lambda dry_run: [evil])
        self.patch("disconnect_network", lambda: True)
        self.patch("fullscreen_alert", lambda reason, status, paused=(), files=(): alerts.append((status, paused, files)))
        self.patch("ask_defender", lambda paths: (asked.append(paths), done.set()))
        self.addCleanup(rg.init_lang, "en")
        rg.respond("test", dry_run=False, files=[r"C:\d\a.docx", r"C:\d\b.pdf"])
        done.wait(5)
        self.assertEqual(rg.load_state()["paused"], [evil])
        self.assertEqual(rg.load_state()["incident"], {"reason": "test", "files": [r"C:\d\a.docx", r"C:\d\b.pdf"]})
        self.assertEqual(asked, [[r"C:\x\evil.exe"]])
        self.assertEqual(alerts, [("cut", [evil], [r"C:\d\a.docx", r"C:\d\b.pdf"])])
        lines = rg.incident_lines(rg.load_state())
        self.assertEqual(lines[0], "Why: test")
        self.assertIn(r"  C:\d\b.pdf", lines)
        self.assertIn("Programs paused: evil.exe (PID 7)", lines)

    def test_trigger_cuts_the_network_even_if_the_state_cannot_be_saved(self):
        cut = []
        self.patch("app_dir", lambda: self.dir)
        self.patch("IS_WINDOWS", True)
        self.patch("pause_writers", lambda dry_run: [{"pid": 7, "name": "e.exe", "path": "", "paused": True,
                                                      "result": "paused"}])
        self.patch("save_state", mock.Mock(side_effect=OSError("disk full")))
        self.patch("disconnect_network", lambda: cut.append(1) or True)
        self.patch("fullscreen_alert", lambda reason, status, paused=(), files=(): None)
        self.patch("ask_defender", lambda paths: None)
        self.addCleanup(rg.init_lang, "en")
        rg.respond("test", dry_run=False, files=[r"C:\d\a.docx"])
        self.assertEqual(cut, [1])

    def test_false_alarm_resumes_only_clean_programs(self):
        paused = [{"pid": 1, "name": "ok.exe", "path": r"C:\a\ok.exe"},
                  {"pid": 2, "name": "bad.exe", "path": r"C:\a\bad.exe"},
                  {"pid": 3, "name": "gone.exe", "path": r"C:\a\gone.exe"},  # its PID now belongs to another program
                  {"pid": 4, "name": "unknown.exe", "path": ""}]
        self.fake_writers([], {1: r"C:\a\ok.exe", 2: r"C:\a\bad.exe", 3: r"C:\b\new.exe", 4: r"C:\c.exe"})
        self.patch("defender_scan", lambda path: {r"C:\a\ok.exe": 0, r"C:\a\bad.exe": 2}[path])
        msgs = []
        rg.resume_paused(paused, msgs.append)
        self.assertEqual(self.calls, [(1, False)])
        self.assertEqual(len(msgs), 5)
        self.assertIn("bad.exe (PID 2) stays paused", msgs[2])

    def fake_tree(self, tree, started):
        """tree: {pid: (parent pid, name, path)}; started: {pid: start time}."""
        self.patch("process_list", lambda: [(pid, parent, name) for pid, (parent, name, _) in tree.items()])
        self.patch("process_path", lambda pid: tree[pid][2] if pid in tree else "")
        self.patch("process_started", lambda pid: started.get(pid))
        self.calls = []
        self.patch("set_paused", lambda pid, paused: self.calls.append((pid, paused)) or True)

    def test_program_behind_a_destructive_command_is_paused(self):
        # explorer -> evil.exe -> cmd.exe -> (vssadmin, already stopped)
        tree = {30: (1, "explorer.exe", rf"{WIN}\explorer.exe"), 40: (30, "evil.exe", r"C:\Users\u\evil.exe"),
                50: (40, "cmd.exe", rf"{WIN}\System32\cmd.exe")}
        self.fake_tree(tree, {30: 100, 40: 200, 50: 300})
        found = rg.pause_ancestors(50, dry_run=False)
        self.assertEqual([p["pid"] for p in found], [50, 40])  # stops at explorer.exe
        self.assertEqual(self.calls, [(50, True), (40, True)])

    def test_a_reused_pid_is_not_taken_for_a_parent(self):
        tree = {40: (30, "unrelated.exe", r"C:\x\unrelated.exe"), 50: (40, "cmd.exe", rf"{WIN}\System32\cmd.exe")}
        self.fake_tree(tree, {40: 900, 50: 300})  # "parent" 40 started after its child: the real one has exited
        self.assertEqual([p["pid"] for p in rg.pause_ancestors(50, dry_run=False)], [50])

    def test_ancestors_stop_at_this_program_and_in_test_mode_nothing_is_paused(self):
        me = os.getpid()
        tree = {me: (1, "RansomGuard.exe", r"C:\x\RansomGuard.exe"), 50: (me, "cmd.exe", rf"{WIN}\System32\cmd.exe")}
        self.fake_tree(tree, {me: 100, 50: 300})
        found = rg.pause_ancestors(50, dry_run=True)
        self.assertEqual([(p["pid"], p["paused"]) for p in found], [(50, False)])
        self.assertEqual(self.calls, [])

    def test_programs_paused_behind_a_command_are_recorded_at_once(self):
        # also after a first trigger, when no respond() follows to record them
        evil = {"pid": 40, "name": "evil.exe", "path": r"C:\x\evil.exe", "paused": True, "result": "paused"}
        hits = []
        self.patch("app_dir", lambda: self.dir)
        self.patch("pause_ancestors", lambda ppid, dry_run: [dict(evil)])
        self.addCleanup(rg._early_paused.clear)
        marker = "rgtest-" + os.urandom(4).hex()
        with mock.patch.object(rg, "DANGEROUS_CMDS", [(rg.re.compile(marker), "test", "test")]), \
                mock.patch.object(rg.os, "kill", lambda pid, sig: None):
            pm = rg.ProcessMonitor(hits.append, kill=True)
            pm._check(100, 40, "cmd.exe", f"cmd /c {marker}")
            pm._check(101, 40, "cmd.exe", f"cmd /c {marker}")  # the same program again
        self.assertEqual(len(hits), 2)
        self.assertEqual(rg.load_state()["paused"], [evil])
        rg.record_paused([{**evil, "pid": 41}, {**evil, "pid": 42, "paused": False}])
        self.assertEqual([p["pid"] for p in rg.load_state()["paused"]], [40, 41])

    def test_trigger_reports_programs_paused_early_once(self):
        evil = {"pid": 40, "name": "evil.exe", "path": r"C:\x\evil.exe", "paused": True, "result": "paused"}
        alerts = []
        self.patch("app_dir", lambda: self.dir)
        self.patch("IS_WINDOWS", True)
        self.patch("pause_writers", lambda dry_run: [dict(evil), {**evil, "pid": 41, "name": "other.exe"}])
        self.patch("disconnect_network", lambda: True)
        self.patch("fullscreen_alert", lambda reason, status, paused=(), files=(): alerts.append(paused))
        self.patch("ask_defender", lambda paths: None)
        self.addCleanup(rg.init_lang, "en")
        rg._early_paused.append(evil)
        rg.respond("test", dry_run=False)
        self.assertEqual([p["pid"] for p in alerts[0]], [40, 41])
        self.assertEqual(rg._early_paused, [])

    def test_real_chain_of_parents_is_paused(self):
        # this test -> A -> B, all harmless Python processes; B's parent chain is paused up to this test.
        # BASE_PYTHON, not a venv's launcher, which would add a process to each level
        code_b = "import time; time.sleep(60)"
        code_a = ("import subprocess, sys, time\n"
                  f"b = subprocess.Popen([sys.executable, '-c', {code_b!r}])\n"
                  "print(b.pid, flush=True)\ntime.sleep(60)\n")
        a = subprocess.Popen([BASE_PYTHON, "-c", code_a], stdout=subprocess.PIPE)
        b_pid = int(a.stdout.readline())
        self.addCleanup(a.stdout.close)
        self.addCleanup(a.wait)
        self.addCleanup(a.kill)
        self.addCleanup(lambda: subprocess.run(["taskkill", "/F", "/PID", str(b_pid)], capture_output=True))
        self.assertLess(rg.process_started(a.pid), rg.process_started(b_pid))
        found = rg.pause_ancestors(b_pid, dry_run=False)
        self.assertEqual([p["pid"] for p in found], [b_pid, a.pid])
        self.assertTrue(all(p["paused"] for p in found))
        for p in found:
            self.assertTrue(rg.set_paused(p["pid"], False))

    def test_process_path_of_this_process(self):
        # in a venv, sys.executable is a launcher that starts the real interpreter: this process is the latter
        self.assertEqual(rg.norm(rg.process_path(os.getpid())), rg.norm(BASE_PYTHON))
        self.assertEqual(rg.process_path(0x7FFFFFF0), "")  # no such process

    def test_warning_does_not_flash(self):
        # the background is set once when the window is built; changing it in the timer made it flash
        self.assertEqual(rg.ALERT_PS1.count("BackColor = $script:bright"), 1)
        timer = rg.ALERT_PS1[rg.ALERT_PS1.index("$timer.add_Tick"):]
        self.assertNotIn("BackColor", timer)

    def test_build_script_packs_the_icon(self):
        # without these the exe shows PyInstaller's default icon (v1.5.4 to v1.6.1 were built that way)
        script = (ROOT / "build.bat").read_text(encoding="utf-8")
        self.assertIn(r"--icon ..\icon.ico", script)
        self.assertIn(r'--add-data "..\icon.ico;."', script)
        for state in ("ok", "paused", "cut"):  # the notification-area icons
            self.assertIn(rf'--add-data "..\tray-{state}.ico;."', script)
            self.assertTrue((ROOT / f"tray-{state}.ico").is_file())
        self.assertIn("check_build.py", script)  # an exe without Tcl/Tk data doesn't start (v1.7.1)
        # code signing (SignPath) requires the product name and version in every signed exe
        self.assertIn("make_version_info.py build\\version_info.txt", script)
        self.assertIn(r'--version-file "%~dp0build\version_info.txt"', script)

    def test_release_notes_link_the_code_signing_policy(self):
        # SignPath requires the code signing policy to be linked from every release page
        sys.path.insert(0, str(ROOT / ".github" / "scripts"))
        import release_notes
        text = release_notes.notes("Fixes.\r\n\r\nDocs: link\r\n", "leo-code-del/RansomGuard")
        self.assertTrue(text.startswith("Fixes.\n\nDocs: link\n"))
        self.assertIn("**Code signing policy:**", text)
        self.assertIn("RansomGuard#code-signing-policy", text)
        self.assertEqual(release_notes.notes(text, "leo-code-del/RansomGuard"), text)  # added only once
        workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        self.assertIn("release_notes.py", workflow)

    def test_version_info_matches_config(self):
        sys.path.insert(0, str(ROOT))
        import make_version_info
        version = make_version_info.read_version((ROOT / "ransomguard" / "config.py").read_text(encoding="utf-8"))
        self.assertEqual(version, rg.VERSION)
        text = make_version_info.version_info(version)
        four = "(" + ", ".join(version.split(".") + ["0"]) + ")"
        self.assertIn(f"filevers={four}", text)
        self.assertIn(f"prodvers={four}", text)
        self.assertIn("StringStruct('ProductName', 'RansomGuard')", text)
        self.assertIn(f"StringStruct('ProductVersion', '{version}')", text)
        with self.assertRaises(ValueError):
            make_version_info.read_version('VERSION = "dev"')

    def test_build_check_finds_a_missing_tcl_tk(self):
        sys.path.insert(0, str(ROOT))
        try:
            import check_build
        except ImportError:
            self.skipTest("PyInstaller is not installed (pip install -r requirements-build.txt)")
        trays = ["tray-ok.ico", "tray-paused.ico", "tray-cut.ico"]
        good = ["icon.ico", "tk86t.dll", "tcl86t.dll", "_tcl_data/init.tcl", "_tk_data/tk.tcl", "base_library.zip"] + trays
        self.assertEqual(check_build.missing(good), [])
        v171 = ["icon.ico", "tcl90.dll", "base_library.zip"] + trays  # what the broken v1.7.1 contained
        self.assertEqual(len(check_build.missing(v171)), 3)
        self.assertEqual(check_build.missing([n for n in good if n != "icon.ico"]), ["icon (icon.ico)"])
        self.assertEqual(check_build.missing([n for n in good if n != "tray-cut.ico"]),
                         ["notification-area icon (tray-cut.ico)"])
        modules = {"ransomguard"} | {m.__name__ for m in MODULES}
        self.assertEqual(check_build.missing_modules(modules), [])
        self.assertEqual(check_build.missing_modules(modules - {"ransomguard.gui"}), ["ransomguard.gui"])

    def test_real_writer_is_found_paused_and_resumed(self):
        # a harmless child that keeps overwriting the start of one file in a temp folder
        code = ("import os, sys, time\nprint(os.getpid(), flush=True)\nf = open(sys.argv[1], 'wb', buffering=0)\n"
                "while True:\n    f.seek(0); f.write(b'x' * 65536); time.sleep(0.005)\n")
        p = subprocess.Popen([sys.executable, "-c", code, str(self.dir / "w.bin")], stdout=subprocess.PIPE)
        self.addCleanup(p.stdout.close)
        self.addCleanup(p.wait)
        self.addCleanup(p.kill)
        pid = int(p.stdout.readline())
        with mock.patch.object(rg.os, "getpid", lambda: 0):  # write_counters() skips this program's children
            before = rg.write_counters()
            time.sleep(1)
            after = rg.write_counters()
            self.assertIn(pid, [r[0] for r in rg.heaviest_writers(before, after)])
            self.assertTrue(rg.process_path(pid).lower().endswith(".exe"))
            self.assertTrue(rg.set_paused(pid, True))
            time.sleep(0.3)
            w1 = rg.write_counters()[pid][1]
            time.sleep(0.5)
            self.assertEqual(rg.write_counters()[pid][1], w1, "a paused process must not write")
            self.assertTrue(rg.set_paused(pid, False))
            time.sleep(0.5)
            self.assertGreater(rg.write_counters()[pid][1], w1, "a resumed process writes again")


# ---------------------------------------------------------------- the full-screen warning's content
class WarningTests(unittest.TestCase):
    def show(self, reason, status, paused=(), exit_code=None, files=()):
        """Call the real fullscreen_alert() with PowerShell replaced; returns (process, shown info, args, alerts)."""
        seen, alerts = {}, []

        class FakeProc:
            def __init__(self, args, **kw):
                seen["args"], seen["env"] = args, kw["env"]
                self.stderr = io.BytesIO(b"window failed")

            def wait(self, timeout=None):
                if exit_code is None:  # still open = the warning is showing
                    raise subprocess.TimeoutExpired("powershell", timeout)
                return exit_code
        with mock.patch.object(rg, "fullscreen_alert", REAL["fullscreen_alert"]), \
                mock.patch.object(rg.subprocess, "Popen", FakeProc), mock.patch.object(rg, "IS_WINDOWS", True), \
                mock.patch.object(rg, "alert", lambda title, msg: alerts.append(msg)):
            proc = rg.fullscreen_alert(reason, status, paused=paused, files=files)
        info = json.loads(base64.b64decode(seen["env"]["RG_ALERT_INFO"]).decode("utf-8"))
        return proc, info, seen["args"], alerts

    def test_warning_names_a_few_of_the_files(self):
        files = [rf"C:\Users\x\Documents\report{i}.docx" for i in range(9)]
        _, info, args, _ = self.show("8 files that look encrypted", "cut", files=files)
        self.assertIn("Files that look encrypted: report6.docx, report7.docx, report8.docx and 6 more",
                      info["t"]["detail"])
        self.assertNotIn("report8.docx", " ".join(args), "file names stay off the command line")
        _, info, _, _ = self.show("Canary file was modified", "cut")
        self.assertNotIn("Files that look encrypted", info["t"]["detail"])

    def test_warning_names_the_reason_and_the_paused_programs(self):
        evil = {"pid": 7, "name": "evil.exe", "path": r"C:\x\evil.exe", "paused": True, "result": "paused"}
        proc, info, _, alerts = self.show("Canary file was modified", "cut", [evil])
        self.assertIsNotNone(proc)
        self.assertEqual(info["status"], "cut")
        self.assertEqual(info["t"]["net"], "The network has been cut off automatically")
        self.assertIn("Reason: Canary file was modified", info["t"]["detail"])
        self.assertIn("Suspicious programs: evil.exe (PID 7, paused)", info["t"]["detail"])
        self.assertEqual(alerts, [])

    def test_reason_stays_off_the_command_line_and_is_shortened(self):
        # a reason can quote a destructive command, and Defender blocks command lines containing one
        marker = "rgtest-" + os.urandom(4).hex()
        _, info, args, _ = self.show(marker + "x" * 300, "partial")
        self.assertNotIn(marker, " ".join(args))
        self.assertIn(marker, info["t"]["detail"])
        self.assertIn("x" * 140 + "...", info["t"]["detail"])
        self.assertNotIn("x" * 160, info["t"]["detail"])
        self.assertIn("may not be fully cut off", info["t"]["net"])

    def test_test_mode_says_so(self):
        _, info, _, _ = self.show("preview", "test")
        self.assertIn("Test mode", info["t"]["net"])
        self.assertIn("This is a test", info["t"]["hint"])

    def test_a_window_that_fails_falls_back_to_a_message_box(self):
        proc, _, _, alerts = self.show("Canary file was modified", "cut", exit_code=3)
        self.assertIsNone(proc)
        self.assertIn("Canary file was modified", alerts[0])


if __name__ == "__main__":
    unittest.main()
