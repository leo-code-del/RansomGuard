"""Tests: cutting the network off, keeping it off and restoring it; the control panel's status. Shared helpers
and the safety net are in support.py."""
import json
import threading
import unittest
from pathlib import Path
from unittest import mock

import support
from support import TempDirTest, rg

setUpModule, tearDownModule = support.setUpModule, support.tearDownModule  # the safety net


# ---------------------------------------------------------------- network cut / restore (simulated adapters)
class FakeNetwork:
    """Stands in for the PowerShell network commands, so nothing real is touched."""

    def __init__(self, adapters=("Ethernet", "Wi-Fi"), disable_works=True, enable_fails=()):
        self.up = set(adapters)
        self.disabled = set()
        self.disable_works = disable_works
        self.enable_fails = set(enable_fails)
        self.firewall_blocked = False
        self.task = "Running"
        self.commands = []

    def cut(self, saved):
        """Stands in for _cut_adapters(): the names are saved before anything is turned off."""
        self.commands.append("cut")
        saved(sorted(self.up))
        if self.disable_works:
            self.disabled |= self.up
            self.up = set()
        return 0, ""

    def ps(self, cmd, timeout=60):
        self.commands.append(cmd)
        if ".Count" in cmd:
            return 0, str(len(self.up)), ""
        if "Get-NetFirewallProfile" in cmd:
            return 0, json.dumps([{"Name": "Domain", "Enabled": "True", "In": "Block", "Out": "Allow"}]), ""
        if "Set-NetFirewallProfile -All" in cmd:
            self.firewall_blocked = True
            return 0, "", ""
        if "Set-NetFirewallProfile -Name" in cmd:
            self.firewall_blocked = False
            return 0, "", ""
        if "Enable-NetAdapter" in cmd:
            out = []
            for a in sorted(self.disabled):
                if a in self.enable_fails:
                    out.append(f"FAIL\t{a}\tdevice not found")
                else:
                    out.append(f"OK\t{a}")
                    self.up.add(a)
            self.disabled -= self.up
            return 0, "\n".join(out), ""
        if "Get-ScheduledTask" in cmd:
            return 0, self.task, ""
        if "Start-ScheduledTask" in cmd:
            self.task = "Running"
        if "Stop-ScheduledTask" in cmd:
            self.task = "Ready"
        return 0, "", ""


class NetworkTests(TempDirTest):
    def setUp(self):
        super().setUp()
        for name, value in (("app_dir", lambda: self.dir), ("is_admin", lambda: True), ("_run", lambda a: None),
                            ("IS_WINDOWS", True)):
            p = mock.patch.object(rg, name, value)
            p.start()
            self.addCleanup(p.stop)
        p = mock.patch.object(rg.time, "sleep")
        p.start()
        self.addCleanup(p.stop)

    def use(self, net):
        for name, value in (("_ps", net.ps), ("_cut_adapters", net.cut)):
            p = mock.patch.object(rg, name, value)
            p.start()
            self.addCleanup(p.stop)
        return net

    def test_cut_and_restore(self):
        net = self.use(FakeNetwork())
        self.assertTrue(rg.disconnect_network())
        st = rg.load_state()
        self.assertEqual(st["disabled_adapters"], ["Ethernet", "Wi-Fi"])
        self.assertTrue(st["triggered_at"])
        self.assertTrue(rg.network_cut(st))
        msgs = []
        self.assertTrue(rg.restore_network(msgs.append))
        self.assertEqual(net.up, {"Ethernet", "Wi-Fi"})
        self.assertEqual(rg.load_state(), {})
        self.assertEqual(net.task, "Running")

    def test_firewall_fallback_when_adapters_stay_up(self):
        net = self.use(FakeNetwork(disable_works=False))
        self.assertFalse(rg.disconnect_network())
        self.assertTrue(net.firewall_blocked)
        self.assertIn("firewall", rg.load_state())
        self.assertTrue(rg.restore_network(lambda m: None))
        self.assertFalse(net.firewall_blocked)

    def test_partial_restore_keeps_state(self):
        net = self.use(FakeNetwork(enable_fails=("Wi-Fi",)))
        rg.disconnect_network()
        self.assertEqual(net.disabled, {"Ethernet", "Wi-Fi"})
        msgs = []
        self.assertFalse(rg.restore_network(msgs.append))
        self.assertTrue(rg.network_cut(rg.load_state()), "state must stay so the user can retry")
        self.assertTrue(any("ncpa.cpl" in m for m in msgs))

    def test_second_cut_keeps_first_adapter_list(self):
        net = self.use(FakeNetwork())
        rg.disconnect_network()
        net.up.add("USB Ethernet")  # an adapter re-enabled or plugged in while the warning is open
        rg.disconnect_network()
        self.assertEqual(rg.load_state()["disabled_adapters"], ["Ethernet", "USB Ethernet", "Wi-Fi"])

    def test_the_adapter_names_are_saved_before_they_are_turned_off(self):
        # the real PowerShell, with a harmless script in place of the one that turns adapters off
        marker = self.dir / "saved"
        harmless = ("[Console]::Out.WriteLine(\"NAME`tEthernet\"); [Console]::Out.WriteLine(\"NAME`tWi-Fi 2\")\n"
                    "[Console]::Out.WriteLine('SAVE'); [Console]::Out.Flush()\n"
                    "$null = [Console]::In.ReadLine()\n"
                    f"if (Test-Path -LiteralPath '{marker}') {{ exit 0 }} else {{ exit 3 }}\n")
        cut = support.REAL["_cut_adapters"]
        got = []
        with mock.patch.object(rg, "CUT_PS1", harmless):
            rc, _ = cut(lambda names: (got.append(names), marker.write_text("x")))
            self.assertEqual((rc, got), (0, [["Ethernet", "Wi-Fi 2"]]))
            marker.unlink()
            rc, _ = cut(mock.Mock(side_effect=OSError("disk full")))
            self.assertEqual(rc, 3, "it goes on without the names saved: cutting the network matters more")
        self.assertLess(rg.CUT_PS1.index("ReadLine"), rg.CUT_PS1.index("Disable-NetAdapter"))

    def test_restore_needs_admin(self):
        self.use(FakeNetwork())
        with mock.patch.object(rg, "is_admin", lambda: False):
            self.assertFalse(rg.restore_network(lambda m: None))

    def test_restore_resumes_paused_programs(self):
        self.use(FakeNetwork())
        rg.disconnect_network()
        st = rg.load_state()
        st["paused"] = [{"pid": 7, "name": "a.exe", "path": r"C:\x\a.exe", "paused": True, "result": "paused"}]
        rg.save_state(st)
        got = []
        with mock.patch.object(rg, "resume_paused", lambda paused, report: got.append(paused)):
            self.assertTrue(rg.restore_network(lambda m: None))
        self.assertEqual(got, [st["paused"]])
        self.assertEqual(rg.load_state(), {})


# ---------------------------------------------------------------- control panel status, keeping offline, scanning
class StatusAndOfflineTests(TempDirTest):
    def setUp(self):
        super().setUp()
        p = mock.patch.object(rg, "app_dir", lambda: self.dir)
        p.start()
        self.addCleanup(p.stop)

    def test_status_cards(self):
        def cards(task, state):
            rg.save_state(state)
            with mock.patch.object(rg, "task_state", lambda: task):
                (_, mon, _), (_, net, _) = rg.status_info()
            return mon, net
        self.assertEqual(cards("Running", {}), ("ok", "ok"))
        self.assertEqual(cards("Ready", {}), ("warn", "ok"))
        self.assertEqual(cards("", {}), ("off", "ok"))
        self.assertEqual(cards("Running", {"triggered_at": "2026-11-02 10:00:00"}), ("ok", "bad"))
        self.assertEqual(cards("Ready", {"firewall": [{"Name": "Domain", "Enabled": "True", "In": "Block",
                                                       "Out": "Allow"}]}), ("warn", "bad"))
        rg.save_state({})
        rg.pause_detection(30)
        self.addCleanup(rg.resume_detection)
        with mock.patch.object(rg, "task_state", lambda: "Running"):
            (text, light, note), _ = rg.status_info()
        self.assertEqual((text, light), ("Detection paused", "paused"))
        self.assertIn("canary files are still watched", note)

    def test_the_home_page_shows_one_status_and_what_to_do(self):
        rg.init_lang("en")
        running, normal = ("Running", "ok", ""), ("Normal", "ok", "")
        cut = ("Cut off", "bad", "Suspicious activity detected at 2026-11-07 10:00:00")
        cases = {
            (running, normal): ("Protected", "ok", "selfcheck"),
            (running, cut): ("Network cut off", "bad", "restore"),
            (("Not installed", "off", ""), cut): ("Network cut off", "bad", "restore"),  # a cut network comes first
            (("Not installed", "off", ""), normal): ("Not installed", "off", "install"),
            (("Stopped", "warn", ""), normal): ("Not protected", "warn", "install"),
            (("Detection paused", "paused", "Resumes at 11:00"), normal): ("Detection paused", "paused", "resume"),
        }
        for info, (title, light, todo) in cases.items():
            got = rg.home_status(info)
            self.assertEqual((got[0], got[1], got[3]), (title, light, todo), info)
        self.assertEqual(rg.home_status((running, cut))[2], cut[2], "says when it was cut")
        self.assertIn("Stopped", rg.home_status((("Stopped", "warn", ""), normal))[2])

    def test_network_turned_back_on_is_cut_again_while_the_warning_is_open(self):
        polls = iter([None, None, None, 0, 0])  # the warning closes after two checks
        cut = []
        with mock.patch.object(rg.time, "sleep"), mock.patch.object(rg, "adapters_up", lambda: "1"), \
                mock.patch.object(rg, "disconnect_network", lambda: cut.append(1)):
            rg.keep_offline(mock.Mock(poll=lambda: next(polls)))
        self.assertEqual(cut, [1])

    def test_download_scanner_worker_keeps_going_after_an_error(self):
        with mock.patch.object(rg, "_known_folder", lambda name: self.dir / name):
            s = rg.DownloadScanner(lambda path: None)
        seen, done = [], threading.Event()

        def scan(path):
            seen.append(Path(path).name)
            if len(seen) == 1:
                raise OSError("scan failed")
            done.set()
        s.scan = scan
        s.start()
        s.add(self.dir / "Downloads" / "a.exe")
        s.add(self.dir / "Downloads" / "b.exe")
        done.wait(5)
        self.assertEqual(seen, ["a.exe", "b.exe"])


if __name__ == "__main__":
    unittest.main()
