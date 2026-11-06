"""Tests: destructive commands and the process monitor. Shared helpers and the safety net are in support.py."""
import base64
import os
import subprocess
import sys
import threading
import time
import unittest
from unittest import mock

import support
from support import rg

setUpModule, tearDownModule = support.setUpModule, support.tearDownModule  # the safety net


# ---------------------------------------------------------------- dangerous commands
def ps_encoded(cmd):
    return base64.b64encode(cmd.encode("utf-16-le")).decode()


class DangerousCommandTests(unittest.TestCase):
    def test_attacks_are_caught(self):
        cases = [
            ("vssadmin.exe", "vssadmin delete shadows /all /quiet"),
            ("vssadmin.exe", "vssadmin.exe Delete Shadows /For=C: /Quiet"),
            ("vssadmin.exe", "vssadmin resize shadowstorage /for=c: /on=c: /maxsize=401MB"),
            ("WMIC.exe", "wmic shadowcopy delete"),
            ("cmd.exe", 'cmd.exe /c "vssadmin delete shadows /all /quiet & bcdedit /set {default} recoveryenabled No"'),
            ("bcdedit.exe", "bcdedit /set {default} bootstatuspolicy ignoreallfailures"),
            ("wbadmin.exe", "wbadmin delete catalog -quiet"),
            ("wevtutil.exe", "wevtutil cl System"),
            ("powershell.exe", "powershell -c Set-MpPreference -DisableRealtimeMonitoring $true"),
            ("powershell.exe", "powershell -enc " + ps_encoded("Get-WmiObject Win32_ShadowCopy | Remove-WmiObject")),
            ("pwsh.exe", "pwsh -EncodedCommand " + ps_encoded("vssadmin delete shadows /all")),
        ]
        for name, cmd in cases:
            self.assertIsNotNone(rg.dangerous_process(name, cmd), f"{name}: {cmd}")

    def test_text_that_merely_mentions_commands_is_ignored(self):
        cases = [
            # git commit / search tools whose arguments only *mention* the commands (this cut the network once)
            ("bash.exe", 'bash -c "git commit -m \'detect vssadmin delete shadows\'"'),
            ("git.exe", 'git commit -m "block wevtutil cl and vssadmin delete shadows"'),
            ("rg.exe", "rg vssadmin.*delete shadows src"),
            ("python.exe", "python test.py --pattern vssadmin delete shadows"),
            ("Code.exe", r"Code.exe C:\notes\vssadmin delete shadows.txt"),
            ("notepad.exe", r"notepad.exe C:\notes\wbadmin delete catalog.txt"),
        ]
        for name, cmd in cases:
            self.assertIsNone(rg.dangerous_process(name, cmd), f"{name}: {cmd}")

    def test_harmless_uses_of_the_tools(self):
        for name, cmd in [("vssadmin.exe", "vssadmin list shadows"), ("bcdedit.exe", "bcdedit /enum"),
                          ("wevtutil.exe", "wevtutil qe System /c:5"), ("powershell.exe", "powershell Get-MpPreference"),
                          ("cmd.exe", "cmd /c dir")]:
            self.assertIsNone(rg.dangerous_process(name, cmd), f"{name}: {cmd}")


# ---------------------------------------------------------------- process monitor (real WMI, harmless marker)
class ProcessMonitorTests(unittest.TestCase):
    def test_new_process_is_seen(self):
        marker = "rgtest-" + os.urandom(4).hex()
        hits = []
        got = threading.Event()
        with mock.patch.object(rg, "DANGEROUS_CMDS", [(rg.re.compile(marker), "test", "test")]):
            pm = rg.ProcessMonitor(lambda r: (hits.append(r), got.set()), kill=False)
            pm.start()
            self.addCleanup(pm.stop)
            time.sleep(4)  # let the WMI subscription start
            # without administrator rights only WMI polling (every 0.5 s) can see it. It lives ~1 s: the
            # polling catches ~0.4 s processes on an idle computer, but its interval stretches when the
            # computer is busy (e.g. Defender scanning the files other tests write), and 0.4 s then failed
            subprocess.run(f'cmd.exe /c ""{sys.executable}" -c "import time; time.sleep(1)" & rem {marker}"')
            got.wait(15)
        self.assertTrue(hits, "process monitor did not report the marked process")
        self.assertIn("cmd.exe", hits[0])

    def test_stop_monitor_recognizes_old_and_new_process_monitors(self):
        old_script = ("\n[Console]::OutputEncoding = [System.Text.Encoding]::UTF8\n"
                      "$q = \"SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'\"\n")
        self.assertEqual(rg.ps_encoded_args(old_script)[-1][:120], rg.ps_encoded_args(rg.PROC_PS1)[-1][:120])


if __name__ == "__main__":
    unittest.main()
