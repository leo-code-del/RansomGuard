"""Tests: which program wrote which file, from the kernel's file events. Shared helpers and the safety net are in
support.py."""
import ctypes
import os
import struct
import subprocess
import time
import unittest

import support
from support import BASE_PYTHON, REAL, TempDirTest, rg

setUpModule, tearDownModule = support.setUpModule, support.tearDownModule  # the safety net

TEST_SESSION = "RansomGuard File Trace (tests)"  # never the installed monitor's: starting one ends that


class FakeEvents:
    """Builds EVENT_RECORDs like the ones Windows hands the trace, for its event callback."""

    def __init__(self):
        self.keep = []

    def record(self, event, pid, data, version=1, stamp=1000, flags=0x40):
        payload = ctypes.create_string_buffer(data, len(data))
        rec = ctypes.create_string_buffer(104)
        struct.pack_into("<H", rec, 4, flags)
        struct.pack_into("<I", rec, 12, pid)
        struct.pack_into("<q", rec, 16, stamp)
        struct.pack_into("<HB", rec, 40, event, version)
        struct.pack_into("<H", rec, 86, len(data))
        struct.pack_into("<Q", rec, 96, ctypes.addressof(payload))
        self.keep += [payload, rec]
        return ctypes.addressof(rec)

    def create(self, pid, file_object, name, **kw):
        # Irp, FileObject, IssuingThreadId, CreateOptions, CreateAttributes, ShareAccess, FileName
        data = struct.pack("<QQIIII", 1, file_object, 2, 0, 0, 0) + (name + "\0").encode("utf-16-le")
        return self.record(rg.CREATE, pid, data, **kw)

    def write(self, pid, file_object, **kw):
        # ByteOffset, Irp, FileObject, FileKey, IssuingThreadId, IOSize, IOFlags, ExtraFlags
        return self.record(rg.WRITE, pid, struct.pack("<QQQQIIII", 0, 1, file_object, 3, 2, 4096, 0, 0), **kw)


class KernelNameTests(unittest.TestCase):
    def test_kernel_names_of_folders(self):
        devices = {"C:": r"\device\harddiskvolume3", "Z:": r"\device\mup\nas\share"}
        self.assertEqual(rg.kernel_path(r"C:\Users\A\Desktop", devices), "\\device\\harddiskvolume3\\users\\a\\desktop\\")
        self.assertEqual(rg.kernel_path("C:\\", devices), "\\device\\harddiskvolume3\\")
        self.assertEqual(rg.kernel_path(r"z:\Photos", devices), "\\device\\mup\\nas\\share\\photos\\")
        self.assertEqual(rg.kernel_path(r"\\nas\share\x", devices), "\\device\\mup\\nas\\share\\x\\")
        self.assertEqual(rg.kernel_path(r"Q:\x", devices), "")  # a drive that isn't there

    def test_drives_of_this_computer(self):
        devices = rg._kernel_devices()
        system = os.environ.get("SystemDrive", "C:").upper()
        self.assertTrue(devices[system].startswith("\\device\\"), devices)


class EventTests(TempDirTest):
    def setUp(self):
        super().setUp()
        self.trace = REAL["FileTrace"](TEST_SESSION)
        self.trace.watch([self.dir])
        prefix = rg.kernel_path(self.dir, rg._kernel_devices())
        self.name = lambda n: (prefix + n).upper()  # the kernel keeps the case the program used
        self.ev = FakeEvents()

    def writes(self):
        return [(pid, path) for _, pid, path in self.trace.recent]

    def test_writes_to_watched_files_are_remembered_with_who_wrote_them(self):
        t, ev = self.trace, self.ev
        t._on_event(ev.create(100, 0xA1, self.name("doc.txt"), stamp=5))
        t._on_event(ev.write(100, 0xA1))
        t._on_event(ev.write(100, 0xA1))  # the same file again: once is enough
        self.assertEqual(self.writes(), [(100, rg.norm(self.dir / "doc.txt"))])
        self.assertEqual(t.latest, 1000)
        t._on_event(ev.create(200, 0xB2, r"\Device\HarddiskVolume9\elsewhere\x.txt"))
        t._on_event(ev.write(200, 0xB2))  # not in a watched folder
        t._on_event(ev.write(rg.SYSTEM_PID, 0xA1))  # Windows writing cached data out later
        t._on_event(ev.write(os.getpid(), 0xA1))  # this program
        self.assertEqual(len(self.writes()), 1)

    def test_a_reused_file_object_is_not_taken_for_the_old_file(self):
        t, ev = self.trace, self.ev
        t._on_event(ev.create(100, 0xA1, self.name("doc.txt")))
        t._on_event(ev.create(300, 0xA1, r"\Device\HarddiskVolume9\elsewhere\x.txt"))  # closed, address reused
        t._on_event(ev.write(300, 0xA1))
        self.assertEqual(self.writes(), [])
        # the opening that goes with a write can arrive after it (each processor's events come in batches of
        # their own): another program's write at the same address is never taken for this one's file
        t._on_event(ev.create(100, 0xC3, self.name("report.docx")))
        t._on_event(ev.write(400, 0xC3))
        self.assertEqual(self.writes(), [])
        t._on_event(ev.write(100, 0xC3))
        self.assertEqual(self.writes(), [(100, rg.norm(self.dir / "report.docx"))])

    def test_unknown_event_versions_and_32_bit_events_are_left_alone(self):
        t, ev = self.trace, self.ev
        t._on_event(ev.create(100, 0xA1, self.name("doc.txt"), version=9))  # TDH doesn't know a fake provider
        t._on_event(ev.create(100, 0xA2, self.name("doc.txt"), flags=0x20))
        t._on_event(ev.write(100, 0xA1))
        t._on_event(ev.write(100, 0xA2))
        self.assertEqual(self.writes(), [])


class CulpritTests(unittest.TestCase):
    def test_the_programs_that_wrote_the_evidence(self):
        t = REAL["FileTrace"](TEST_SESSION)
        now = time.monotonic()
        d, other = r"C:\Users\u\Documents", r"C:\Users\u\Music"
        evidence = [rf"{d}\f{i}.docx" for i in range(8)]
        for f in evidence:
            t.recent.append((now - 5, 10, rg.norm(f)))                                # wrote every evidence file
        t.recent += [(now - 5, 20, rg.norm(rf"{d}\other{i}.txt")) for i in range(3)]  # 3 more files in the folder
        t.recent += [(now - 5, 30, rg.norm(rf"{d}\save{i}.txt")) for i in range(2)]   # only 2: an editor saving
        t.recent.append((now - 5, 40, rg.norm(evidence[0])))                          # one evidence file itself
        t.recent += [(now - 5, 50, rg.norm(rf"{other}\m{i}.mp3")) for i in range(9)]  # another folder
        t.recent += [(now - 999, 60, rg.norm(f)) for f in evidence]                   # long ago
        self.assertEqual(t.culprits(evidence), [(10, 8), (20, 3), (40, 1)])
        self.assertEqual(t.culprits([]), [])
        # a renamed file: written under its old name, the evidence is the new one, in the same folder
        self.assertEqual(t.culprits([rf"{other}\m0.mp3.locked"]), [(50, 9)])


@unittest.skipUnless(rg.IS_WINDOWS and rg.is_admin(), "the kernel's file events need administrator rights")
class RealTraceTests(TempDirTest):
    """A real trace session (of its own name) while harmless child processes write and read files in a temporary
    folder."""

    def test_the_program_that_wrote_the_files_is_found(self):
        REAL["stop_trace_session"](TEST_SESSION)
        t = REAL["FileTrace"](TEST_SESSION)
        t.watch([self.dir])
        self.assertTrue(t.start())
        self.addCleanup(t.stop)
        files = [self.dir / f"doc{i}.txt" for i in range(6)]
        write = ("import sys\nfor p in sys.argv[1:]:\n    open(p, 'wb').write(b'x' * 50000)\n")
        read = ("import sys, time\nfor _ in range(20):\n    [open(p, 'rb').read() for p in sys.argv[1:]]\n"
                "    time.sleep(0.05)\n")
        writer = subprocess.Popen([BASE_PYTHON, "-c", write, *map(str, files)])
        writer.wait(30)
        reader = subprocess.Popen([BASE_PYTHON, "-c", read, *map(str, files)])
        reader.wait(30)
        found = dict(t.culprits(files))
        self.assertEqual(found.get(writer.pid), len(files), found)
        self.assertNotIn(reader.pid, found)
        t.stop()
        time.sleep(0.5)
        self.assertFalse(t.alive())


if __name__ == "__main__":
    unittest.main()
