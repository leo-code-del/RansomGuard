"""Which program writes which file, from Windows' kernel file events (ETW, the Microsoft-Windows-Kernel-File
provider). The file monitor sees what changed but not who changed it; with this, a trigger pauses the programs
that wrote the files that looked encrypted, instead of the ones that write the most.

Listening needs administrator rights (the monitor has them) and costs next to nothing: the kernel sends file
opens and writes, and only writes to files in watched folders are kept, for a couple of minutes."""
import collections
import ctypes
import os
import re
import struct
import threading
import time
import uuid
from ctypes import c_long, c_ubyte, c_uint16, c_uint32, c_uint64, c_int64, c_void_p, c_wchar, c_wchar_p

from .config import log, tr
from .winapi import norm

SESSION = "RansomGuard File Trace"
KERNEL_FILE = "EDD08927-9CC4-4E65-B970-C2560FB5C289"  # Microsoft-Windows-Kernel-File
KEYWORDS = 0x80 | 0x200  # KERNEL_FILE_KEYWORD_CREATE | KERNEL_FILE_KEYWORD_WRITE
CREATE, WRITE = 12, 16   # event IDs
SYSTEM_PID = 4           # Windows writing cached data out later: not the program that wrote it
KEEP_MAX = 20000         # writes remembered at most (the oldest go first)
OPEN_MAX = 100000        # open files remembered at most
LOOKBACK_SEC = 60        # on a trigger, the writes of the last minute are looked at
# a program that wrote this many files in the folders of the evidence is paused (one that wrote an evidence file
# itself is paused anyway)
CULPRIT_MIN_FILES = 3
# on a trigger, the trace is looked at this long at least: the events of each processor arrive in batches of their
# own (seen: 0.16-0.21 s for the writes before a trigger)
TRACE_SETTLE_SEC = 0.3
current = None  # the FileTrace the monitor runs, for respond(); None when there is none


class GUID(ctypes.Structure):
    _fields_ = [("b", c_ubyte * 16)]


def _guid(text):
    g = GUID()
    ctypes.memmove(ctypes.byref(g), uuid.UUID(text).bytes_le, 16)
    return g


class WNODE_HEADER(ctypes.Structure):
    _fields_ = [("BufferSize", c_uint32), ("ProviderId", c_uint32), ("HistoricalContext", c_uint64),
                ("TimeStamp", c_int64), ("Guid", GUID), ("ClientContext", c_uint32), ("Flags", c_uint32)]


class EVENT_TRACE_PROPERTIES(ctypes.Structure):
    _fields_ = [("Wnode", WNODE_HEADER), ("BufferSize", c_uint32), ("MinimumBuffers", c_uint32),
                ("MaximumBuffers", c_uint32), ("MaximumFileSize", c_uint32), ("LogFileMode", c_uint32),
                ("FlushTimer", c_uint32), ("EnableFlags", c_uint32), ("AgeLimit", c_long),
                ("NumberOfBuffers", c_uint32), ("FreeBuffers", c_uint32), ("EventsLost", c_uint32),
                ("BuffersWritten", c_uint32), ("LogBuffersLost", c_uint32), ("RealTimeBuffersLost", c_uint32),
                ("LoggerThreadId", c_void_p), ("LogFileNameOffset", c_uint32), ("LoggerNameOffset", c_uint32)]


class _Properties(ctypes.Structure):
    _fields_ = [("p", EVENT_TRACE_PROPERTIES), ("name", c_wchar * 1024)]  # the session name goes after them


class EVENT_TRACE_HEADER(ctypes.Structure):
    _fields_ = [("Size", c_uint16), ("FieldTypeFlags", c_uint16), ("Version", c_uint32), ("ThreadId", c_uint32),
                ("ProcessId", c_uint32), ("TimeStamp", c_int64), ("Guid", GUID), ("ProcessorTime", c_uint64)]


class EVENT_TRACE(ctypes.Structure):
    _fields_ = [("Header", EVENT_TRACE_HEADER), ("InstanceId", c_uint32), ("ParentInstanceId", c_uint32),
                ("ParentGuid", GUID), ("MofData", c_void_p), ("MofLength", c_uint32), ("ClientContext", c_uint32)]


class SYSTEMTIME(ctypes.Structure):
    _fields_ = [("w", c_uint16 * 8)]


class TIME_ZONE_INFORMATION(ctypes.Structure):
    _fields_ = [("Bias", c_long), ("StandardName", c_wchar * 32), ("StandardDate", SYSTEMTIME),
                ("StandardBias", c_long), ("DaylightName", c_wchar * 32), ("DaylightDate", SYSTEMTIME),
                ("DaylightBias", c_long)]


class TRACE_LOGFILE_HEADER(ctypes.Structure):
    _fields_ = [("BufferSize", c_uint32), ("Version", c_uint32), ("ProviderVersion", c_uint32),
                ("NumberOfProcessors", c_uint32), ("EndTime", c_int64), ("TimerResolution", c_uint32),
                ("MaximumFileSize", c_uint32), ("LogFileMode", c_uint32), ("BuffersWritten", c_uint32),
                ("LogInstanceGuid", GUID), ("LoggerName", c_void_p), ("LogFileName", c_void_p),
                ("TimeZone", TIME_ZONE_INFORMATION), ("BootTime", c_int64), ("PerfFreq", c_int64),
                ("StartTime", c_int64), ("ReservedFlags", c_uint32), ("BuffersLost", c_uint32)]


_CALLBACK = ctypes.WINFUNCTYPE(None, c_void_p)  # gets the address of an EVENT_RECORD


class EVENT_TRACE_LOGFILEW(ctypes.Structure):
    _fields_ = [("LogFileName", c_wchar_p), ("LoggerName", c_wchar_p), ("CurrentTime", c_int64),
                ("BuffersRead", c_uint32), ("ProcessTraceMode", c_uint32), ("CurrentEvent", EVENT_TRACE),
                ("LogfileHeader", TRACE_LOGFILE_HEADER), ("BufferCallback", c_void_p), ("BufferSize", c_uint32),
                ("Filled", c_uint32), ("EventsLost", c_uint32), ("EventRecordCallback", _CALLBACK),
                ("IsKernelTrace", c_uint32), ("Context", c_void_p)]


class EVENT_PROPERTY_INFO(ctypes.Structure):
    _fields_ = [("Flags", c_uint32), ("NameOffset", c_uint32), ("InType", c_uint16), ("OutType", c_uint16),
                ("MapNameOffset", c_uint32), ("count", c_uint16), ("length", c_uint16), ("Reserved", c_uint32)]


class TRACE_EVENT_INFO(ctypes.Structure):
    _fields_ = [("ProviderGuid", GUID), ("EventGuid", GUID), ("EventDescriptor", c_ubyte * 16)] + [
        (n, c_uint32) for n in ("DecodingSource", "ProviderNameOffset", "LevelNameOffset", "ChannelNameOffset",
                                "KeywordsNameOffset", "TaskNameOffset", "OpcodeNameOffset", "EventMessageOffset",
                                "ProviderMessageOffset", "BinaryXMLOffset", "BinaryXMLSize", "EventNameOffset",
                                "EventAttributesOffset", "PropertyCount", "TopLevelPropertyCount", "Flags")]


# The parts of an EVENT_RECORD read for each event: header flags, process ID, time stamp, event ID and version,
# the size of the event's data and where it is
_HEADER = struct.Struct("<4xH6xIq16xHB43xH8xQ")
_32BIT_HEADER = 0x20
# Where FileObject and FileName are in the event data (64-bit Windows), per (event ID, version); other versions
# are looked up once through TDH
_LAYOUTS = {(CREATE, 1): (8, 32), (WRITE, 1): (16, None)}
_FIXED_SIZES = {3: 1, 4: 1, 5: 2, 6: 2, 7: 4, 8: 4, 9: 8, 10: 8, 11: 4, 12: 8, 13: 4, 15: 16, 16: 8, 17: 8, 18: 16,
                20: 4, 21: 8}  # TDH in-types of a fixed size (16: a pointer, 8 bytes on 64-bit Windows)


def _api():
    adv = ctypes.WinDLL("advapi32")
    props = ctypes.POINTER(EVENT_TRACE_PROPERTIES)
    for name, res, args in (
            ("StartTraceW", c_uint32, [ctypes.POINTER(c_uint64), c_wchar_p, props]),
            ("ControlTraceW", c_uint32, [c_uint64, c_wchar_p, props, c_uint32]),
            ("EnableTraceEx2", c_uint32, [c_uint64, ctypes.POINTER(GUID), c_uint32, c_ubyte, c_uint64, c_uint64,
                                          c_uint32, c_void_p]),
            ("OpenTraceW", c_uint64, [ctypes.POINTER(EVENT_TRACE_LOGFILEW)]),
            ("ProcessTrace", c_uint32, [ctypes.POINTER(c_uint64), c_uint32, c_void_p, c_void_p]),
            ("CloseTrace", c_uint32, [c_uint64])):
        fn = getattr(adv, name)
        fn.restype, fn.argtypes = res, args
    return adv


def _properties():
    b = _Properties()
    b.p.Wnode.BufferSize = ctypes.sizeof(_Properties)
    b.p.Wnode.Flags = 0x20000      # WNODE_FLAG_TRACED_GUID
    b.p.Wnode.ClientContext = 1    # time stamps from QueryPerformanceCounter
    b.p.LogFileMode = 0x100        # EVENT_TRACE_REAL_TIME_MODE
    b.p.FlushTimer = 1             # deliver events at least every second
    b.p.BufferSize = 64            # KB
    b.p.MinimumBuffers, b.p.MaximumBuffers = 8, 64
    b.p.LoggerNameOffset = ctypes.sizeof(EVENT_TRACE_PROPERTIES)
    return b


def stop_trace_session(session=SESSION):
    """End the session if one is left (a monitor that was ended doesn't end it). Never raises."""
    try:
        _api().ControlTraceW(0, session, ctypes.byref(_properties().p), 1)  # EVENT_TRACE_CONTROL_STOP
    except Exception:
        pass


def _layout(addr):
    """(FileObject offset, FileName offset or None) of an event version not in _LAYOUTS, from TDH; None if the
    event has no FileObject."""
    tdh = ctypes.WinDLL("tdh")
    size = c_uint32(0)
    tdh.TdhGetEventInformation(c_void_p(addr), 0, None, None, ctypes.byref(size))
    buf = ctypes.create_string_buffer(size.value or 1)
    if tdh.TdhGetEventInformation(c_void_p(addr), 0, None, buf, ctypes.byref(size)):
        return None
    info = TRACE_EVENT_INFO.from_buffer(buf)
    found, off = {}, 0
    for i in range(info.TopLevelPropertyCount):
        p = EVENT_PROPERTY_INFO.from_buffer(buf, ctypes.sizeof(TRACE_EVENT_INFO) + i * ctypes.sizeof(EVENT_PROPERTY_INFO))
        found[ctypes.wstring_at(ctypes.addressof(buf) + p.NameOffset)] = off
        step = _FIXED_SIZES.get(p.InType)
        if not step or p.Flags:  # a string or anything of variable size: what comes after it can't be placed
            break
        off += step
    return (found["FileObject"], found.get("FileName")) if "FileObject" in found else None


def _kernel_devices() -> dict:
    """{"C:": r"\\device\\harddiskvolume3", ...} for every drive letter: the kernel names files by device."""
    k32 = ctypes.WinDLL("kernel32")
    k32.QueryDosDeviceW.argtypes = [c_wchar_p, c_wchar_p, c_uint32]
    buf = ctypes.create_unicode_buffer(1024)
    out = {}
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        if k32.QueryDosDeviceW(f"{letter}:", buf, len(buf)):
            out[f"{letter}:"] = buf.value.lower()
    for drive, dev in out.items():
        if dev.startswith("\\??\\") and dev[4:6].upper() in out:  # subst X: C:\folder
            out[drive] = out[dev[4:6].upper()] + dev[6:]
        m = re.match(r"\\device\\(?:lanmanredirector|mup)\\;[^\\]*(\\.*)$", dev)  # a mapped network drive
        if m:
            out[drive] = "\\device\\mup" + m.group(1)
    return out


def kernel_path(path, devices) -> str:
    r"""How the kernel names a folder, lower case with a backslash at the end: \device\harddiskvolume3\users\...;
    \\server\share is \device\mup\server\share. "" if its drive is unknown."""
    p = os.path.abspath(str(path)).rstrip("\\")
    if p.startswith("\\\\"):
        dev = "\\device\\mup" + p[1:]
    else:
        drive = devices.get(p[:2].upper())
        if not drive:
            return ""
        dev = drive + p[2:]
    return dev.lower() + "\\"


class FileTrace:
    """Listens to the kernel's file events and remembers which program wrote which file in the watched folders."""

    def __init__(self, session=SESSION):
        self.session = session
        self.roots = []          # [(kernel name of a watched folder, its norm() + backslash)]
        self.open = {}           # FileObject -> norm() path, for files opened in watched folders
        self.recent = collections.deque(maxlen=KEEP_MAX)  # (time.monotonic(), PID, norm() path) per write
        self.layouts = dict(_LAYOUTS)
        self.latest = 0          # time stamp of the newest event
        self.me = os.getpid()
        self.handle = self.trace = None
        self.thread = None
        self._callback = _CALLBACK(self._on_event)  # kept: Windows calls it as long as the session runs

    def watch(self, dirs):
        """Remember writes in these folders (and the folders in them)."""
        try:
            devices = _kernel_devices()
        except Exception:
            log.exception(tr("無法取得磁碟的核心名稱", "Could not get the kernel names of the drives"))
            return
        roots = []
        for d in dirs:
            k = kernel_path(d, devices)
            if k:
                roots.append((k, norm(d).rstrip("\\") + "\\"))
        self.roots = sorted(roots, key=lambda r: len(r[0]), reverse=True)  # the deepest first

    def _path(self, kernel_name):
        """norm() path of a file the kernel names, if it is in a watched folder; else None."""
        low = kernel_name.lower()
        for k, d in self.roots:
            if low.startswith(k):
                return d + low[len(k):]
        return None

    def start(self) -> bool:
        """Start listening (a session left by an earlier monitor is ended first). False if it can't."""
        adv = _api()
        stop_trace_session(self.session)
        handle = c_uint64()
        rc = adv.StartTraceW(ctypes.byref(handle), self.session, ctypes.byref(_properties().p))
        if rc:
            log.warning(tr("無法啟動檔案寫入追蹤（ETW，錯誤 %s）", "Could not start file write tracing (ETW, error %s)"), rc)
            return False
        self.handle = handle.value
        rc = adv.EnableTraceEx2(self.handle, ctypes.byref(_guid(KERNEL_FILE)), 1, 5, KEYWORDS, 0, 0, None)
        logfile = EVENT_TRACE_LOGFILEW(LoggerName=self.session, EventRecordCallback=self._callback,
                                       ProcessTraceMode=0x100 | 0x10000000)  # real time, EVENT_RECORD callback
        trace = adv.OpenTraceW(ctypes.byref(logfile)) if rc == 0 else 0
        if rc or trace in (0, 0xFFFFFFFFFFFFFFFF):
            log.warning(tr("無法啟動檔案寫入追蹤（ETW，錯誤 %s）", "Could not start file write tracing (ETW, error %s)"),
                        rc or ctypes.GetLastError())
            self.stop()
            return False
        self.trace = trace
        handles = (c_uint64 * 1)(trace)
        self.thread = threading.Thread(target=adv.ProcessTrace, args=(handles, 1, None, None), daemon=True)
        self.thread.start()
        return True

    def alive(self) -> bool:
        return self.thread is not None and self.thread.is_alive()

    def stop(self):
        adv = _api()
        if self.handle is not None:
            adv.ControlTraceW(self.handle, None, ctypes.byref(_properties().p), 1)  # stop: ProcessTrace returns
            self.handle = None
        if self.trace is not None:
            adv.CloseTrace(self.trace)
            self.trace = None

    def _on_event(self, addr):
        try:
            flags, pid, stamp, event, version, size, data = _HEADER.unpack(ctypes.string_at(addr, _HEADER.size))
            self.latest = stamp
            if flags & _32BIT_HEADER or not data:
                return
            key = (event, version)
            if key not in self.layouts:
                self.layouts[key] = _layout(addr)
            where = self.layouts[key]
            if where is None:
                return
            # A FileObject's address is used again once the file is closed, and Windows hands over the events of
            # each processor in batches of their own, not in time order: a write may arrive before the opening it
            # belongs to. Per process, at least another program's write is never taken for this one's file.
            obj = (pid, c_uint64.from_address(data + where[0]).value)
            if event == CREATE and where[1] is not None:
                name = ctypes.wstring_at(data + where[1], max(0, size - where[1]) // 2).split("\0", 1)[0]
                path = self._path(name)
                if path:
                    if len(self.open) >= OPEN_MAX:
                        self.open.clear()
                    self.open[obj] = path
                else:  # the same FileObject address now belongs to a file this doesn't follow
                    self.open.pop(obj, None)
            elif event == WRITE and pid not in (SYSTEM_PID, self.me):
                path = self.open.get(obj)
                if path and not (self.recent and self.recent[-1][1] == pid and self.recent[-1][2] == path):
                    self.recent.append((time.monotonic(), pid, path))
        except Exception:  # never let an exception reach Windows' event loop
            pass

    def flush(self, timeout=0.2):
        """Have Windows deliver the events it is holding (it does so every second otherwise) and wait a moment for
        them."""
        if self.handle is None:
            return
        _api().ControlTraceW(self.handle, None, ctypes.byref(_properties().p), 3)  # EVENT_TRACE_CONTROL_FLUSH
        now = c_int64()
        ctypes.windll.kernel32.QueryPerformanceCounter(ctypes.byref(now))
        end = time.monotonic() + timeout
        while self.latest < now.value and time.monotonic() < end:
            time.sleep(0.01)

    def culprits(self, evidence, wait=1.0) -> list:
        """[(PID, number of files)] of the programs that, in the last LOOKBACK_SEC seconds, wrote one of the evidence
        files or at least CULPRIT_MIN_FILES files in their folders (ransomware that renames a file may write it
        under its old name), most files first. The latest writes may still be on their way: waits up to `wait`
        seconds for someone to show up, and a moment more for the batches of other processors."""
        files = {norm(f) for f in evidence}
        if not files:
            return []
        start = time.monotonic()
        while True:
            self.flush()
            rows = self._rank(files)
            spent = time.monotonic() - start
            # someone found: still look until TRACE_SETTLE_SEC, an innocent program's events may have come first
            if (rows and spent >= TRACE_SETTLE_SEC) or spent >= wait or self.handle is None:
                return rows
            time.sleep(0.05)

    def _rank(self, files) -> list:
        folders = {os.path.dirname(f) for f in files}
        since = time.monotonic() - LOOKBACK_SEC
        wrote, direct = collections.defaultdict(set), set()
        for t, pid, path in list(self.recent):
            if t < since:
                continue
            if path in files:
                direct.add(pid)
                wrote[pid].add(path)
            elif os.path.dirname(path) in folders:
                wrote[pid].add(path)
        rows = [(pid, len(paths)) for pid, paths in wrote.items() if pid in direct or len(paths) >= CULPRIT_MIN_FILES]
        return sorted(rows, key=lambda r: r[1], reverse=True)
