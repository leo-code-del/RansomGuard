r"""The log (kept 30 days) and the state the parts running with administrator rights act on, kept in
C:\ProgramData\RansomGuard where only administrators can change it."""
import json
import logging
import os
import re
import shutil
import sys
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path

from . import config, winapi
from .config import log, tr
from .winapi import norm


LOG_KEEP_DAYS = 30  # the log names files and programs, which can be personal: older entries are removed


def setup_logging():
    log.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    prune_log(config.app_dir() / "guard.log")
    fh = RotatingFileHandler(config.app_dir() / "guard.log", maxBytes=1_000_000,
                             backupCount=3, encoding="utf-8")
    fh.setFormatter(fmt)
    log.addHandler(fh)
    if sys.stderr is not None:  # no console when run with pythonw
        sh = logging.StreamHandler()
        sh.setFormatter(fmt)
        log.addHandler(sh)


def _log_files(log_file: Path) -> list:
    """guard.log and the older parts RotatingFileHandler made of it (guard.log.1, .2, .3)."""
    return [log_file, *(log_file.with_name(f"{log_file.name}.{i}") for i in range(1, 4))]


def prune_log(log_file: Path, days=LOG_KEEP_DAYS):
    """Remove log entries older than `days`: whole older parts, and old lines at the start of guard.log.
    Done before this program opens the log; if another RansomGuard has it open, it is left for next time."""
    cutoff = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - days * 86400))
    for part in _log_files(log_file)[1:]:
        try:
            if part.stat().st_mtime < time.time() - days * 86400:
                part.unlink()
        except OSError:
            pass
    try:
        lines = log_file.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
    except OSError:
        return
    # an entry starts with its time ("2026-11-04 10:00:00,123 [INFO] ..."); the lines after it (a traceback)
    # belong to it. Entries are in time order, so keep everything from the first recent one on.
    start = next((i for i, line in enumerate(lines) if re.match(r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d", line)
                  and line[:19] >= cutoff), len(lines))
    if start == 0:
        return
    try:
        tmp = log_file.with_name(log_file.name + ".tmp")
        tmp.write_text("".join(lines[start:]), encoding="utf-8")
        os.replace(tmp, log_file)
    except OSError:
        pass


def prune_own_log():
    """prune_log() from a program that has the log open itself (the background monitor, daily): let go of
    the file first; the next log line reopens it."""
    for h in log.handlers:
        if isinstance(h, logging.FileHandler):
            h.acquire()
            try:
                if h.stream:
                    h.stream.close()
                    h.stream = None  # not h.close(): the handler stays usable and reopens on the next line
            finally:
                h.release()
    prune_log(config.app_dir() / "guard.log")


def clear_log() -> bool:
    """Empty the log and delete its older parts (the control panel's "Clear log"). The background monitor
    keeps it open but appends, so it simply goes on writing at the new end."""
    ok = True
    for i, part in enumerate(_log_files(config.app_dir() / "guard.log")):
        try:
            if i == 0:
                with open(part, "r+b") as f:
                    f.truncate(0)
            else:
                part.unlink(missing_ok=True)
        except FileNotFoundError:
            pass
        except OSError:
            ok = False
    return ok


# What the parts running with administrator rights act on - state.json (adapters and firewall settings to
# restore, programs to resume), the canary record, the watched folders, the "stopped by the user" flag -
# lives in a folder only administrators can change. In the user's app folder, any program running as the
# user could have made "Restore network" turn the firewall off, or stopped monitoring.
def state_dir() -> Path:
    """C:\\ProgramData\\RansomGuard (not created here: see secure_state_dir)."""
    return (Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "RansomGuard" if config.IS_WINDOWS else
            config.app_dir() / "state")


_state_secured = False
STATE_FILES = ("state.json", "canaries.json", "watch.json", "monitor_stopped", "detection_paused")


def _is_link(p: Path) -> bool:
    """A symbolic link or a directory junction (which Windows lets any user create)."""
    return p.is_symlink() or bool(getattr(p, "is_junction", lambda: False)())


def _remove_entry(p: Path):
    if _is_link(p):
        try:
            os.rmdir(p)  # a link to a folder: removes the link only, never what it points to
        except OSError:
            os.unlink(p)
    elif p.is_dir():
        shutil.rmtree(p)  # doesn't follow links inside either
    else:
        p.unlink()


def secure_state_dir():
    """Hand the state folder to administrators: owned by Administrators, full control for SYSTEM and
    Administrators, read-only for the user who runs RansomGuard (the health check reads state.json), nothing
    inherited from ProgramData (where every user may create files and folders). Someone could have created it
    first, so a link in its place and anything in it that isn't one of STATE_FILES is removed, and permissions
    are set on the folder and those files only (never recursively: that could follow a link elsewhere).
    Needs administrator rights; done once per run, by the parts that have them."""
    global _state_secured
    if _state_secured or not config.IS_WINDOWS:
        return
    d = state_dir()
    if os.path.lexists(d) and _is_link(d):
        _remove_entry(d)
    d.mkdir(parents=True, exist_ok=True)
    for entry in list(d.iterdir()):
        if entry.name not in STATE_FILES or _is_link(entry) or not entry.is_file():
            try:
                _remove_entry(entry)
            except OSError as ex:
                log.warning(tr("無法移除 %s：%s", "Could not remove %s: %s"), entry, ex)
    icacls, user = winapi.sys_exe("icacls.exe"), f"{os.environ.get('USERDOMAIN', '')}\\{os.environ.get('USERNAME', '')}"
    files = [str(d / n) for n in STATE_FILES if (d / n).is_file()]
    for path in [str(d), *files]:
        winapi._run([icacls, path, "/setowner", "*S-1-5-32-544", "/C", "/Q"])
    winapi._run([icacls, str(d), "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F",
                 f"{user}:(OI)(CI)RX", "/Q"])
    for path in files:  # they take the folder's permissions
        winapi._run([icacls, path, "/reset", "/C", "/Q"])
    _state_secured = True


def _read_state_json(path: Path):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


_FIREWALL_VALUES = {"Name": {"Domain", "Private", "Public"}, "Enabled": {"True", "False"},
                    "In": {"Block", "Allow", "NotConfigured"}, "Out": {"Block", "Allow", "NotConfigured"}}


def clean_state(st: dict) -> dict:
    """Only well-formed entries of a state file. Whatever wrote it, restoring can then only enable network
    adapters by name, put firewall profiles back to ordinary values and resume programs Defender finds clean."""
    out = {}
    if isinstance(st.get("triggered_at"), str):
        out["triggered_at"] = st["triggered_at"][:40]
    if isinstance(st.get("reminded"), (int, float)):
        out["reminded"] = st["reminded"]
    if isinstance(st.get("disabled_adapters"), list):
        out["disabled_adapters"] = [n for n in st["disabled_adapters"] if isinstance(n, str) and 0 < len(n) <= 256]
    if isinstance(st.get("firewall"), list):
        out["firewall"] = [{k: str(p[k]) for k in _FIREWALL_VALUES} for p in st["firewall"] if isinstance(p, dict)
                           and all(str(p.get(k)) in ok for k, ok in _FIREWALL_VALUES.items())]
    if isinstance(st.get("paused"), list):
        out["paused"] = [{"pid": p["pid"], "name": str(p.get("name", ""))[:260], "path": str(p.get("path", ""))[:1024],
                          "paused": bool(p.get("paused")), "result": str(p.get("result", ""))[:100]}
                         for p in st["paused"] if isinstance(p, dict) and isinstance(p.get("pid"), int)
                         and not isinstance(p.get("pid"), bool) and p["pid"] > 0]
    inc = st.get("incident")
    if isinstance(inc, dict) and isinstance(inc.get("reason"), str):
        files = inc.get("files") if isinstance(inc.get("files"), list) else []
        out["incident"] = {"reason": inc["reason"][:500],
                           "files": [f[:1024] for f in files if isinstance(f, str) and f][:50]}
    return out


def incident_lines(st: dict, limit=10) -> list:
    """The detection report of the last trigger, as lines of text: why, and the files that looked encrypted (up to
    `limit`), the programs that were paused. [] when there is none."""
    inc = st.get("incident")
    if not inc:
        return []
    lines = [tr(f"偵測原因：{inc['reason']}", f"Why: {inc['reason']}")]
    files = inc.get("files") or []
    if files:
        lines.append(tr(f"被判定像被加密的檔案（{len(files)} 個）：", f"Files that looked encrypted ({len(files)}):"))
        lines += [f"  {f}" for f in files[:limit]]
        if len(files) > limit:
            lines.append(tr(f"  ……還有 {len(files) - limit} 個（詳見紀錄檔）", f"  ...and {len(files) - limit} more (see the log)"))
    paused = [p for p in st.get("paused", []) if p.get("paused")]
    if paused:
        lines.append(tr("被暫停的程式：", "Programs paused: ") + ", ".join(f"{p['name']} (PID {p['pid']})" for p in paused))
    return lines


def load_state() -> dict:
    """The state, checked by clean_state(). A state file left in the user's app folder by versions before
    1.7.5 is moved over (once, after the same check)."""
    new, legacy = state_dir() / "state.json", config.app_dir() / "state.json"
    if not new.exists() and legacy.exists() and norm(new) != norm(legacy):
        st = clean_state(_read_state_json(legacy))
        try:
            save_state(st)
            legacy.unlink()
        except OSError:
            pass
        return st
    return clean_state(_read_state_json(new))


def save_state(st: dict):
    d = state_dir()
    d.mkdir(parents=True, exist_ok=True)
    (d / "state.json").write_text(json.dumps(st, ensure_ascii=False, indent=2), encoding="utf-8")


# The control panel can pause file detection for a while (bulk work: converting, renaming or encrypting many files
# on purpose). Only what such work sets off is paused - files that look encrypted, unknown extensions, ransom
# notes, encrypted copies; canary files and dangerous commands are watched as always. The end time lives in the
# administrators-only state folder, so a program running as the user can't pause detection.
PAUSE_MAX_MINUTES = 120


def _pause_file() -> Path:
    return state_dir() / "detection_paused"


def pause_detection(minutes: int) -> float:
    """Pause file detection for `minutes` (at most PAUSE_MAX_MINUTES); returns when it resumes."""
    until = time.time() + max(1, min(int(minutes), PAUSE_MAX_MINUTES)) * 60
    d = state_dir()
    d.mkdir(parents=True, exist_ok=True)
    _pause_file().write_text(str(until), encoding="utf-8")
    return until


def resume_detection():
    try:
        _pause_file().unlink(missing_ok=True)
    except OSError:
        pass


def detection_paused_until():
    """When paused file detection resumes (seconds since the epoch), or None if it isn't paused. A damaged file, a
    time already past or one further away than PAUSE_MAX_MINUTES (the clock was changed) counts as not paused."""
    try:
        until = float(_pause_file().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    now = time.time()
    return until if now < until <= now + PAUSE_MAX_MINUTES * 60 + 60 else None


def network_cut(st: dict) -> bool:
    return bool(st.get("triggered_at") or st.get("disabled_adapters") or st.get("firewall"))
