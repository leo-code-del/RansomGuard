"""Which folders are watched: the user's own folders and the ones added in the control panel."""
import json
import os
from pathlib import Path

from . import storage, winapi
from .config import tr
from .winapi import norm


def default_watch_dirs():
    dirs = []
    for name in winapi._KNOWN_FOLDERS:
        p = winapi._known_folder(name)
        if p.is_dir() and norm(p) not in {norm(d) for d in dirs}:
            dirs.append(p)
    return dirs


# ---- folders the user added in the control panel (kept in the administrators-only state folder) ----
def watch_problem(path) -> str:
    """Why a folder can't be added to the watched folders ("" if it can). System folders and the whole system
    drive would bring constant changes (slow, false alarms); a folder under a default one is watched already."""
    p = norm(path)
    if not os.path.isdir(p):
        return tr("找不到這個資料夾", "This folder doesn't exist")
    system_drive = os.environ.get("SystemDrive", "C:") + "\\"
    if p == norm(system_drive):
        return tr("不能監控整個系統磁碟，請選擇裡面的資料夾", "The whole system drive can't be watched; choose a folder in it")
    for root in ("SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramData", "LOCALAPPDATA", "APPDATA"):
        r = os.environ.get(root)
        if r and (p == norm(r) or p.startswith(norm(r) + os.sep)):
            return tr("系統或程式資料夾變動太頻繁，不能監控", "System and program folders change too often to be watched")
    for d in default_watch_dirs():
        if p == norm(d) or p.startswith(norm(d) + os.sep):
            return tr("這個資料夾已經在監控中", "This folder is watched already")
    return ""


def extra_watch_dirs() -> list:
    """The folders the user added that exist and may be watched."""
    try:
        dirs = json.loads((storage.state_dir() / "watch.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return [Path(d) for d in dirs if isinstance(d, str) and not watch_problem(d)] if isinstance(dirs, list) else []


def save_extra_watch_dirs(dirs):
    d = storage.state_dir()
    d.mkdir(parents=True, exist_ok=True)
    (d / "watch.json").write_text(json.dumps([str(p) for p in dirs], ensure_ascii=False, indent=2), encoding="utf-8")
