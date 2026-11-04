"""Whether the user's files are backed up: File History and OneDrive folder backup. Read only: no backup setting is
changed and nothing leaves the computer. RansomGuard stops ransomware; only a backup brings encrypted files back."""
import os
import time
from pathlib import Path

from . import config, winapi
from .config import log, tr
from .winapi import norm


FRESH_DAYS = 7     # a File History backup older than this needs attention
REMIND_DAYS = 14   # the background monitor reminds about a missing backup at most this often
ONEDRIVE_FOLDERS = ("Desktop", "Documents", "Pictures")  # the folders OneDrive folder backup can take over


def _file_history_registry_time():
    """When File History last finished a backup, as Windows records it (seconds since the epoch), or None."""
    if not config.IS_WINDOWS:
        return None
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\FileHistory") as k:
            value, kind = winreg.QueryValueEx(k, "ProtectedUpToTime")
    except (OSError, ImportError):
        return None
    if kind != getattr(winreg, "REG_QWORD", 11) or not isinstance(value, int) or value <= 0:
        return None
    return value / 10_000_000 - 11_644_473_600  # FILETIME (100 ns since 1601) -> epoch


def _file_history_folder() -> Path:
    return Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "Windows" / "FileHistory" / "Configuration"


def file_history():
    """(set up, time of the last backup or None). Without Windows' own record, the catalog File History rewrites
    after each backup tells the time."""
    folder = _file_history_folder()
    try:
        configured = any(folder.glob("Config*.xml"))
        catalogs = [p.stat().st_mtime for p in folder.glob("Catalog*.edb")]
    except OSError:
        configured, catalogs = False, []
    last = _file_history_registry_time()
    if last is None and catalogs:
        last = max(catalogs)
    if last is not None and last > time.time() + 86400:  # a clock gone wrong: don't trust it
        last = None
    return configured or last is not None, last


def onedrive_folders() -> list:
    """Which of Desktop, Documents and Pictures are kept in OneDrive (which keeps earlier versions of each file)."""
    roots = [norm(r) for r in (os.environ.get(v) for v in ("OneDrive", "OneDriveConsumer", "OneDriveCommercial"))
             if r and os.path.isdir(r)]
    covered = []
    for name in ONEDRIVE_FOLDERS:
        p = norm(winapi._known_folder(name))
        if any(p == r or p.startswith(r + os.sep) for r in roots):
            covered.append(name)
    return covered


def _days(seconds: float) -> str:
    days = int(max(0.0, seconds) // 86400)
    return tr("今天", "today") if days == 0 else tr(f"{days} 天前", f"{days} day ago" if days == 1 else f"{days} days ago")


def _names(folders) -> str:
    zh = {"Desktop": "桌面", "Documents": "文件", "Pictures": "圖片"}
    return tr("、".join(zh[f] for f in folders), ", ".join(folders))


def backup_status():
    """(text, light, note) for the control panel; light is ok / warn / bad."""
    if config.load_settings().get("other_backup") is True:
        return tr("其他方式", "Another way"), "ok", tr("你選擇用其他備份程式備份", "You back up with another program")
    configured, last = file_history()
    covered = onedrive_folders()
    if last is not None and time.time() - last < FRESH_DAYS * 86400:
        ago = _days(time.time() - last)
        return tr("檔案歷程記錄", "File History"), "ok", tr(f"上次備份：{ago}", f"Last backup: {ago}")
    if len(covered) == len(ONEDRIVE_FOLDERS):
        return "OneDrive", "ok", tr("雲端保留檔案的舊版本", "Keeps earlier versions")
    if configured:  # (the notes are short: they fit one line of the control panel)
        when = _days(time.time() - last) if last is not None else tr("不明", "unknown")
        return tr("太久沒備份", "Out of date"), "warn", tr(f"上次備份：{when}", f"Last backup: {when}")
    if covered:
        return tr("只有部分", "Partly"), "warn", tr(f"OneDrive 只有{_names(covered)}", f"OneDrive: {_names(covered)} only")
    return tr("找不到備份", "No backup found"), "bad", tr("檔案被加密就救不回來", "Encrypted files are lost")


def remind_if_needed(now=None) -> bool:
    """Background monitor, about once a day: if no up-to-date backup is found, say so - at most every REMIND_DAYS
    days, and never after the user chose "I back up with another program". Returns whether it reminded."""
    now = time.time() if now is None else now
    settings = config.load_settings()
    reminded = settings.get("backup_reminded")
    if isinstance(reminded, (int, float)) and not isinstance(reminded, bool) and 0 <= now - reminded < REMIND_DAYS * 86400:
        return False
    text, light, note = backup_status()
    if light == "ok":
        return False
    config.init_lang()  # the language most recently chosen in the control panel
    try:
        config.set_setting("backup_reminded", now)
    except OSError:
        return False  # without a record it would remind every day
    log.info(tr("提醒備份：%s（%s）", "Backup reminder: %s (%s)"), text, note)
    winapi.notice(tr("RansomGuard：備份提醒", "RansomGuard: backup reminder"),
                  tr(f"{text}：{note}。\n\nRansomGuard 能在勒索病毒發作時切斷網路，但沒辦法救回已經被加密的檔案，"
                     "只有備份可以。\n\n開啟 RansomGuard 控制台，按「備份…」看設定方式。"
                     f"\n（{REMIND_DAYS} 天後才會再提醒；在「備份…」選擇用其他備份程式，就不再提醒。）",
                     f"{text}: {note}.\n\nRansomGuard cuts the network when ransomware strikes, but it can't bring "
                     "encrypted files back. Only a backup can.\n\nOpen the RansomGuard control panel and click "
                     f"\"Backup…\" to see how to set one up.\n(The next reminder comes in {REMIND_DAYS} days at the "
                     "earliest; choose \"another backup program\" under \"Backup…\" to stop them.)"))
    return True
