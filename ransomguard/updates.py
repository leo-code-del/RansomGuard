"""Looking for, downloading and verifying new versions on GitHub, and offering them."""
import ctypes
import hashlib
import json
import re
import urllib.request  # imported up front: the update must not depend on loading modules later

from . import config, install
from .config import log, tr


def version_tuple(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3])


def latest_release():
    """(version, RansomGuard.exe asset or None) of the newest release on GitHub."""
    req = urllib.request.Request(config.UPDATE_API, headers={"User-Agent": "RansomGuard",
                                                      "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        rel = json.load(r)
    return rel["tag_name"].lstrip("v"), next((a for a in rel["assets"] if a["name"] == "RansomGuard.exe"), None)


def check_for_update():
    """The newer version on GitHub, or None (up to date, not the packaged exe, or GitHub unreachable)."""
    if not config.FROZEN:
        return None
    try:
        latest, asset = latest_release()
    except Exception as ex:
        log.info(tr("無法檢查更新：%s", "Could not check for updates: %s"), ex)
        return None
    return latest if asset is not None and version_tuple(latest) > version_tuple(config.VERSION) else None


def check_updates(report):
    """The control panel's "Check for updates" button: ask GitHub (the user clicked, so contacting it is
    expected) and say what it found. Returns the newer version, or None; updating is offered separately."""
    report(tr("檢查新版本...", "Checking for a new version..."))
    if not config.FROZEN:
        report(tr("從原始碼執行時，請用 git pull 更新程式碼。", "Running from source: update the code with git pull."))
        return None
    try:
        latest, asset = latest_release()
    except Exception as ex:
        report(tr(f"[失敗] 無法連到 GitHub：{ex}", f"[Failed] Could not reach GitHub: {ex}"))
        return None
    if asset is not None and version_tuple(latest) > version_tuple(config.VERSION):
        report(tr(f"有新版本 v{latest}（目前是 v{config.VERSION}）。", f"Version {latest} is available (you have v{config.VERSION})."))
        return latest
    report(tr(f"已經是最新版本（v{config.VERSION}）。", f"You have the latest version (v{config.VERSION})."))
    return None


def fetch_update(report):
    """If GitHub has a newer release, download it, check its SHA-256 against the one GitHub publishes
    and install it as INSTALL_EXE. Returns the new version, or None (already latest / check failed)."""
    report(tr("檢查新版本...", "Checking for a new version..."))
    try:
        latest, asset = latest_release()
        if version_tuple(latest) <= version_tuple(config.VERSION):
            report(tr(f"  已經是最新版本（v{config.VERSION}）", f"  Already the latest version (v{config.VERSION})"))
            return None
        if asset is None:
            raise RuntimeError(tr("新版本沒有附上 RansomGuard.exe", "the new release has no RansomGuard.exe"))
        algo, _, want = (asset.get("digest") or "").partition(":")
        url = asset["browser_download_url"]
        if algo != "sha256" or not want or not url.startswith("https://github.com/"):
            raise RuntimeError(tr("GitHub 沒有提供可核對的 SHA-256", "GitHub gave no SHA-256 to check the file against"))
        report(tr(f"下載 v{latest}（{asset['size'] / 1048576:.1f} MB）...",
                  f"Downloading v{latest} ({asset['size'] / 1048576:.1f} MB)..."))
        # kept in memory until verified, so nothing can swap a temp file between the check and the install
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "RansomGuard"}),
                                    timeout=120) as r:
            data = r.read()
        if hashlib.sha256(data).hexdigest() != want.lower():
            raise RuntimeError(tr("下載的檔案和 GitHub 公布的 SHA-256 不符", "the download doesn't match GitHub's SHA-256"))
    except Exception as ex:
        log.warning(tr("無法更新：%s", "Could not update: %s"), ex)
        report(tr(f"  無法更新：{ex}（改為安裝目前這個版本）", f"  Could not update: {ex} (installing this version instead)"))
        return None
    install.replace_install_exe(lambda: config.INSTALL_EXE.write_bytes(data))
    log.info(tr("已從 GitHub 更新到 v%s", "Updated from GitHub to v%s"), latest)
    report(tr(f"  已更新到 v{latest}", f"  Updated to v{latest}"))
    return latest


UPDATE_CHECK_DELAY = 120           # first update check this many seconds after the monitor starts
UPDATE_CHECK_INTERVAL = 6 * 3600   # then check again this often


def ask_update(new: str) -> bool:
    """Ask whether to update now (a topmost Yes/No box)."""
    text = tr(f"RansomGuard v{new} 已推出（目前是 v{config.VERSION}）。\n\n要現在更新嗎？控制台會開啟並自動完成更新。",
              f"RansomGuard v{new} is available (you have v{config.VERSION}).\n\n"
              "Update now? The control panel will open and update automatically.")
    # MB_YESNO | MB_ICONINFORMATION | MB_SETFOREGROUND | MB_TOPMOST; IDYES = 6
    return ctypes.windll.user32.MessageBoxW(None, text, "RansomGuard", 0x4 | 0x40 | 0x10000 | 0x40000) == 6


def update_watcher(stop):
    """Background monitor: whenever GitHub has a newer release, ask the user to update
    (each version once per sign-in) and, on Yes, open the control panel to do it.
    Only while automatic update checks are turned on (read again each time, so switching applies at once)."""
    asked = set()
    if stop.wait(UPDATE_CHECK_DELAY):
        return
    while True:
        new = check_for_update() if config.auto_update_check() else None
        if new and new not in asked:
            asked.add(new)
            config.init_lang()
            log.info(tr("有新版本 v%s，詢問是否更新", "Version %s is available; asking whether to update"), new)
            if ask_update(new):
                try:
                    install.spawn_installed("--update")
                except OSError as ex:
                    log.error(tr("無法開啟控制台更新：%s", "Could not open the control panel to update: %s"), ex)
        if stop.wait(UPDATE_CHECK_INTERVAL):
            return
