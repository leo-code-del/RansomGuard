r"""Version, install locations, the settings you can tune, the interface language and the user's
settings (%LOCALAPPDATA%\RansomGuard\settings.json)."""
import ctypes
import json
import logging
import os
import sys
from pathlib import Path


VERSION = "1.15.1"  # bump this, add release-notes/v1.15.1.md and push the tag v1.15.1 to publish a release
IS_WINDOWS = os.name == "nt"
FROZEN = bool(getattr(sys, "frozen", False))  # running as an .exe packaged by PyInstaller
TASK_NAME = "RansomGuard"
INSTALL_DIR = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "RansomGuard"
INSTALL_EXE = INSTALL_DIR / "RansomGuard.exe"
UPDATE_API = "https://api.github.com/repos/leo-code-del/RansomGuard/releases/latest"
# the project folder and the script that starts the program, when running from source
ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "ransom_guard.py"

# =============== Settings you can tune ===============

WINDOW_SEC = 30              # counting window (seconds)
BROKEN_THRESHOLD = 8         # trigger when this many files "break" within the window
EXT_CHANGE_THRESHOLD = 10    # trigger when this many files get unknown extensions within the window
ENTROPY_LIMIT = 7.5          # max entropy for text files (bits/byte; encrypted data is ~7.9-8.0)
ENTROPY_MIN_SIZE = 4096      # skip the entropy check below this size (too little data to judge)
NOTE_DIR_THRESHOLD = 3       # trigger when ransom notes appear in this many folders within the window
PROCESS_MONITOR = True       # watch new processes and stop destructive commands (deleting restore points...)
CHECK_INTERVAL = 15          # seconds between periodic checks of canary files and monitor health
HIBERNATE_ON_TRIGGER = False  # True: hibernate right after cutting the network so encryption stops
PAUSE_ON_TRIGGER = True      # pause the programs that wrote the files (or write the most), and the one behind a command
FILE_TRACE = True           # follow which program writes which file (kernel file events), to know whom to pause
DEFENDER_SCAN_ON_TRIGGER = True  # have Microsoft Defender scan the paused programs and run a quick scan
DEFENDER_SCAN_DOWNLOADS = True   # have Defender scan new programs, scripts and archives in Downloads / on the Desktop

log = logging.getLogger("RansomGuard")
LANG = "zh"      # interface language: zh / en, set by init_lang()
_LANG_ARG = None  # language given with --lang on the command line


def tr(zh: str, en: str) -> str:
    """Return the Chinese or English text for the interface language."""
    return en if LANG == "en" else zh


def app_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") if IS_WINDOWS else None
    d = Path(base) / "RansomGuard" if base else Path.home() / ".ransom_guard"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _load_json(name: str) -> dict:
    """Read a JSON object from the app folder; a missing, damaged or non-object file counts as empty."""
    try:
        data = json.loads((app_dir() / name).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def load_settings() -> dict:
    return _load_json("settings.json")


def saved_lang():
    """Language chosen in the control panel; None if none (or an unknown one) was saved."""
    lang = load_settings().get("lang")
    return lang if lang in ("zh", "en") else None


def system_lang() -> str:
    """Chinese if the Windows display language is Chinese, English for any other language."""
    if IS_WINDOWS:
        try:
            return "zh" if ctypes.windll.kernel32.GetUserDefaultUILanguage() & 0x3FF == 0x04 else "en"
        except Exception:
            pass
    return "zh" if os.environ.get("LANG", "").lower().startswith("zh") else "en"


def init_lang(arg=None):
    """Interface language: --lang on the command line > language chosen in the control panel > Windows
    display language. Called again when the monitor triggers, to pick up a newly chosen language."""
    global LANG, _LANG_ARG
    if arg:
        _LANG_ARG = arg
    LANG = _LANG_ARG or saved_lang() or system_lang()


def set_setting(key: str, value):
    st = load_settings()
    st[key] = value
    (app_dir() / "settings.json").write_text(
        json.dumps(st, ensure_ascii=False, indent=2), encoding="utf-8")


def set_lang(lang: str):
    global LANG
    LANG = lang
    set_setting("lang", lang)


def auto_update_check() -> bool:
    """Whether RansomGuard may look for new versions on GitHub by itself. Off unless the user turned it on:
    every check shows GitHub this computer's IP address. Updating by clicking the button always works."""
    return load_settings().get("auto_update_check") is True
