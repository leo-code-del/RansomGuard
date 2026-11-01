<img src="icon.png" width="96" alt="">

# RansomGuard

**English** | [中文(繁體)](README.zh-TW.md)

Detects ransomware encryption behavior and **cuts off the network automatically** the moment something looks wrong, then shows a full-screen warning. This stops files from being encrypted further and keeps data from being sent out.

[![Download RansomGuard.exe](https://img.shields.io/badge/Download-RansomGuard.exe-2563eb?style=for-the-badge&logo=windows)](https://github.com/leo-code-del/RansomGuard/releases/latest/download/RansomGuard.exe)

[All versions and release notes](https://github.com/leo-code-del/RansomGuard/releases)

> The interface is available in English and 中文(繁體) (Traditional Chinese). The first time you open it, you choose the language (English or 中文(繁體)). Switch it any time with the **English / 中文(繁體)** button in the top-right corner of the control panel; the background monitor's warnings use the same language.

## Install

1. Download `RansomGuard.exe` with the button above (Windows 10 / 11 only).
2. Double-click it. When User Account Control asks, click **Yes**. Administrator rights are needed to cut the network.
   - If you see "Windows protected your PC", click **More info** → **Run anyway**. This appears because the program is not digitally signed.
3. In the control panel, click **Install / update and start monitoring**.

The program copies itself to `C:\Program Files\RansomGuard` and starts in the background every time you sign in to Windows. A "RansomGuard" shortcut on the desktop opens the control panel.

### If Windows Defender removes it

Defender sometimes reports RansomGuard.exe as a threat (for example `Trojan:Win32/Bearfoos!ml`). The `!ml` means a machine-learning guess, not a known virus: programs packaged with PyInstaller that need administrator rights, stop processes and disable network adapters look suspicious to it. When that happens Defender also deletes the installed copy and its scheduled task, so **protection stops without any message**. Check now and then that the control panel shows "Running".

1. Compare the file's SHA-256 with the one shown under Assets on the [release page](https://github.com/leo-code-del/RansomGuard/releases) (PowerShell: `Get-FileHash RansomGuard.exe`). Only continue if they match.
2. Windows Security → Virus & threat protection → Protection history → select the item → **Restore** (or **Allow on device**).
3. Run RansomGuard.exe again and click **Install / update and start monitoring**.
4. Please report the false positive to Microsoft at <https://www.microsoft.com/wdsi/filesubmission> (choose "Incorrectly detected"), which clears it for everyone.

## What it detects

Any one of these triggers it:

| Detection | Details |
| --- | --- |
| Canary files | A few files such as `!!!_canary_do_not_delete.docx` are placed in Documents and Pictures. Modifying, moving or deleting them triggers it |
| Broken files | Within a short time, several .docx / .pdf / .jpg / .mp4 files get corrupted headers, or text files turn into what looks like encrypted data |
| Unknown extensions | Many files renamed within a short time, e.g. `report.docx` → `report.docx.locked` |
| Ransom notes | Files such as `HOW_TO_DECRYPT.txt` appear in several folders within a short time |
| Dangerous commands | A program deletes restore points, disables boot recovery, deletes backups, clears event logs or turns off Defender (that program is terminated immediately) |

Watched folders: Desktop, Documents, Pictures, Downloads, Videos, Music.

> Do not open, move or delete the canary files (names containing `canary_do_not_delete`). Doing so cuts the network.

## When it triggers

1. All network adapters are disabled (the firewall is used as a fallback), and a red warning covers every screen.
2. **Do not restore the network**, and do not plug in backup drives or USB sticks.
3. If files are still being renamed or becoming unreadable one by one, hold the power button to force the computer off immediately.
4. Take a photo of the ransom note with your phone, and use your phone to change the passwords of important accounts such as email and banking.

**If it was a false alarm** (e.g. you touched a canary file yourself): open "RansomGuard" on the desktop and click **Restore network and restart monitoring**.

## Update

RansomGuard tells you when a new version is out: the background monitor checks GitHub two minutes after you sign in and then every 6 hours, and the control panel checks when it opens. Answer **Yes** and it updates by itself (each version is asked about once per sign-in).

To update by hand, open "RansomGuard" on the desktop and click **Install / update and start monitoring**. It checks GitHub for a newer release, downloads it, verifies it against the SHA-256 that GitHub publishes, installs it and reopens the control panel with the new version. Without an internet connection it simply reinstalls the current version. The current version number is shown in the top-left corner of the control panel.

> Versions before 1.4.0 can't update themselves: download the new `RansomGuard.exe` from [Releases](https://github.com/leo-code-del/RansomGuard/releases) once, run it and click **Install / update and start monitoring**.

## Control panel

| Button | What it does |
| --- | --- |
| Install / update and start monitoring | Updates to the latest release from GitHub, installs background monitoring and starts it |
| Restore network and restart monitoring | Restores the network after a false alarm |
| Stop monitoring | Stops it for now; it starts again at next sign-in |
| Preview warning | Shows what the warning looks like, without cutting the network |
| Open log | Log file: `%LOCALAPPDATA%\RansomGuard\guard.log` |
| Uninstall | Removes background monitoring, the desktop shortcut and the canary files |
| English / 中文(繁體) (top right) | Switches the interface language |

## Command-line options

```
RansomGuard.exe              Open the control panel
RansomGuard.exe --install    Install / update background monitoring
RansomGuard.exe --update     Open the control panel and update to the latest version
RansomGuard.exe --restore    Restore the network and restart background monitoring
RansomGuard.exe --dry-run    Test mode: log and show alerts only, never cut the network
RansomGuard.exe --test-alert Preview the full-screen warning
RansomGuard.exe --watch D:\Data --watch E:\Backup   Watch custom folders
RansomGuard.exe --version    Show the version
RansomGuard.exe --lang en    Use English for this run (zh = 中文(繁體))
```

## Run from source and build

```
pip install watchdog pyinstaller
python ransom_guard.py --gui
python -m PyInstaller --onefile --windowed --uac-admin --name RansomGuard --icon ..\icon.ico ^
       --distpath dist --workpath build --specpath build ransom_guard.py
```

Run the tests (they only use temporary folders and never touch the network or the installed program):

```
python -m unittest discover -s tests -v
```

The icon (`icon.ico` / `icon.png`) is generated by `make_icon.py` (needs `pip install pillow`). To change the icon, edit that file and run it again.

To run with Python instead of the exe, the project includes a few helper files (keep them in the same folder as `ransom_guard.py`):

| File | What it does |
| --- | --- |
| `install_ransom_guard.bat` | Installs background monitoring using Python (finds Python and installs watchdog) |
| `restore_network.bat` | Restores a cut-off network, no Python needed |
| `preview_warning.bat` | Previews the full-screen warning |

The built file is `dist\RansomGuard.exe`.

### Publishing a new version

1. Change `VERSION` in `ransom_guard.py`, e.g. to `"1.4.3"`.
2. Run the tests, rebuild, commit and push.
3. Create a release with the exe attached:

   ```
   gh release create v1.4.3 dist\RansomGuard.exe --title "RansomGuard 1.4.3" --notes-file notes.md
   ```

4. Only the newest version is offered for download. Remove the exe from the previous release and put a notice at the top of its notes (the notes stay readable):

   ```
   gh release delete-asset v1.4.2 RansomGuard.exe --yes
   ```

The download button in the README always points to the latest version, so it never needs editing.

## Note

RansomGuard is an extra line of defense. It does not replace antivirus software or **offline backups**. Back up important files regularly to a drive that is not normally connected to the computer.
