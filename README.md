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
3. In the control panel, click **Install and start monitoring**.

The program copies itself to `C:\Program Files\RansomGuard` and starts in the background every time you sign in to Windows. A "RansomGuard" shortcut on the desktop opens the control panel.

### Verify the download

From v1.7.1 on, every `RansomGuard.exe` is built by [GitHub Actions](.github/workflows/release.yml) from the tagged source code, not on anyone's own computer, and GitHub signs a *build provenance attestation* for it: a record of which repository, workflow and commit produced exactly this file. You can check it before running the exe:

1. Install the [GitHub CLI](https://cli.github.com/) and sign in once with `gh auth login`.
2. In the folder with the downloaded file, run:

   ```
   gh attestation verify RansomGuard.exe --repo leo-code-del/RansomGuard
   ```

   To also require that it came from the release workflow (not from any other workflow in the repository):

   ```
   gh attestation verify RansomGuard.exe --repo leo-code-del/RansomGuard --signer-workflow leo-code-del/RansomGuard/.github/workflows/release.yml
   ```

3. "Verification succeeded" means the file is byte for byte what the workflow built. If it fails, don't run the file.

Releases are also immutable: once published, their files can't be replaced. To check that a file is the one attached to a release, run `gh release verify-asset v1.7.1 RansomGuard.exe --repo leo-code-del/RansomGuard` (use the version you downloaded).

Without the GitHub CLI, compare the SHA-256 shown under Assets on the [release page](https://github.com/leo-code-del/RansomGuard/releases) with PowerShell's `Get-FileHash RansomGuard.exe`.

Versions before 1.7.1 were built on the developer's computer and have no attestation.

### If Windows Defender removes it

Defender sometimes reports RansomGuard.exe as a threat (for example `Trojan:Win32/Bearfoos!ml`). The `!ml` means a machine-learning guess, not a known virus: programs packaged with PyInstaller that need administrator rights, stop processes and disable network adapters look suspicious to it. When that happens Defender also deletes the installed copy and its scheduled task, and protection stops. Since 1.7.0 a separate health check notices this: five minutes after you sign in and every day at noon it shows a message if protection is gone or monitoring is not running, and offers to open the download page or the control panel. It runs without opening a window and doesn't need RansomGuard.exe. Versions before 1.7.0 give no message, so check now and then that the control panel shows "Running".

1. Compare the file's SHA-256 with the one shown under Assets on the [release page](https://github.com/leo-code-del/RansomGuard/releases) (PowerShell: `Get-FileHash RansomGuard.exe`). Only continue if they match.
2. Windows Security → Virus & threat protection → Protection history → select the item → **Restore** (or **Allow on device**).
3. Run RansomGuard.exe again and click **Install and start monitoring**.
4. Please report the false positive to Microsoft at <https://www.microsoft.com/wdsi/filesubmission> (choose "Incorrectly detected"), which clears it for everyone.

## What it detects

Any one of these triggers it:

| Detection | Details |
| --- | --- |
| Canary files | A few files such as `!!!_canary_do_not_delete.docx` are placed in Documents and Pictures. Modifying, moving or deleting them triggers it |
| Broken files | Within a short time, several .docx / .pdf / .jpg / .mp4 files get corrupted headers, or text files turn into what looks like encrypted data |
| Unknown extensions | Many files renamed within a short time, e.g. `report.docx` → `report.docx.locked` |
| Ransom notes | Files such as `HOW_TO_DECRYPT.txt` appear in several folders within a short time |
| Dangerous commands | A program deletes restore points, disables boot recovery, deletes backups, clears event logs or turns off Defender. That command is terminated immediately, and the program that started it is paused, because ransomware usually does this just before it starts encrypting |

Watched folders: Desktop, Documents, Pictures, Downloads, Videos, Music.

New programs, scripts and archives (`.exe`, `.msi`, `.js`, `.zip`...) in Downloads or directly on the Desktop are also scanned with Microsoft Defender once they finish downloading. If Defender finds a threat, a message tells you. This does not cut the network, because Defender removes the file.

> Do not modify, move or delete the canary files (names containing `canary_do_not_delete`). Doing so cuts the network. Opening one in Word or Excel shows a notice explaining this. Close it without saving; Word and Excel suggest opening it read-only.

## When it triggers

1. The programs writing the most data (and the program behind a dangerous command) are paused, which stops the encryption, and Microsoft Defender scans them. Windows' own processes, Defender and the desktop are never paused. Then all network adapters are disabled (the firewall is used as a fallback), and a red warning covers every screen that names the paused programs.
2. **Do not restore the network**, and do not plug in backup drives or USB sticks.
3. If files are still being renamed or becoming unreadable one by one, hold the power button to force the computer off immediately.
4. Take a photo of the ransom note with your phone, and use your phone to change the passwords of important accounts such as email and banking.

**If it was a false alarm** (e.g. you touched a canary file yourself): open "RansomGuard" on the desktop and click **Restore network and restart monitoring**. Paused programs are scanned by Defender again and resumed if it finds nothing. A program that stays paused ends when you restart the computer.

## What it does to your computer

This section lists everything RansomGuard changes, so you can decide whether you trust it. What it records about you, how long, and how to delete it is in the [privacy page](PRIVACY.md).

**Permissions.** RansomGuard.exe asks for administrator rights (User Account Control) when it starts. The background monitor runs with administrator rights through a scheduled task that starts at every sign-in. The health check runs with normal user rights.

**Files it reads.** It reads files that change in Desktop, Documents, Pictures, Downloads, Videos and Music. For common formats (Office files, PDF, pictures, videos, text files) it reads only the first 16 KB, to check whether the file looks encrypted. OneDrive files that are not downloaded yet are skipped. It does not read other drives or network drives, unless you add them with `--watch`.

**Programs it watches.** It reads the command line of every program that starts, to spot the dangerous commands listed above. Only those are written to the log. When it triggers, it also reads how much each running program has written.

**Files and settings it creates or changes.**

| Where | What |
| --- | --- |
| Documents and Pictures (or the folders given with `--watch`) | Three canary files in each (`!!!_canary_do_not_delete.docx` and similar) |
| `%LOCALAPPDATA%\RansomGuard\` | `guard.log` (at most 4 files of 1 MB, entries older than 30 days removed), `state.json` (what was cut off or paused), `settings.json` (language, automatic update checks) |
| `C:\Program Files\RansomGuard\` | `RansomGuard.exe`, `icon.ico`, `health_check.js` |
| `%TEMP%` | A `_MEI…` folder the exe unpacks itself into while it runs, removed when it exits. `MpCmdRun.log`, the log Microsoft Defender's scanner keeps of the scans RansomGuard asks for |
| Desktop | The "RansomGuard" shortcut |
| Task Scheduler | The scheduled tasks "RansomGuard" and "RansomGuard Health Check" |
| Windows' icon cache | Refreshed when installing, so the shortcut shows the current icon |

**What it deletes.** It never deletes your own files, with two exceptions listed under [Things that can go wrong](#known-limitations-and-risks): a file of yours named exactly like a canary file, and anything you put into `C:\Program Files\RansomGuard`. Otherwise it deletes only what it created: its canary files (when the network is restored and on uninstall), files left by older versions, log entries older than 30 days, the log when you click **Clear log**, and on uninstall the desktop shortcut, both scheduled tasks, the `C:\Program Files\RansomGuard` folder and its own log and settings in `%LOCALAPPDATA%\RansomGuard`.

**Programs and the network.**

| When | What it does |
| --- | --- |
| A program runs a dangerous command (deleting restore points, turning off Defender...) | Ends that program and pauses the programs that started it (up to three levels) |
| Possible ransomware is detected | Pauses the programs writing the most data (up to five), asks Microsoft Defender to scan the paused programs and run a quick scan, disables every network adapter (if that fails: blocks all traffic in the firewall, releases the IP address and disconnects Wi-Fi), shows the full-screen warning |
| A new program, script or archive appears in Downloads or on the Desktop | Asks Microsoft Defender to scan it once it is complete, and tells you if Defender finds a threat |
| While the warning is open | Disables any network adapter that gets turned on again |
| You restore the network | Turns the network adapters back on, puts the firewall settings back, and resumes paused programs that Defender finds clean |
| You click "Force shut down now" on the warning | Shuts the computer down, after asking you to confirm |

**Internet connections.** By default RansomGuard doesn't connect to the internet by itself. Only the exe ever connects, and only to GitHub: when you click **Update to the latest version** (or run it with `--update` or `--install`), or every 6 hours and when the control panel opens if you turn on **Check for updates automatically** (off by default, because every check shows GitHub your IP address). It downloads a new version from `github.com` only after you agree, and checks the file's SHA-256 before installing it. No information about you or your files is sent anywhere. The Python version never connects to the internet. Microsoft Defender scans run on your computer; whether Defender itself contacts Microsoft depends on your Defender settings.

## Update

To be told when a new version is out, tick **Check for updates automatically** at the bottom left of the control panel. The background monitor then checks GitHub two minutes after you sign in and every 6 hours, and the control panel checks when it opens. Answer **Yes** and it updates by itself (each version is asked about once per sign-in). It is off by default, because each check shows GitHub your IP address (see [Privacy](PRIVACY.md)); versions before 1.7.3 always checked.

To update by hand, open "RansomGuard" on the desktop and click **Update to the latest version** (with automatic update checks on, it reads **Update to v…** and turns blue when the control panel has found a newer version). It checks GitHub for a newer release, downloads it, verifies it against the SHA-256 that GitHub publishes, installs it and reopens the control panel with the new version. Without an internet connection it simply reinstalls the current version. The current version number is shown in the top-left corner of the control panel.

**You don't have to update.** Answer **No** when asked, and monitoring continues with the version you have. **Install and start monitoring** never contacts GitHub: it installs the version that is running and starts monitoring with it. You can update whenever you like.

> Versions before 1.4.0 can't update themselves: download the new `RansomGuard.exe` from [Releases](https://github.com/leo-code-del/RansomGuard/releases) once, run it and click **Install and start monitoring**.

## Control panel

| Button | What it does |
| --- | --- |
| Install and start monitoring | Installs background monitoring with the version that is running and starts it, without contacting GitHub |
| Update to the latest version | Updates to the latest release from GitHub, installs it and starts monitoring |
| Restore network and restart monitoring | Restores the network after a false alarm |
| Stop monitoring | Stops it for now; it starts again at next sign-in |
| Preview warning | Shows what the warning looks like, without cutting the network |
| Open log | Log file: `%LOCALAPPDATA%\RansomGuard\guard.log` (entries older than 30 days are removed) |
| Check for updates automatically (bottom left) | Off by default. When on, RansomGuard asks GitHub for new versions every 6 hours and when the control panel opens |
| Clear log | Empties the log, which lists the files and programs that were detected |
| Uninstall | Removes background monitoring, the health check, the desktop shortcut, the canary files, the `C:\Program Files\RansomGuard` folder and the log and settings |
| English / 中文(繁體) (top right) | Switches the interface language |

## Command-line options

```
RansomGuard.exe              Open the control panel
RansomGuard.exe --install    Install background monitoring (updating first if there is a newer release)
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
pip install -r requirements-build.txt
python ransom_guard.py --gui
build.bat
```

`requirements.txt` lists what running from source needs; `requirements-build.txt` adds the exact PyInstaller version used for releases.

`build.bat` packs `icon.ico` into the exe. Without it, the window, taskbar and desktop shortcut show PyInstaller's default icon. It then runs `check_build.py`, which fails the build if the exe lacks the Tcl/Tk files the control panel needs: PyInstaller only warns about that, and such an exe doesn't start at all (that happened to v1.7.1, built with Python 3.14.9, whose Tcl/Tk 9 files PyInstaller 6.21 can't pack; releases use Python 3.14.6). To use a Python that is not on PATH, set `PYTHON` first, e.g. `set PYTHON=C:\Python314\python.exe`.

Run the tests (Python's built-in `unittest`; `pytest` runs them too):

```
python -m unittest discover -s tests -v
```

The tests only use temporary folders and never touch your files, the network settings, the internet or the installed program. This is enforced for the whole suite: user folders, the app folder and the install folder point into a temporary sandbox, and a test that reaches the PowerShell commands for network adapters, the firewall or scheduled tasks, `ipconfig` / `netsh` / shutdown, the internet or the full-screen warning without replacing it fails instead. Only processes the tests started themselves can be paused. Some tests use read-only Windows features for real: watching new processes through WMI, Defender scans of temporary files, and reading scheduled tasks.

The icon (`icon.ico` / `icon.png`) is generated by `make_icon.py` (needs `pip install pillow`). To change the icon, edit that file and run it again.

To run with Python instead of the exe, the project includes a few helper files (keep them in the same folder as `ransom_guard.py`):

| File | What it does |
| --- | --- |
| `install_ransom_guard.bat` | Installs background monitoring using Python (finds Python and installs watchdog) |
| `restore_network.bat` | Restores a cut-off network, no Python needed |
| `preview_warning.bat` | Previews the full-screen warning |

The built file is `dist\RansomGuard.exe`.

### Publishing a new version

Releases are built and published by GitHub Actions, never uploaded by hand:

1. Change `VERSION` in `ransom_guard.py`, e.g. to `"1.7.2"`, and write the release notes in `release-notes/v1.7.2.md`.
2. Run the tests, commit and push. The [CI workflow](.github/workflows/ci.yml) runs the checks, the tests and a build on every push to a branch and every pull request.
3. Tag the commit and push the tag:

   ```
   git tag v1.7.2
   git push origin v1.7.2
   ```

4. The [release workflow](.github/workflows/release.yml) checks that the tag matches `VERSION`, runs the tests, builds the exe, signs its attestation, publishes the release (as a draft first, so the exe is attached before the release becomes immutable) and adds a "please update" notice to the previous release's notes.

Releases from v1.7.0 on are immutable: once published, their files and tags can't be changed, so a mistake means a new version number, and their exe stays downloadable. The download button in the README always points to the latest version, so it never needs editing.

## How it is developed

RansomGuard is developed mainly with [Claude Code](https://claude.com/claude-code), an AI coding assistant made by Anthropic. The repository owner reviews the changes, decides what goes into each release and tries new versions on their own computers. Every change is checked by the automated tests in `tests/`. Code written with AI help can still contain mistakes, so please report anything that looks wrong in [Issues](https://github.com/leo-code-del/RansomGuard/issues).

## Known limitations and risks

RansomGuard is an extra line of defense, not your only one. Keep using antivirus software (such as Microsoft Defender), install Windows updates, and back up important files regularly to a drive that is **not normally connected** to the computer. A backup drive that is always plugged in can be encrypted too.

**What it can't do**

- It is not antivirus software. It doesn't recognize malware; it only reacts to behavior that looks like encryption.
- It watches only Desktop, Documents, Pictures, Downloads, Videos and Music. Files on other drives, network drives and cloud folders outside these are not protected, unless you add them with `--watch`.
- Some files are lost before it reacts. It triggers after about 8 to 10 files look encrypted within 30 seconds (or when a canary file is touched), and Windows reports file changes with a delay of about one second.
- Ransomware that encrypts slowly enough to stay under these thresholds is caught only if it touches a canary file. So is ransomware that keeps each file's name and leaves its first bytes intact.
- Ransomware that deletes restore points through Windows programming interfaces, instead of running commands such as `vssadmin`, is not caught by the dangerous-command check.
- Programs that write through memory-mapped files don't show up in the write counts, so they may not be found to be paused.
- Ransomware that already has administrator rights can stop RansomGuard or delete its scheduled task. The health check tells you within a day.
- After it triggers and you close the warning, monitoring stays off until you restore the network or sign in to Windows again. If you sign in again before restoring the network, it reminds you that the network was cut and starts monitoring again.
- It has been tested with automated tests and simulated ransomware (files encrypted and renamed by a test script), never with real ransomware.
- Windows 10 and 11 only, and it needs administrator rights.

**Things that can go wrong**

- **False alarms cut the network.** This happens if you touch a canary file, if a program renames 10 or more files to an unusual extension within 30 seconds, or if files named like ransom notes (e.g. `how to recover files.txt`) appear in three folders.
- **Legitimate maintenance is stopped.** Backup software or an administrator running `wbadmin delete backup`, `vssadmin delete shadows` or `wevtutil cl` is treated as ransomware: the command is ended and the network is cut.
- **Normal programs can be paused by a false alarm.** Editors, browsers and OneDrive write all the time and may be paused (and freeze) until you restore the network from the control panel. If you restore with `restore_network.bat` instead, they stay paused until the computer restarts.
- **You won't hear about new versions unless you ask.** Automatic update checks are off by default for privacy, so improvements and fixes reach you only if you click **Update to the latest version** now and then, or turn on **Check for updates automatically**.
- **Uninstalling deletes the whole `C:\Program Files\RansomGuard` folder**, including any files you put there yourself.
- A file of your own named exactly like a canary file (e.g. `!!!_canary_do_not_delete.docx`) in Documents or Pictures is replaced by the canary file.

**Known security issues** (removed from this list once fixed)

- **Running from Python source can give malware administrator rights.** `install_ransom_guard.bat` and `ransom_guard.py --install` make the scheduled task run `ransom_guard.py` from the folder it is in, with administrator rights. If that folder can be changed without administrator rights (for example a folder on D: or in your user folder), any program running as you could change the script and get administrator rights at your next sign-in. The exe doesn't have this problem: it copies itself to `C:\Program Files\RansomGuard`, which only administrators can change. If you run from source, keep the project in a folder only administrators can change.
- **Settings in your user folder steer actions taken with administrator rights.** `state.json` lives in `%LOCALAPPDATA%\RansomGuard`, which any program running as you can change. When you restore the network, the firewall settings saved there are put back with administrator rights, so a malicious program could use it to turn the firewall off at that moment. It could also make the health check stay quiet about stopped monitoring.
- **Updates are checked only against GitHub.** The SHA-256 that an update is checked against comes from GitHub too, so it protects against damaged downloads but not against a compromised GitHub account. The built-in updater doesn't check the attestation either; you can check it yourself (see [Verify the download](#verify-the-download)). The exe is not code-signed, which is also why SmartScreen and Defender sometimes distrust it.
