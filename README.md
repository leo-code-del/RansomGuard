<div align="center">

<img src="icon.png" width="96" alt="RansomGuard icon">

# RansomGuard

**English** | [中文(繁體)](README.zh-TW.md)

Detects ransomware as it starts encrypting your files, **cuts off the network automatically** and shows a full-screen warning,<br>
so files stop being encrypted and your data isn't sent out.

[![Download RansomGuard.exe](https://img.shields.io/badge/Download-RansomGuard.exe-2563eb?style=for-the-badge&logo=windows)](https://github.com/leo-code-del/RansomGuard/releases/latest/download/RansomGuard.exe)

[![CI](https://github.com/leo-code-del/RansomGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/leo-code-del/RansomGuard/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/leo-code-del/RansomGuard)](https://github.com/leo-code-del/RansomGuard/releases/latest)

Windows 10 / 11 · English and 中文(繁體) · [All versions](https://github.com/leo-code-del/RansomGuard/releases) · [Privacy](PRIVACY.md) · [Code signing policy](#code-signing-policy) · [MIT License](LICENSE)

</div>

> [!IMPORTANT]
> RansomGuard is an extra line of defense, not your only one. Keep using antivirus software and keep [offline backups](#known-limitations-and-risks).

## Contents

- [Install](#install)
- [What it detects](#what-it-detects)
- [When it triggers](#when-it-triggers)
- [Control panel](#control-panel)
- [Updates](#updates)
- [What it does to your computer](#what-it-does-to-your-computer)
- [Verify the download](#verify-the-download)
- [Code signing policy](#code-signing-policy)
- [If Microsoft Defender removes it](#if-microsoft-defender-removes-it)
- [Known limitations and risks](#known-limitations-and-risks)
- [How it is developed](#how-it-is-developed)

## Install

1. Download `RansomGuard.exe` with the button above.
2. Double-click it and click **Yes** when User Account Control asks. Administrator rights are needed to cut the network.<br>
   If you see "Windows protected your PC", click **More info** → **Run anyway**. It appears because the program is not digitally signed.
3. In the control panel, click **Install and start monitoring**.

The program copies itself to `C:\Program Files\RansomGuard` and starts in the background every time you sign in to Windows. A "RansomGuard" shortcut on the desktop opens the control panel.

## What it detects

Any one of these triggers it:

| Detection | What triggers it |
| --- | --- |
| **Canary files** | Hidden decoy documents in every watched folder are modified, moved or deleted. They have ordinary-looking names, so ransomware that skips obvious decoys still reaches them |
| **Broken files** | Within a short time, several documents, photos (also camera RAW), videos, mailboxes or password databases get corrupted headers, or text files turn into what looks like encrypted data. Office files, zip archives and PDFs are also checked at their end, which catches ransomware that leaves the header alone and encrypts the rest or only blocks of it (partial and intermittent encryption) |
| **Encrypted copies** | Files are deleted and, at the same moment, new files of an unknown type that look encrypted appear in the same folder, e.g. `photo.jpg` → `a8Fk2.b3c1`: ransomware that writes an encrypted copy under another name and deletes the original |
| **Unknown extensions** | Many files are renamed within a short time, e.g. `report.docx` → `report.docx.locked` |
| **Ransom notes** | Files such as `HOW_TO_DECRYPT.txt` appear in several folders within a short time |
| **Dangerous commands** | A program deletes restore points, disables boot recovery, deletes backups, clears event logs or turns off Defender. The command is ended immediately and the program that started it is paused, because ransomware usually does this just before it starts encrypting |

**Watched folders:** Desktop, Documents, Pictures, Downloads, Videos, Music, plus any folder you add with **Watched folders…** under **Settings** in the control panel (another drive, a USB drive, a NAS). A USB drive or NAS that isn't connected is watched as soon as it is (within a minute). System folders and the whole system drive can't be added: they change all the time.

**Downloads are checked too:** new programs, scripts and archives (`.exe`, `.msi`, `.js`, `.zip`...) in Downloads or directly on the Desktop are scanned with Microsoft Defender once they finish downloading. If Defender finds a threat, a message tells you. This doesn't cut the network, because Defender removes the file.

> [!WARNING]
> The canary files are hidden: `0000 Scan index.docx`, `Household budget.xlsx` and `ZZ Archive notes.docx` in each watched folder. You won't see them unless Explorer shows hidden files. Don't modify, move or delete them: that cuts the network. Opening one in Word or Excel shows a notice explaining this; close it without saving. If you already have a file of your own with one of these names, RansomGuard leaves it alone and skips that canary.

## When it triggers

**What RansomGuard does**

1. Pauses the programs that wrote the files that looked encrypted, as Windows' kernel file events tell (if they name nobody: the programs writing the most data), and the program behind a dangerous command. That stops the encryption; Microsoft Defender then scans them. Windows' own processes, Defender and the desktop are never paused.
2. At the same time, disables all network adapters (the firewall is used as a fallback).
3. Covers every screen with a red warning that names the paused programs.

**What you should do**

1. **Don't restore the network**, and don't plug in backup drives or USB sticks.
2. If files are still being renamed or becoming unreadable one by one, hold the power button to force the computer off immediately.
3. Take a photo of the ransom note with your phone, and use your phone to change the passwords of important accounts such as email and banking.

**If it was a false alarm** (e.g. you touched a canary file yourself): open "RansomGuard" on the desktop and click **Restore network and restart monitoring**. Paused programs are scanned by Defender again and resumed if it finds nothing. A program that stays paused ends when you restart the computer.

## Control panel

The home page shows one thing: whether this computer is protected (**Protected**, **Network cut off**, **Detection paused**, **Not protected** or **Not installed**), with the one button you need now, such as **Restore network and restart monitoring** while the network is cut or **Self-check** when everything is fine. Under it, **Protection**, **Backup**, **Tools** and **Settings** each open their page, where every button says what it does; **‹ Back** returns.

| | Button | What it does |
| --- | --- | --- |
| **Protection** | **Install and start monitoring** | Installs background monitoring with the version that is running and starts it, without contacting GitHub |
| | **Pause or stop monitoring** | **Pause file detection** for 30 minutes or 2 hours before bulk work (converting, renaming or encrypting many files on purpose): files that look encrypted, unknown extensions, ransom notes and encrypted copies aren't counted, while canary files and dangerous commands are still watched. It resumes by itself; the home page shows until when. Or **stop monitoring** until you click **Install and start monitoring** or restart Windows |
| | **Restore network and restart monitoring** | Restores the network after a false alarm. While the network is cut, the control panel shows the detection report (why it triggered, which files looked encrypted, which programs were paused), and so does this button before it asks, so you can tell a false alarm from a real attack |
| **Backup** | The home page's **Backup** | RansomGuard can't bring encrypted files back; only a backup can. This row shows whether File History or OneDrive backs up your files; clicking it shows when File History last did, explains how to set one up and opens Windows' settings. Without an up-to-date backup the background monitor reminds you, at most every 14 days; tick "I back up with another program" to stop that |
| **Tools** | **Self-check** | Makes sure protection really works: background monitoring, the process monitor and file write tracing are running, in the control panel's version; the canary files are intact and hidden; only administrators can change the state folder; no errors since monitoring started; the network and backup state. Then a drill in a temporary folder (simulated encryption of 12 documents and a changed canary file, in test mode: no network cut, no warning) shows how fast detection reacts. Takes about 10 seconds, changes nothing |
| | **Check for updates** | Asks GitHub whether there is a newer version and tells you; if there is, asks whether to update |
| | **Preview warning** | Shows what the warning looks like, without cutting the network |
| | **Open log** | Opens `%LOCALAPPDATA%\RansomGuard\guard.log` (entries older than 30 days are removed) |
| | **Clear log** | Empties the log, which lists the files and programs that were detected |
| **Settings** | **Watched folders…** | Adds or removes folders watched besides the default ones, and subfolders file detection skips: folders that change a lot on their own, such as `node_modules` or a build output folder inside a watched drive. Only a folder inside a watched one can be excluded; canary files and dangerous commands are watched there as always, but ransomware encrypting it goes unnoticed. Saving restarts background monitoring |
| | **Check for updates automatically** | Off by default. When on, RansomGuard asks GitHub for new versions every 6 hours and when the control panel opens |
| | **Show a notice by the clock when the network is cut** | On by default. When possible ransomware is detected and the network is cut, a shield with a red dot appears by the clock with a Windows notification; click either for the control panel and the detection report. Nothing shows there otherwise, also while file detection is paused, and it never blinks |
| | **Uninstall** | Removes background monitoring, the health check, the desktop shortcut, the canary files, the `C:\Program Files\RansomGuard` folder, the log and settings and the state data |
| **Top right** | **English / 中文(繁體)** | Switches the interface language |

The **Progress** box, at the bottom of every page, shows what the button you clicked is doing and its results. The first time you open the control panel, you choose the language; the background monitor's warnings use the same language.

<details>
<summary><b>Command-line options</b></summary>

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

</details>

## Updates

- **Checking by hand:** click **Check for updates**. It asks GitHub and tells you whether you have the latest version. If there is a newer one, it asks whether to update; with **Yes** it downloads it, verifies it against the SHA-256 that GitHub publishes, installs it and reopens the control panel with the new version. The current version number is shown in the top-left corner of the control panel.
- **Being told about new versions:** tick **Check for updates automatically** at the bottom left of the control panel. The background monitor then checks GitHub two minutes after you sign in and every 6 hours, and the control panel checks when it opens (the update button then reads **Update to v…** and turns blue). Answer **Yes** and it updates by itself; each version is asked about once per sign-in. It is off by default, because each check shows GitHub your IP address (see [Privacy](PRIVACY.md)); versions before 1.7.3 always checked.
- **You don't have to update.** Answer **No** when asked, and monitoring continues with the version you have. **Install and start monitoring** never contacts GitHub: it installs the version that is running and starts monitoring with it.

> [!NOTE]
> Versions before 1.4.0 can't update themselves: download the new `RansomGuard.exe` from [Releases](https://github.com/leo-code-del/RansomGuard/releases) once, run it and click **Install and start monitoring**.

## What it does to your computer

Everything RansomGuard changes, so you can decide whether you trust it. What it records about you, for how long, and how to delete it is on the [privacy page](PRIVACY.md).

### Permissions

RansomGuard.exe asks for administrator rights (User Account Control) when it starts. The background monitor runs with administrator rights through a scheduled task that starts at every sign-in. The health check runs with normal user rights.

### What it reads

- **Files** that change in Desktop, Documents, Pictures, Downloads, Videos and Music. For common formats (Office files, PDF, pictures, videos, text files) only the first 16 KB, to check whether the file looks encrypted; of Office files, zip archives, PDFs and large text files also the last 4 KB and, for Office files and zip archives, the few bytes where each part starts. A new file of an unknown type is read only when a file is deleted in the same folder at the same moment. OneDrive files that are not downloaded yet are skipped. Other drives and network drives are not read, unless you add them with **Watched folders…** (or `--watch`).
- **Programs:** the command line of every program that starts, to spot the dangerous commands listed above; only those are written to the log. When it triggers, it also reads how much each running program has written.
- **Backup settings:** when File History last backed up (Windows' record of it and File History's own folder in `%LOCALAPPDATA%`) and whether Desktop, Documents and Pictures are in OneDrive. Nothing about your backup is changed or sent anywhere.

### What it creates or changes

| Where | What |
| --- | --- |
| Every watched folder | Three hidden canary files (`0000 Scan index.docx`, `Household budget.xlsx`, `ZZ Archive notes.docx`) |
| `%LOCALAPPDATA%\RansomGuard\` | `guard.log` (at most 4 files of 1 MB, entries older than 30 days removed), `settings.json` (language, automatic update checks, whether you back up with another program, when it last reminded you about a backup, whether to show a notice by the clock when the network is cut) |
| `C:\ProgramData\RansomGuard\` | `state.json` (what was cut off or paused, and the detection report: why it triggered and up to 50 files that looked encrypted, kept until you restore the network), `canaries.json` (which canary files it created), `watch.json` (folders you added), `exclude.json` (subfolders you excluded), `monitor_stopped` (when you stopped monitoring), `detection_paused` (until when file detection is paused). Only administrators can change this folder; your account can read it |
| `C:\Program Files\RansomGuard\` | `RansomGuard.exe`, `icon.ico`, `health_check.js` |
| `%TEMP%` | A `_MEI…` folder the exe unpacks itself into while it runs, removed when it exits. `MpCmdRun.log`, the log Microsoft Defender's scanner keeps of the scans RansomGuard asks for |
| Desktop | The "RansomGuard" shortcut |
| Task Scheduler | The scheduled tasks "RansomGuard" (at sign-in, and every minute if monitoring isn't running; that repeating trigger is taken off while you have stopped monitoring until restart, and put back when it starts) and "RansomGuard Health Check" |
| Windows' icon cache | Refreshed when installing, so the shortcut shows the current icon |

### What it deletes

It never deletes your own files, with one exception listed under [Things that can go wrong](#things-that-can-go-wrong): anything you put into `C:\Program Files\RansomGuard`. Otherwise it deletes only what it created:

- its canary files (only the ones it recorded creating), when the network is restored, when you remove a folder from the watched folders, and on uninstall;
- files left by older versions;
- log entries older than 30 days, and the log when you click **Clear log**;
- on uninstall: the desktop shortcut, both scheduled tasks, the `C:\Program Files\RansomGuard` folder, its own log and settings in `%LOCALAPPDATA%\RansomGuard` and its state data in `C:\ProgramData\RansomGuard`.

### Programs and the network

| When | What it does |
| --- | --- |
| A program runs a dangerous command (deleting restore points, turning off Defender...) | Ends that program and pauses the programs that started it (up to three levels) |
| Possible ransomware is detected | Pauses the programs that wrote the files that looked encrypted (or, if Windows' file events name none, the ones writing the most data; up to five), asks Microsoft Defender to scan the paused programs and run a quick scan, meanwhile disables every network adapter (if that fails: blocks all traffic in the firewall, releases the IP address and disconnects Wi-Fi), shows the full-screen warning |
| Always, while monitoring | Follows which program writes which file in the watched folders (Windows' kernel file events), for a trigger to know whom to pause. Kept in memory for a couple of minutes, never written down |
| A new program, script or archive appears in Downloads or on the Desktop | Asks Microsoft Defender to scan it once it is complete, and tells you if Defender finds a threat |
| While the warning is open | Disables any network adapter that gets turned on again |
| You restore the network | Turns the network adapters back on, puts the firewall settings back, and resumes paused programs that Defender finds clean |
| You click "Force shut down now" on the warning | Shuts the computer down, after asking you to confirm |

### Internet connections

By default RansomGuard doesn't connect to the internet by itself. Only the exe ever connects, and only to GitHub:

- when you click **Check for updates**, and to download a new version you agreed to (or when you run it with `--update` or `--install`);
- every 6 hours and when the control panel opens, if you turn on **Check for updates automatically** (off by default, because every check shows GitHub your IP address).

It downloads a new version from `github.com` only after you agree, and checks the file's SHA-256 before installing it. No information about you or your files is sent anywhere. The Python version never connects to the internet. Microsoft Defender scans run on your computer; whether Defender itself contacts Microsoft depends on your Defender settings.

## Verify the download

From v1.7.1 on, every `RansomGuard.exe` is built by [GitHub Actions](.github/workflows/release.yml) from the tagged source code, not on anyone's own computer, and GitHub signs a *build provenance attestation* for it: a record of which repository, workflow and commit produced exactly this file. Versions before 1.7.1 were built on the developer's computer and have no attestation.

**With the [GitHub CLI](https://cli.github.com/)** (sign in once with `gh auth login`), run this in the folder with the downloaded file:

```
gh attestation verify RansomGuard.exe --repo leo-code-del/RansomGuard
```

"Verification succeeded" means the file is byte for byte what the workflow built. If it fails, don't run the file. Two stricter checks:

- that it came from the release workflow, not from any other workflow in the repository:

  ```
  gh attestation verify RansomGuard.exe --repo leo-code-del/RansomGuard --signer-workflow leo-code-del/RansomGuard/.github/workflows/release.yml
  ```

- that it is the file attached to a release (releases are immutable, so their files can't be replaced; use the version you downloaded):

  ```
  gh release verify-asset v1.7.3 RansomGuard.exe --repo leo-code-del/RansomGuard
  ```

**Without the GitHub CLI**, compare the SHA-256 shown under Assets on the [release page](https://github.com/leo-code-del/RansomGuard/releases) with PowerShell's `Get-FileHash RansomGuard.exe`.

## Code signing policy

RansomGuard.exe is **not code-signed yet**. The project plans to apply to the [SignPath Foundation](https://signpath.org) program for free code signing of open-source software. Until a release is actually signed, check downloads as described in [Verify the download](#verify-the-download).

If the application is approved, signed releases will carry this statement: Free code signing provided by [SignPath.io](https://about.signpath.io), certificate by [SignPath Foundation](https://signpath.org).

- **What is signed:** only `RansomGuard.exe`, built by the [release workflow](.github/workflows/release.yml) on GitHub Actions from this repository's source code. Nothing built on a personal computer is signed.
- **Committers and reviewers:** [leo-code-del](https://github.com/leo-code-del)
- **Approvers:** [leo-code-del](https://github.com/leo-code-del) approves each release before it is signed.
- **Privacy:** RansomGuard doesn't transfer any information to other networked systems unless the user asks it to (checking for and downloading updates from GitHub). See the [privacy page](PRIVACY.md).
- **License:** [MIT](LICENSE).

## If Microsoft Defender removes it

Defender sometimes reports RansomGuard.exe as a threat (for example `Trojan:Win32/Bearfoos!ml`). The `!ml` means a machine-learning guess, not a known virus: programs packaged with PyInstaller that need administrator rights, stop processes and disable network adapters look suspicious to it. Defender then also deletes the installed copy and its scheduled task, and protection stops.

Since 1.7.0 a separate **health check** notices this: five minutes after you sign in and every day at noon, it shows a message if protection is gone or monitoring is not running, and offers to open the download page or the control panel. It runs without opening a window and doesn't need RansomGuard.exe. Versions before 1.7.0 give no message, so check now and then that the control panel shows "Running".

To restore it:

1. Compare the file's SHA-256 with the one shown under Assets on the [release page](https://github.com/leo-code-del/RansomGuard/releases) (PowerShell: `Get-FileHash RansomGuard.exe`). Only continue if they match.
2. Windows Security → Virus & threat protection → Protection history → select the item → **Restore** (or **Allow on device**).
3. Run RansomGuard.exe again and click **Install and start monitoring**.
4. Please report the false positive to Microsoft at <https://www.microsoft.com/wdsi/filesubmission> (choose "Incorrectly detected"), which clears it for everyone.

## Known limitations and risks

Keep using antivirus software (such as Microsoft Defender), install Windows updates, and back up important files regularly to a drive that is **not normally connected** to the computer. A backup drive that is always plugged in can be encrypted too.

### What it can't do

- It is not antivirus software. It doesn't recognize malware; it only reacts to behavior that looks like encryption.
- It watches only Desktop, Documents, Pictures, Downloads, Videos and Music. Files on other drives, network drives and cloud folders outside these are not protected, unless you add them with **Watched folders…**.
- Some files are lost before it reacts. It triggers after about 8 to 10 files look encrypted within 30 seconds (or when a canary file is touched), and cutting the network takes a second or two.
- Ransomware that encrypts slowly enough to stay under these thresholds is caught only if it touches a canary file. So is ransomware that keeps each file's name and encrypts only the middle of photos and videos, leaving their start intact (for Office files, zip archives, PDFs and text files the end is checked too).
- Files in subfolders you excluded under **Watched folders…** aren't checked at all; ransomware encrypting them is caught only by the canary files and dangerous-command checks elsewhere.
- Ransomware that deletes restore points through Windows programming interfaces, instead of running commands such as `vssadmin`, is not caught by the dangerous-command check.
- Programs that write through memory-mapped files look like Windows itself in the file events and don't show up in the write counts either, so they may not be found to be paused.
- Ransomware that already has administrator rights can stop RansomGuard. The scheduled task starts it again within a minute; if the ransomware deletes the task too, the health check tells you within a day.
- After it triggers, it doesn't trigger a second time until you restore the network, but it keeps stopping dangerous commands and pausing the programs behind them.
- It has been tested with automated tests and simulated ransomware (a test script using 11 techniques, from encrypting and renaming to partial and intermittent encryption and encrypted copies), alongside 11 kinds of everyday work that must not trigger it, never with real ransomware. Which program to pause was checked with a stand-in encryptor next to a program writing 2 MB a second: the encryptor was found in 20 of 20 trials, the busy program never.
- Windows 10 and 11 only, and it needs administrator rights.

### Things that can go wrong

- **False alarms cut the network.** This happens if you touch a canary file, if a program renames 10 or more files to an unusual extension within 30 seconds, if files named like ransom notes (e.g. `how to recover files.txt`) appear in three folders, or if a file-encryption program (such as AxCrypt) turns 8 or more documents into encrypted files and deletes the originals within 30 seconds. Before such bulk work, pause file detection with **Pause or stop monitoring**.
- **Legitimate maintenance is stopped.** Backup software or an administrator running `wbadmin delete backup`, `vssadmin delete shadows` or `wevtutil cl` is treated as ransomware: the command is ended and the network is cut.
- **Normal programs can be paused by a false alarm.** Editors, browsers and OneDrive write all the time and may be paused (and freeze) until you restore the network from the control panel. If you restore with `restore_network.bat` instead, they stay paused until the computer restarts.
- **You won't hear about new versions unless you ask.** Automatic update checks are off by default for privacy, so improvements and fixes reach you only if you click **Check for updates** now and then, or turn on **Check for updates automatically**.
- **Uninstalling deletes the whole `C:\Program Files\RansomGuard` folder**, including any files you put there yourself.

### Known security issues

These are removed from this list once fixed.

- **Running from Python source can give malware administrator rights.** `install_ransom_guard.bat` and `ransom_guard.py --install` make the scheduled task run `ransom_guard.py` and the `ransomguard` package from the folder they are in, with administrator rights. If that folder can be changed without administrator rights (for example a folder on D: or in your user folder), any program running as you could change the code and get administrator rights at your next sign-in. The exe doesn't have this problem: it copies itself to `C:\Program Files\RansomGuard`, which only administrators can change. If you run from source, keep the project in a folder only administrators can change.
- **Updates are checked only against GitHub.** The SHA-256 that an update is checked against comes from GitHub too, so it protects against damaged downloads but not against a compromised GitHub account. The built-in updater doesn't check the attestation either; you can check it yourself (see [Verify the download](#verify-the-download)). The exe is not code-signed, which is also why SmartScreen and Defender sometimes distrust it.

## How it is developed

RansomGuard is developed mainly with [Claude Code](https://claude.com/claude-code), an AI coding assistant made by Anthropic. The repository owner reviews the changes, decides what goes into each release and tries new versions on their own computers. Every change is checked by the automated tests in `tests/`, and releases are built and published by GitHub Actions. Code written with AI help can still contain mistakes, so please report anything that looks wrong in [Issues](https://github.com/leo-code-del/RansomGuard/issues).

Running from source, building, testing and publishing: see [DEVELOPMENT.md](DEVELOPMENT.md).
