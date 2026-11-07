# Privacy

**English** | [中文(繁體)](PRIVACY.zh-TW.md)

This page describes what personal data RansomGuard handles. It is written with the principles of the EU General Data Protection Regulation (GDPR) in mind: collect as little as possible, keep it no longer than needed, be transparent, and let you delete it. It is a description of what the program does, not legal advice.

## In short

- **The developer collects nothing.** RansomGuard has no telemetry, analytics, crash reports, accounts or advertising, and it never sends your files, file names, logs or settings anywhere.
- Everything RansomGuard records stays on your computer, is kept for at most 30 days (the log), and can be deleted by you at any time.
- By default RansomGuard **doesn't connect to the internet by itself**. It contacts GitHub only when you click **Check for updates**, or every 6 hours if you turn on **Check for updates automatically**.

## What stays on your computer

| What | Where | Contains | How long |
| --- | --- | --- | --- |
| Log | `%LOCALAPPDATA%\RansomGuard\guard.log` (and `.1` to `.3`) | Times, names of files that looked encrypted, programs that were stopped or paused (with their command lines), what RansomGuard did. File and folder names can include your Windows user name or other personal details | Entries older than 30 days are removed when RansomGuard starts and daily while it monitors; at most 4 MB in all |
| State | `C:\ProgramData\RansomGuard\state.json` | When the network was cut, which network adapters and firewall settings to restore, which programs were paused, why it triggered and up to 50 names of files that looked encrypted | Until the network is restored |
| Canary record, watched folders, stop flag | `C:\ProgramData\RansomGuard\` (`canaries.json`, `watch.json`, `monitor_stopped`) | Paths of the canary files it created and of the folders you added; when you stopped monitoring | Until uninstall |
| Settings | `%LOCALAPPDATA%\RansomGuard\settings.json` | Interface language, whether automatic update checks are on, whether you back up with another program, when it last reminded you about a backup, whether to show a notice by the clock when the network is cut | Until uninstall |
| Canary files | Every watched folder (hidden) | A fixed text explaining what the file is; nothing about you | Until uninstall |

`C:\ProgramData\RansomGuard` can be changed only by administrators, so no program running as you can tamper with what RansomGuard does with administrator rights. Your own account can read it.

**Deleting it:** the control panel's **Clear log** button empties the log. **Uninstall** deletes `%LOCALAPPDATA%\RansomGuard`, `C:\ProgramData\RansomGuard`, the canary files and everything RansomGuard installed. You can also delete these files yourself (`C:\ProgramData\RansomGuard` needs administrator rights); RansomGuard recreates what it needs.

RansomGuard reads the first 16 KB of files that change in your watched folders to tell whether they look encrypted. What it reads is only compared in memory and never stored, except the file's name in the log when a file looks encrypted.

While monitoring, it also follows Windows' kernel file events to know which program wrote which file in your watched folders (only the program's process ID and the file's name, no content). That stays in memory for a couple of minutes, so that a trigger can pause the right program; only the programs it pauses are written to the log.

## Connections to the internet

**GitHub** (`api.github.com`, `github.com`) is the only place RansomGuard connects to, and only:

- when you click **Check for updates**, and to download a new version you agreed to install (or when you run `RansomGuard.exe --update` / `--install`);
- every 6 hours and when the control panel opens, **only if you turned on Check for updates automatically** (off by default; the control panel explains what it means before turning it on);
- when the health check finds that protection is gone and you choose to open the download page in your browser.

What GitHub receives: your IP address, the time, and the request itself, which only asks for the latest version or downloads the exe. RansomGuard identifies itself as `RansomGuard` without a version number or anything about you. GitHub handles this under the [GitHub General Privacy Statement](https://docs.github.com/site-policy/privacy-policies/github-general-privacy-statement). The developer doesn't receive it.

**Your IP address can't be hidden from a server you connect to**; no program can do that. To keep it from GitHub, leave automatic update checks off and don't click the update button, or update through a VPN (RansomGuard uses Windows' proxy settings). A VPN provider can see your IP address instead.

**Installing with Install and start monitoring never connects to the internet.**

## Microsoft Defender

RansomGuard asks Microsoft Defender, which is part of Windows, to scan new programs, scripts and archives in Downloads and on the Desktop, and the programs it pauses when it triggers. The scans run on your computer. Whether Defender sends information about a file (or the file itself) to Microsoft is decided by your Defender settings, not by RansomGuard: Windows Security → Virus & threat protection → Manage settings → **Cloud-delivered protection** and **Automatic sample submission**. Defender scans downloaded files on its own anyway, so RansomGuard's scans don't change what Defender may send. See the [Microsoft Privacy Statement](https://privacy.microsoft.com/privacystatement).

Defender's scanner (`MpCmdRun.exe`) keeps its own log, `%TEMP%\MpCmdRun.log`, which lists the files it was asked to scan. It belongs to Defender, so RansomGuard doesn't clear or delete it; you can delete it yourself.

## Your rights under the GDPR

The developer doesn't collect, receive or store any personal data of RansomGuard's users, so there is nothing the developer could show, correct, export or delete for you. The data described above stays on your own computer, under your control: you can read it (it is plain text), delete it (Clear log, Uninstall) and stop it from being created (uninstall).

## Questions

Ask in [Issues](https://github.com/leo-code-del/RansomGuard/issues). Issues are public: don't post your log or anything personal there.
