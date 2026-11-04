#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RansomGuard - detects ransomware-like encryption activity and cuts off the network when it triggers.
The program lives in the ransomguard package next to this file; this script starts it.

Detection (any one of these triggers it):
  1. A canary file is modified, moved or deleted (also checked periodically, in case events are missed)
  2. Within a short time, several files get "broken": .docx/.pdf/.jpg/.mp4 headers no longer match,
     or plain-text files (.txt/.py/.cpp...) turn into high-entropy content (looks encrypted)
  3. Within a short time, many files are renamed to unknown extensions (e.g. report.docx -> report.docx.locked)
  4. Within a short time, ransom notes appear in several folders (e.g. HOW_TO_DECRYPT.txt)
  5. A process runs a destructive command commonly used by ransomware/intruders: deleting restore
     points (vssadmin, wmic), disabling boot recovery (bcdedit), deleting backups (wbadmin), clearing
     event logs, disabling Defender (in normal mode that process is terminated immediately, and the program
     that started it is paused)

When triggered: pause the programs writing the most data (Microsoft Defender then scans them)
        -> disable every network adapter (fall back to a firewall block) -> write the log
        -> full-screen red warning (all screens, steady red, alarm sound); adapters re-enabled while the
           warning is open are disabled again
        (optional: HIBERNATE_ON_TRIGGER = True in ransomguard/config.py hibernates right away)

Also: new programs, scripts and archives in Downloads or on the Desktop are scanned by Microsoft Defender
      once they finish downloading, and the user is told if it finds a threat.
      A separate health check (scheduled task, no RansomGuard.exe needed) warns at sign-in and daily when
      background protection is gone (e.g. removed by Defender by mistake) or not running.

Usage (Windows; normal mode needs administrator rights):
  python ransom_guard.py             monitor (the packaged .exe opens the control panel when run without options)
  python ransom_guard.py --monitor   monitor (used by the scheduled task)
  python ransom_guard.py --gui       control panel: install, restore network, preview warning, uninstall
  python ransom_guard.py --dry-run   test mode: log and show alerts only, never cut the network
  python ransom_guard.py --restore   restore the network and restart background monitoring
  python ransom_guard.py --install   install / update background monitoring (the .exe is copied to Program Files)
  python ransom_guard.py --update    open the control panel and update to the latest release right away
  python ransom_guard.py --test-alert  preview the full-screen warning (no detection, no network cut)
  python ransom_guard.py --watch D:\\Data --watch E:\\Backup   watch custom folders
  python ransom_guard.py --lang en   English interface (zh = Traditional Chinese; defaults to the Windows
                                     display language and can be switched in the control panel)

Requires: pip install watchdog
Log file: %LOCALAPPDATA%\\RansomGuard\\guard.log

Build a single executable: run build.bat (output dist\\RansomGuard.exe, with icon.ico from make_icon.py
packed inside; without it the window, taskbar and shortcut show PyInstaller's default icon)

Download and update: https://github.com/leo-code-del/RansomGuard/releases
  Download the new RansomGuard.exe -> run it -> click "Install and start monitoring"
  (or click "Check for updates" in the control panel; "Install and start monitoring" alone keeps the
  version that is running)
"""
import os
import sys

# The scheduled task runs Python with -P, which keeps this folder off the import path so that a planted
# json.py here can't run with administrator rights. Adding it at the end lets the ransomguard package be
# found without letting anything here shadow a standard module.
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ransomguard.app import main  # noqa: E402

if __name__ == "__main__":
    main()
