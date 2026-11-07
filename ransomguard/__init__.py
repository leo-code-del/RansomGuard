"""RansomGuard: detects ransomware-like encryption and cuts off the network. Started by ransom_guard.py.

Modules, roughly in the order a trigger goes through them:
  config     version, settings you can tune, language, the user's settings
  winapi     Windows plumbing (PowerShell, kernel32, processes, message boxes, known folders)
  storage    the log and the state only administrators can change
  folders    which folders are watched
  canary     hidden decoy files
  detection  telling encryption from everyday work; the file-event handler
  processes  destructive commands and the process monitor
  filetrace  which program writes which file (the kernel's file events)
  response   pausing programs and the full-screen warning
  defender   Microsoft Defender scans and the download scanner
  network    cutting the network off and restoring it
  install    scheduled task, install, uninstall, health check
  updates    new versions from GitHub
  backup     whether files are backed up (File History, OneDrive) and the backup reminder
  selftest   the control panel's self-check: is protection really working, and a drill
  tray       the notice by the clock while the network is cut
  gui        the control panel
  app        the monitor's main loop and the command line

Modules refer to each other as `module.name` (not `from module import name`), so replacing a name in its
module, as the tests do, takes effect everywhere.
"""
