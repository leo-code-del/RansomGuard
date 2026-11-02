@echo off
rem Build dist\RansomGuard.exe: one file, asks for administrator rights, shield icon packed inside.
rem Uses "python" from PATH; set PYTHON to use another one, e.g.  set PYTHON=C:\Python314\python.exe
setlocal
cd /d "%~dp0"
if not defined PYTHON set "PYTHON=python"
if not exist icon.ico (
  echo icon.ico is missing. Create it with:  %PYTHON% make_icon.py
  exit /b 1
)
rem paths are relative to --specpath build, hence ..\icon.ico
"%PYTHON%" -m PyInstaller --noconfirm --onefile --windowed --uac-admin --name RansomGuard ^
  --icon ..\icon.ico --add-data "..\icon.ico;." ^
  --distpath dist --workpath build --specpath build ransom_guard.py
exit /b %errorlevel%
