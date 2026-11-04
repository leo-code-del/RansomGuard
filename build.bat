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
rem product name and version (from ransomguard\config.py) in the exe's Properties > Details
"%PYTHON%" make_version_info.py build\version_info.txt
if errorlevel 1 exit /b 1
rem paths are relative to --specpath build, hence ..\icon.ico
"%PYTHON%" -m PyInstaller --noconfirm --onefile --windowed --uac-admin --name RansomGuard ^
  --icon ..\icon.ico --version-file "%~dp0build\version_info.txt" --add-data "..\icon.ico;." ^
  --distpath dist --workpath build --specpath build ransom_guard.py
if errorlevel 1 exit /b 1
rem PyInstaller only warns when it can't pack the Tcl/Tk data, and the exe then doesn't start (v1.7.1)
"%PYTHON%" check_build.py dist\RansomGuard.exe
exit /b %errorlevel%
