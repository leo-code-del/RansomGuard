"""Check a built RansomGuard.exe contains what it needs to start; build.bat runs this after PyInstaller.

    python check_build.py dist\\RansomGuard.exe

The control panel uses tkinter, and PyInstaller's start-up hook for it stops the whole program, the
background monitor included, when the Tcl/Tk data is missing. That happened to v1.7.1: it was built with a
Python whose Tcl/Tk 9 keeps that data inside its DLL, which PyInstaller didn't pack, and the build itself
only printed a warning.
"""
import sys
from pathlib import Path

from PyInstaller.archive.readers import CArchiveReader

REQUIRED = {
    "Tcl data (_tcl_data)": lambda n: n.startswith(("_tcl_data/", "_tcl_data\\")),
    "Tk data (_tk_data)": lambda n: n.startswith(("_tk_data/", "_tk_data\\")),
    "Tk library (tk*.dll)": lambda n: n.lower().startswith("tk") and n.lower().endswith(".dll"),
    "icon (icon.ico)": lambda n: n == "icon.ico",
}


def missing(names) -> list:
    """What the exe whose packed file names are `names` lacks."""
    return [what for what, found in REQUIRED.items() if not any(found(n) for n in names)]


def missing_modules(packed) -> list:
    """The program's modules (every .py in the ransomguard folder) not among the packed module names; one
    left out would only fail when that part of the program first runs."""
    package = Path(__file__).resolve().parent / "ransomguard"
    wanted = ["ransomguard"] + [f"ransomguard.{f.stem}" for f in sorted(package.glob("*.py")) if f.stem != "__init__"]
    return [m for m in wanted if m not in packed]


def main():
    exe = sys.argv[1] if len(sys.argv) > 1 else r"dist\RansomGuard.exe"
    archive = CArchiveReader(exe)
    lacking = missing(list(archive.toc))
    pyz = next((n for n in archive.toc if n.endswith(".pyz")), None)
    lacking += missing_modules(set(archive.open_embedded_archive(pyz).toc) if pyz else set())
    if lacking:
        print(f"{exe} is incomplete, it would not start: missing " + ", ".join(lacking))
        sys.exit(1)
    print(f"{exe}: Tcl/Tk data, icon and all program modules are packed")


if __name__ == "__main__":
    main()
