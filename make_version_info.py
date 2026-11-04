"""Write the Windows version resource for RansomGuard.exe; build.bat runs this before PyInstaller.

    python make_version_info.py build\\version_info.txt

The exe's Properties > Details tab then shows the product name and VERSION from ransomguard/config.py.
Code signing (SignPath) requires every signed file to carry the product name and the same product
version as the release.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PRODUCT = "RansomGuard"


def read_version(config_text: str) -> str:
    """VERSION from the text of ransomguard/config.py (read as text, so nothing of the program runs)."""
    m = re.search(r'^VERSION = "(\d+)\.(\d+)\.(\d+)"', config_text, re.M)
    if not m:
        raise ValueError('VERSION = "x.y.z" not found in ransomguard/config.py')
    return ".".join(m.groups())


def version_info(version: str) -> str:
    """PyInstaller's --version-file text for `version` ("1.8.1")."""
    four = tuple(int(n) for n in version.split(".")) + (0,)
    strings = {
        "CompanyName": "leo-code-del",
        "FileDescription": PRODUCT,
        "FileVersion": version,
        "InternalName": PRODUCT,
        "LegalCopyright": "Copyright (c) 2026 leo-code-del. MIT License.",
        "OriginalFilename": f"{PRODUCT}.exe",
        "ProductName": PRODUCT,
        "ProductVersion": version,
    }
    entries = ",\n".join(f"          StringStruct({k!r}, {v!r})" for k, v in strings.items())
    return f"""VSVersionInfo(
  ffi=FixedFileInfo(
    filevers={four},
    prodvers={four},
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo([
      StringTable(
        '040904B0',
        [
{entries}
        ])
    ]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
"""


def main(out: str) -> None:
    version = read_version((ROOT / "ransomguard" / "config.py").read_text(encoding="utf-8"))
    path = Path(out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(version_info(version), encoding="utf-8")
    print(f"{path}: {PRODUCT} {version}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python make_version_info.py <output file>")
    main(sys.argv[1])
