"""Put a "please update to the latest version" notice at the top of the previous release's notes.
Used by .github/workflows/release.yml after a release is published:

    python .github/scripts/recommend_latest.py v1.7.1            (the release just published)
    python .github/scripts/recommend_latest.py v1.7.1 --dry-run  (only print what would change)

Written in Python rather than PowerShell so the notes (with Chinese text) are read and written as UTF-8
whatever the console's code page is. The notice doesn't say the old version has problems; it only
recommends the latest one."""
import json
import os
import shutil
import subprocess
import sys
import tempfile

GH = shutil.which("gh") or r"C:\Program Files\GitHub CLI\gh.exe"


def gh(*args) -> str:
    return subprocess.run([GH, *args], capture_output=True, check=True).stdout.decode("utf-8")


def notice(repo: str, has_exe: bool) -> str:
    latest = f"https://github.com/{repo}/releases/latest"
    if has_exe:  # immutable releases keep their exe, so it is still downloadable
        return (f"> **This is not the latest version.** Please update to the [latest version]({latest}).\n>\n"
                f"> **這不是最新版本。** 建議更新到[最新版本]({latest})。\n\n")
    return (f"> **No longer available for download.** Please update to the [latest version]({latest}).\n>\n"
            f"> **此版本已停止提供下載。** 建議更新到[最新版本]({latest})。\n\n")


def main():
    tag, dry_run = sys.argv[1], "--dry-run" in sys.argv
    repo = os.environ.get("GH_REPO", "leo-code-del/RansomGuard")
    releases = json.loads(gh("release", "list", "--repo", repo, "--limit", "20", "--exclude-drafts",
                             "--json", "tagName,publishedAt"))
    older = sorted((r for r in releases if r["tagName"] != tag), key=lambda r: r["publishedAt"], reverse=True)
    if not older:
        print("no previous release")
        return
    previous = older[0]["tagName"]
    view = json.loads(gh("release", "view", previous, "--repo", repo, "--json", "body,assets"))
    body = view["body"].replace("\r\n", "\n")
    if body.startswith(("> **No longer available", "> **This is not the latest")):
        print(f"{previous} already recommends the latest version")
        return
    notes = notice(repo, bool(view["assets"])) + body
    if dry_run:
        sys.stdout.reconfigure(encoding="utf-8")
        print(f"would update {previous}:\n" + "\n".join(notes.split("\n")[:6]))
        return
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".md", delete=False) as f:
        f.write(notes)
    try:
        gh("release", "edit", previous, "--repo", repo, "--notes-file", f.name)
    finally:
        os.remove(f.name)
    print(f"{previous} now recommends the latest version")


if __name__ == "__main__":
    main()
