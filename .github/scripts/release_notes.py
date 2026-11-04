"""Write the notes for a new release: release-notes/<tag>.md plus a "Code signing policy" link at the end.
Used by .github/workflows/release.yml before the release is created:

    python .github/scripts/release_notes.py v1.8.2 notes.md

SignPath Foundation requires the code signing policy to be linked from the download/release pages, so
every release gets the link without anyone having to remember it. Written in Python so the notes (with
Chinese text) are read and written as UTF-8 whatever the console's code page is."""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent


def footer(repo: str) -> str:
    home = f"https://github.com/{repo}"
    return ("\n\n---\n\n"
            f"**Code signing policy:** [English]({home}#code-signing-policy) · "
            f"[中文]({home}/blob/main/README.zh-TW.md#code-signing-policy-程式碼簽章政策)\n")


def notes(body: str, repo: str) -> str:
    """`body` with the code signing policy link added at the end (once)."""
    body = body.replace("\r\n", "\n").rstrip("\n")
    if "**Code signing policy:**" in body:
        return body + "\n"
    return body + footer(repo)


def main():
    tag, out = sys.argv[1], sys.argv[2]
    repo = os.environ.get("GH_REPO", "leo-code-del/RansomGuard")
    body = (ROOT / "release-notes" / f"{tag}.md").read_text(encoding="utf-8")
    Path(out).write_text(notes(body, repo), encoding="utf-8")
    print(f"{out}: notes for {tag} with the code signing policy link")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: python .github/scripts/release_notes.py <tag> <output file>")
    main()
