"""Canary files: hidden decoy Word / Excel files in every watched folder, the record of which ones
this program created, and checking, resetting and deleting them."""
import io
import json
import os
import zipfile
from pathlib import Path

from . import config, storage, winapi
from .config import log, tr
from .winapi import norm


# Canary files look like ordinary documents, so ransomware that skips obvious decoys still reaches them, and
# they are hidden, so people don't come across them. The names sort first, in the middle and last, because
# ransomware usually works through a folder in name order. Placed in every watched folder; a file of the
# user's that happens to have one of these names is never touched (see plant_canaries).
CANARY_NAMES = ["0000 Scan index.docx", "Household budget.xlsx", "ZZ Archive notes.docx"]
# names used before (visible "canary" names until v1.7.4, Chinese ones before v1.3.0): deleted when the
# monitor starts
LEGACY_CANARY_NAMES = ["!!!_canary_do_not_delete.docx", "!!!_canary_do_not_delete.xlsx",
                       "zzz_canary_do_not_delete.docx", "!!!_canary_勿刪.docx", "!!!_canary_勿刪.xlsx", "zzz_canary_勿刪.docx"]
# what canary files contained before v1.6.1 (plain text, so Word and Excel called them corrupt); still
# accepted as intact, and replaced by the current content when the monitor starts
LEGACY_CANARY_BYTES = ((
    "This is a ransomware canary file (RansomGuard). Do not open, modify, move or delete it.\n"
    "這是防勒索病毒的誘餌檔（RansomGuard），請勿開啟、修改、移動或刪除。\n"
) * 200).encode("utf-8")

# Canary files are real Word / Excel files: opening one explains what it is, and Word and Excel suggest
# opening it read-only. Stored uncompressed with fixed timestamps, so every version writes the same bytes.
# (heading?, text); the text must not contain & < >
_CANARY_TEXT = [
    (True, "RansomGuard 誘餌檔：請直接關閉，不要修改"),
    (True, "RansomGuard canary file: please close it without changes"),
    (False, "這個檔案用來偵測勒索病毒。修改、儲存、移動或刪除它，RansomGuard 會以為電腦中了勒索病毒，並自動切斷網路。"),
    (False, "This file detects ransomware. If it is modified, saved, moved or deleted, RansomGuard assumes the "
            "computer has ransomware and cuts off the network."),
    (False, "如果不小心觸發了：開啟桌面上的「RansomGuard」，按「恢復網路並重新開啟監控」。"),
    (False, "If that happens by mistake: open \"RansomGuard\" on the desktop and click \"Restore network and "
            "restart monitoring\"."),
]
_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_RELS_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
_CT_NS = "http://schemas.openxmlformats.org/package/2006/content-types"
_OOXML_CT = "application/vnd.openxmlformats-officedocument."


def _ooxml(main: str, parts: dict) -> bytes:
    """A minimal Office Open XML package. main: path of the main part; parts: {path: (content type, xml)}."""
    types = "".join(f'<Override PartName="/{n}" ContentType="{_OOXML_CT}{ct}"/>'
                    for n, (ct, _) in parts.items() if ct)  # .rels parts are covered by the Default
    files = {
        "[Content_Types].xml": f'<Types xmlns="{_CT_NS}"><Default Extension="rels" ContentType='
                               f'"application/vnd.openxmlformats-package.relationships+xml"/>'
                               f'<Default Extension="xml" ContentType="application/xml"/>{types}</Types>',
        "_rels/.rels": f'<Relationships xmlns="{_RELS_NS}"><Relationship Id="rId1" '
                       f'Type="{_REL}/officeDocument" Target="{main}"/></Relationships>',
        **{n: xml for n, (_, xml) in parts.items()},
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        for name, xml in files.items():
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 0  # otherwise it depends on the system that built the program
            z.writestr(info, ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n' + xml).encode("utf-8"))
    return buf.getvalue()


def _rels(*rels) -> str:
    return f'<Relationships xmlns="{_RELS_NS}">' + "".join(
        f'<Relationship Id="rId{i}" Type="{_REL}/{t}" Target="{target}"/>'
        for i, (t, target) in enumerate(rels, 1)) + "</Relationships>"


def _docx_par(head: bool, text: str) -> str:
    size = ('<w:b/><w:color w:val="C00000"/><w:sz w:val="40"/><w:szCs w:val="40"/>' if head else
            '<w:sz w:val="28"/><w:szCs w:val="28"/>')
    return f"<w:p><w:r><w:rPr>{size}</w:rPr><w:t>{text}</w:t></w:r></w:p>"


def _xlsx_row(i: int, head: bool, text: str) -> str:
    style = ' s="1"' if head else ""  # cell format 1 = the bold red font in styles.xml
    return f'<row r="{i}"><c r="A{i}" t="inlineStr"{style}><is><t>{text}</t></is></c></row>'


_WML = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
_SML = 'xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
CANARY_DOCX = _ooxml("word/document.xml", {
    "word/document.xml": ("wordprocessingml.document.main+xml", f"<w:document {_WML}><w:body>"
                          + "".join(_docx_par(*t) for t in _CANARY_TEXT) + "</w:body></w:document>"),
    "word/_rels/document.xml.rels": ("", _rels(("settings", "settings.xml"))),
    "word/settings.xml": ("wordprocessingml.settings+xml",
                          f'<w:settings {_WML}><w:writeProtection w:recommended="1"/></w:settings>'),
})
CANARY_XLSX = _ooxml("xl/workbook.xml", {
    "xl/workbook.xml": ("spreadsheetml.sheet.main+xml",
                        f'<workbook {_SML} xmlns:r="{_REL}"><fileSharing readOnlyRecommended="1"/>'
                        '<sheets><sheet name="RansomGuard" sheetId="1" r:id="rId1"/></sheets></workbook>'),
    "xl/_rels/workbook.xml.rels": ("", _rels(("worksheet", "worksheets/sheet1.xml"), ("styles", "styles.xml"))),
    "xl/worksheets/sheet1.xml": ("spreadsheetml.worksheet+xml",
                                 f'<worksheet {_SML}><cols><col min="1" max="1" width="120" customWidth="1"/></cols>'
                                 "<sheetData>" + "".join(_xlsx_row(i, *t) for i, t in enumerate(_CANARY_TEXT, 1))
                                 + "</sheetData></worksheet>"),
    "xl/styles.xml": ("spreadsheetml.styles+xml",
                      f'<styleSheet {_SML}><fonts count="2"><font><sz val="11"/><name val="Calibri"/></font>'
                      '<font><b/><sz val="16"/><color rgb="FFC00000"/><name val="Calibri"/></font></fonts>'
                      '<fills count="2"><fill><patternFill patternType="none"/></fill>'
                      '<fill><patternFill patternType="gray125"/></fill></fills>'
                      '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
                      '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
                      '<cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
                      '<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/></cellXfs>'
                      '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>'
                      "</styleSheet>"),
})


def canary_bytes(path) -> bytes:
    """What the canary file at `path` contains."""
    return CANARY_XLSX if Path(path).suffix.lower() == ".xlsx" else CANARY_DOCX


def canary_intact(path, data: bytes) -> bool:
    return data == canary_bytes(path) or data == LEGACY_CANARY_BYTES


# ---- canary files ----
def _canary_record_file() -> Path:
    return storage.state_dir() / "canaries.json"


def canary_record() -> list:
    """The canary files this program created (paths); only these may be rewritten or deleted."""
    try:
        paths = json.loads(_canary_record_file().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return [p for p in paths if isinstance(p, str)] if isinstance(paths, list) else []


def _set_hidden(path, hidden: bool):
    if config.IS_WINDOWS:
        winapi.kernel32().SetFileAttributesW(str(path), 0x2 if hidden else 0x80)  # HIDDEN / NORMAL


def _write_canary(path: Path):
    if path.exists():
        _set_hidden(path, False)  # a hidden file can't be opened for overwriting
    path.write_bytes(canary_bytes(path))
    _set_hidden(path, True)


def plant_canaries(dirs, upgrade=False):
    """Create missing canary files (hidden) in every folder and reset changed ones. A file with a canary's
    name that this program didn't create and that isn't a canary is the user's own: it is left alone, and that
    canary is skipped. upgrade: also replace the canary content of versions before 1.6.1 (only when no other
    monitor can be watching them)."""
    record = {norm(p): p for p in canary_record()}
    paths = []
    for d in dirs:
        for name in CANARY_NAMES:
            p = Path(d) / name
            try:
                data = p.read_bytes() if p.exists() else None
                if data is not None and not canary_intact(p, data):
                    if norm(p) not in record:
                        log.info(tr("略過誘餌檔：已經有同名的檔案 %s", "Canary skipped: a file of that name exists: %s"), p)
                        continue
                    log.warning(tr("誘餌檔內容和預期不同（程式沒執行時被改過？）：%s",
                                   "Canary file content is not what was expected "
                                   "(changed while the program was not running?): %s"), p)
                    winapi.alert(tr("RansomGuard 注意", "RansomGuard notice"),
                                 tr(f"誘餌檔在程式沒執行時被修改過：\n{p}\n\n請確認電腦是否異常。",
                                    f"A canary file was modified while the program was not running:\n{p}\n\n"
                                    "Please check whether something is wrong with this computer."))
                if data is None or not canary_intact(p, data) or (upgrade and data != canary_bytes(p)):
                    _write_canary(p)
                else:
                    _set_hidden(p, True)
                record[norm(p)] = str(p)
                paths.append(p)
            except OSError as ex:
                log.warning(tr("無法建立誘餌檔 %s：%s", "Could not create canary file %s: %s"), p, ex)
    try:
        _canary_record_file().parent.mkdir(parents=True, exist_ok=True)
        _canary_record_file().write_text(json.dumps(sorted(record.values()), ensure_ascii=False, indent=2),
                                         encoding="utf-8")
    except OSError as ex:  # test mode without administrator rights
        log.warning(tr("無法記錄誘餌檔：%s", "Could not record the canary files: %s"), ex)
    return paths


def changed_canary(canaries):
    """(path, what happened to it) of the first canary file that is not intact; None if all are fine."""
    for p in canaries:
        try:
            if not canary_intact(p, winapi.read_shared(p)):
                return p, tr(f"誘餌檔內容被修改：{p}", f"Canary file was modified: {p}")
        except FileNotFoundError:
            if not Path(p).parent.is_dir():
                continue  # the whole folder is gone (e.g. OneDrive was unlinked), not an attack on the file
            return p, tr(f"誘餌檔不見了：{p}", f"Canary file is missing: {p}")
        except OSError:
            pass  # temporarily locked (e.g. antivirus is scanning); check again next time
    return None


def check_canaries(canaries):
    """Describe the first canary file that is not intact; None if all are fine."""
    found = changed_canary(canaries)
    return found[1] if found else None


def remove_canaries(only_in=None):
    """Delete the canary files this program recorded (only_in: just those inside these folders), and those of
    older versions; the monitor creates fresh ones when it restarts (so they aren't mistaken for "changed
    while the program was not running")."""
    keep = []
    for p in canary_record():
        if os.path.basename(p) not in CANARY_NAMES:  # whatever the record says, only canary names are deleted
            continue
        if only_in is not None and not any(norm(p).startswith(norm(d) + os.sep) for d in only_in):
            keep.append(p)
            continue
        try:
            Path(p).unlink(missing_ok=True)  # works on hidden files too
        except OSError as ex:
            keep.append(p)
            log.warning(tr("無法刪除誘餌檔 %s：%s", "Could not delete canary file %s: %s"), p, ex)
    try:
        if keep:
            _canary_record_file().write_text(json.dumps(keep, ensure_ascii=False, indent=2), encoding="utf-8")
        else:
            _canary_record_file().unlink(missing_ok=True)
    except OSError:
        pass
    if only_in is None:
        remove_legacy_canaries()


def remove_legacy_canaries():
    """Delete the visible canary files of versions before 1.7.5 (Documents and Pictures)."""
    for d in (winapi._known_folder("Documents"), winapi._known_folder("Pictures")):
        for name in LEGACY_CANARY_NAMES:
            try:
                (d / name).unlink(missing_ok=True)
            except OSError as ex:
                log.warning(tr("無法刪除誘餌檔 %s：%s", "Could not delete canary file %s: %s"), d / name, ex)
