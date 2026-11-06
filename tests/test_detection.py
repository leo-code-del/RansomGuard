"""Tests: telling encryption from everyday work: broken files, file ends, extensions, ransom notes, the file-event handler and canary files. Shared helpers and the safety net are in support.py."""
import base64
import hashlib
import io
import os
import time
import unittest
from pathlib import Path
from unittest import mock

from watchdog.events import FileCreatedEvent, FileDeletedEvent, FileModifiedEvent, FileMovedEvent

import support
from support import OLE_HEAD, TempDirTest, ZIP_HEAD, encrypt_end, overwrite, random_bytes, real_pdf, real_zip, rg

setUpModule, tearDownModule = support.setUpModule, support.tearDownModule  # the safety net


# ---------------------------------------------------------------- broken files
class BrokenFileTests(TempDirTest):
    def test_valid_files_are_not_broken(self):
        cases = {
            "a.docx": ZIP_HEAD + random_bytes(),
            "b.pdf": b"%PDF-1.7\n" + random_bytes(),
            "c.jpg": b"\xff\xd8\xff\xe0" + random_bytes(),
            "d.png": b"\x89PNG\r\n\x1a\n" + random_bytes(),
            "e.mp4": b"\x00\x00\x00\x20ftypisom" + random_bytes(),
            "f.zip": ZIP_HEAD + random_bytes(),
        }
        for name, data in cases.items():
            self.assertIsNone(rg.broken_reason(self.file(name, data)), name)

    def test_encrypted_files_are_broken(self):
        for name in ("a.docx", "b.pdf", "c.jpg", "d.png", "e.xlsx", "f.mp4", "g.zip"):
            self.assertIsNotNone(rg.broken_reason(self.file(name, random_bytes())), name)

    def test_header_overwritten_but_rest_intact_is_broken(self):
        data = os.urandom(16) + random_bytes()
        self.assertIsNotNone(rg.broken_reason(self.file("a.docx", data)))

    def test_misnamed_but_real_files_are_not_broken(self):
        cases = {
            "webp_named.jpg": b"RIFF\x00\x00\x00\x00WEBPVP8 " + random_bytes(),
            "png_named.jpg": b"\x89PNG\r\n\x1a\n" + random_bytes(),
            "html_export.xls": b"<html><body><table>" + b"<tr><td>1</td><td>2</td></tr>" * 300,
            "rtf_saved.doc": b"{\\rtf1\\ansi " + b"hello world " * 400,
            "password_protected.docx": OLE_HEAD + random_bytes(),
            "password_protected.xlsx": OLE_HEAD + random_bytes(),
            "id3_tagged.flac": b"ID3\x04\x00\x00" + random_bytes(),
            "big.wav": b"RF64\xff\xff\xff\xffWAVE" + random_bytes(),
            "fragment.mp4": b"\x00\x00\x00\x18stypmsdh" + random_bytes(),
            "csv_export.xls": b"date,amount,memo\n" + b"2026-01-01,100,coffee\n" * 300,
        }
        for name, data in cases.items():
            self.assertIsNone(rg.broken_reason(self.file(name, data)), name)

    def test_git_lfs_pointer_is_not_broken(self):
        pointer = (b"version https://git-lfs.github.com/spec/v1\n"
                   b"oid sha256:4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d17e2393\n"
                   b"size 12345\n")
        for name in ("logo.png", "photo.jpg", "doc.pdf"):
            self.assertIsNone(rg.broken_reason(self.file(name, pointer)), name)

    def test_text_files(self):
        self.assertIsNotNone(rg.broken_reason(self.file("notes.txt", random_bytes(8192))))
        self.assertIsNone(rg.broken_reason(self.file("small.txt", random_bytes(1000))))
        b64 = base64.b64encode(random_bytes(9000))
        self.assertIsNone(rg.broken_reason(self.file("embedded.svg", b"<svg>" + b64 + b"</svg>")))
        self.assertIsNone(rg.broken_reason(self.file("code.py", b"print('hello')\n" * 1000)))

    def test_mpeg_ts_video_is_not_typescript(self):
        packet = b"\x47" + random_bytes(187)
        self.assertIsNone(rg.broken_reason(self.file("clip.ts", packet * 50)))

    def test_empty_zero_and_unknown_files(self):
        self.assertIsNone(rg.broken_reason(self.file("empty.docx", b"")))
        self.assertIsNone(rg.broken_reason(self.file("zeros.mp4", b"\0" * 100000)))
        self.assertIsNone(rg.broken_reason(self.file("data.bin", random_bytes())))
        self.assertIsNone(rg.broken_reason(str(self.dir / "missing.docx")))

    def test_more_kinds_of_files_people_keep(self):
        # camera RAW photos, mailboxes, password databases, Access databases: real ones pass, encrypted ones don't
        real = {"IMG_0001.cr2": b"II*\x00\x10\x00\x00\x00CR\x02\x00", "DSC_0001.nef": b"MM\x00*\x00\x00\x00\x08",
                "P1000001.rw2": b"IIU\x00\x18\x00\x00\x00", "DSCF0001.raf": b"FUJIFILMCCD-RAW 0201",
                "IMG_0001.cr3": b"\x00\x00\x00\x18ftypcrx ", "Outlook.pst": b"!BDN\x00\x00\x00\x00",
                "Passwords.kdbx": b"\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5", "Shop.accdb": b"\x00\x01\x00\x00Standard ACE DB\x00",
                "Mail.msg": OLE_HEAD}
        for name, head in real.items():
            self.assertIsNone(rg.broken_reason(self.file(name, head + random_bytes())), name)
            self.assertIsNotNone(rg.broken_reason(self.file("enc_" + name, random_bytes())), name)

    def test_text_encrypted_after_its_start_is_broken(self):
        text = b"2026-11-04 10:00:00 meeting notes and plans\n" * 800  # ~35 KB
        self.assertIsNone(rg.broken_reason(self.file("notes.txt", text)))
        self.assertIsNotNone(rg.broken_reason(self.file("partly.txt", text[:20000] + random_bytes(16000))))


class EndOfFileTests(TempDirTest):
    """Partial encryption that leaves the header alone: the structure at the end of ZIP-based files and PDFs."""

    def test_intact_files_pass(self):
        for name, data in {"a.docx": real_zip(), "b.xlsx": real_zip(200000), "c.pdf": real_pdf(),
                           "commented.zip": real_zip(comment=b"x" * 10000), "tiny.zip": real_zip(10)}.items():
            self.assertIsNone(rg.damaged_end(self.file(name, data)), name)

    def test_encrypted_end_is_found(self):
        for name, data in {"a.docx": real_zip(), "b.pptx": real_zip(300000), "c.pdf": real_pdf(50000)}.items():
            p = self.file(name, data)
            encrypt_end(p)
            self.assertIsNotNone(rg.damaged_end(p), name)
            self.assertIsNone(rg.broken_reason(p), "the header is intact, so only the end gives it away")

    def test_encrypted_middle_that_reaches_the_zip_directory_is_found(self):
        import zipfile
        data = real_zip(300000)
        eocd = data.rfind(b"PK\x05\x06")
        cd = zipfile.ZipFile(io.BytesIO(data)).start_dir
        p = self.file("big.docx", data[:cd] + os.urandom(eocd - cd) + data[eocd:])  # the end record survives
        self.assertIsNotNone(rg.damaged_end(p))

    def test_intermittent_encryption_that_spares_the_end_is_found(self):
        import zipfile
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:  # an Office file: many parts, each with its own header
            for k in range(12):
                z.writestr(f"word/media/image{k}.jpeg", b"\xff\xd8\xff\xe0" + os.urandom(40000))
        data = bytearray(buf.getvalue())
        self.assertIsNone(rg.damaged_end(self.file("intact.pptx", bytes(data))))
        for k in range(65536, len(data) - 4096, 65536):  # 16 KB of every 64 KB; header and end untouched
            data[k:k + 16384] = os.urandom(16384)
        self.assertIsNotNone(rg.damaged_end(self.file("blocks.pptx", bytes(data[:len(data)]))))
        empty = io.BytesIO()
        zipfile.ZipFile(empty, "w").close()
        self.assertIsNone(rg.damaged_end(self.file("empty.zip", empty.getvalue())))

    def test_unfinished_or_reserved_files_are_no_alarm(self):
        self.assertIsNone(rg.damaged_end(self.file("reserved.zip", b"PK\x03\x04" + b"\0" * 100000)))
        self.assertIsNone(rg.damaged_end(self.file("cut_in_text.pdf", b"%PDF-1.4\n" + b"1 0 obj << >> endobj\n" * 500)))
        self.assertIsNone(rg.damaged_end(self.file("other.jpg", b"\xff\xd8\xff\xe0" + random_bytes())))
        self.assertIsNone(rg.damaged_end(self.file("password.docx", OLE_HEAD + random_bytes())))
        self.assertIsNone(rg.damaged_end(str(self.dir / "missing.docx")))

    def test_unknown_files_that_look_encrypted(self):
        self.assertTrue(rg.looks_encrypted(self.file("a8Fk2.b3c1", random_bytes())))
        self.assertFalse(rg.looks_encrypted(self.file("small.b3c1", random_bytes(500))))
        self.assertFalse(rg.looks_encrypted(self.file("zeros.b3c1", b"\0" * 8192)))
        self.assertFalse(rg.looks_encrypted(self.file("zipped.pak", real_zip())))
        self.assertFalse(rg.looks_encrypted(self.file("notes.xyz", b"plain text\n" * 1000)))

    def test_a_file_being_written_by_another_program(self):
        p = self.file("copying.docx", b"PK\x03\x04")
        with open(p, "ab") as f:
            f.write(random_bytes())
            self.assertTrue(rg.being_written(p))
        self.assertFalse(rg.being_written(p))
        self.assertFalse(rg.being_written(str(self.dir / "missing.docx")))


# ---------------------------------------------------------------- extensions
class ExtensionTests(unittest.TestCase):
    def test_ransomware_renames_are_suspicious(self):
        self.assertTrue(rg.suspicious_ext("moved", r"C:\d\report.docx", r"C:\d\report.docx.locked"))
        self.assertTrue(rg.suspicious_ext("moved", r"C:\d\photo.jpg", r"C:\d\photo.jpg.id-8F2A.[mail@x.cc].eking"))
        self.assertTrue(rg.suspicious_ext("moved", r"C:\d\a.pdf", r"C:\d\a.pdf.encrypted"))
        self.assertTrue(rg.suspicious_ext("created", r"C:\d\budget.xlsx.crypt", ""))
        self.assertTrue(rg.suspicious_ext("moved", r"C:\d\a.txt", r"C:\d\a.wncry"))
        # letters appended straight onto the extension, with no separating dot
        self.assertTrue(rg.suspicious_ext("moved", r"C:\d\photo.jpg", r"C:\d\photo.jpgcrypt"))
        self.assertTrue(rg.suspicious_ext("moved", r"C:\d\note.txt", r"C:\d\note.txtlocked"))

    def test_everyday_names_are_not_suspicious(self):
        benign_created = [
            r"C:\proj\dist\main.js.map", r"C:\proj\dist\style.css.map", r"C:\proj\dist\index.d.ts.map",
            r"C:\dl\movie.mkv.!qB", r"C:\dl\song.mp3.!ut", r"C:\dl\file.zip.aria2",
            r"C:\dl\backup.zip.001", r"C:\dl\backup.7z.002", r"C:\dl\big.rar.r00",
            r"C:\proj\app.py.orig", r"C:\proj\app.c.rej", r"C:\proj\.app.py.swp",
            r"C:\proj\data.tar.zst", r"C:\proj\__snapshots__\a.test.ts.snap",
            r"C:\dl\setup.zip.sha256", r"C:\dl\iso.iso.sha512", r"C:\dl\file.pdf.crdownload",
            r"C:\proj\report.docx", r"C:\proj\x.tar.gz",
        ]
        for p in benign_created:
            self.assertFalse(rg.suspicious_ext("created", p, ""), p)
        benign_moved = [
            (r"C:\dl\a.zip.crdownload", r"C:\dl\a.zip"),
            (r"C:\pics\a.jpg", r"C:\pics\a.jpg_original"),  # exiftool keeps the original this way
            (r"C:\d\a.docx", r"C:\d\a.pdf"),
            (r"C:\d\a.docx", r"C:\d\a"),
            (r"C:\d\a.JPG", r"C:\d\a.jpg"),
            (r"C:\d\a.txt", r"C:\d\a.txt.bak"),
        ]
        for s, d in benign_moved:
            self.assertFalse(rg.suspicious_ext("moved", s, d), f"{s} -> {d}")


# ---------------------------------------------------------------- ransom notes
class RansomNoteTests(unittest.TestCase):
    def test_ransom_notes(self):
        for n in ("HOW_TO_DECRYPT.txt", "README_RANSOM.html", "如何解密.txt", "RESTORE_MY_FILES.hta",
                  "!!!_HOW_TO_RECOVER_FILES_!!!.txt", "YOUR_FILES_ARE_ENCRYPTED.html", "解密說明.txt",
                  "decrypt_instructions.png", "restore-your-files.url"):
            self.assertTrue(rg.is_ransom_note(n), n)

    def test_not_ransom_notes(self):
        for n in ("RansomGuard.exe", "RansomGuard.lnk", "RansomGuard.exe - Shortcut.lnk", "RansomGuard (1).exe",
                  "ransom_guard.py", "decrypt.py", "aes_decrypt.c", "Encrypt_Decrypt_Lab.pdf",
                  "test_decrypt.js", "decrypt_utils.java", "ransomware_report.docx", "report.docx"):
            self.assertFalse(rg.is_ransom_note(n), n)


class HandlerTests(TempDirTest):
    def setUp(self):
        super().setUp()
        (self.dir / "docs").mkdir()
        self.canaries = rg.plant_canaries([self.dir / "docs"])
        self.fired = []
        self.h = rg.make_handler(self.canaries, self.fired.append, dry_run=True)

    def test_canaries_are_planted(self):
        self.assertEqual(sorted(p.name for p in self.canaries), sorted(rg.CANARY_NAMES))
        self.assertTrue(all(p.read_bytes() == rg.canary_bytes(p) for p in self.canaries))
        self.assertEqual({p.read_bytes()[:4] for p in self.canaries}, {b"PK\x03\x04"})
        self.assertTrue(all(os.stat(p).st_file_attributes & 0x2 for p in self.canaries), "canaries are hidden")
        self.assertFalse([n for n in rg.CANARY_NAMES if "canary" in n.lower()], "names don't give them away")
        self.assertTrue({rg.norm(p) for p in self.canaries} <= {rg.norm(p) for p in rg.canary_record()})

    def test_a_users_own_file_with_a_canary_name_is_never_touched(self):
        mine = self.dir / "mine"
        mine.mkdir()
        own = mine / rg.CANARY_NAMES[1]
        own.write_bytes(b"my real budget")
        planted = rg.plant_canaries([mine])
        self.assertEqual(own.read_bytes(), b"my real budget")
        self.assertNotIn(rg.norm(own), {rg.norm(p) for p in planted})
        self.assertNotIn(rg.norm(own), {rg.norm(p) for p in rg.canary_record()})
        rg.remove_canaries(only_in=[mine])
        self.assertEqual(own.read_bytes(), b"my real budget", "and never deleted")
        self.assertEqual(sorted(p.name for p in mine.iterdir()), [rg.CANARY_NAMES[1]])

    def test_canary_deleted(self):
        self.h.on_any_event(FileDeletedEvent(str(self.canaries[0])))
        self.assertEqual(len(self.fired), 1)

    def test_canary_moved(self):
        self.h.on_any_event(FileMovedEvent(str(self.canaries[0]), str(self.dir / "x.docx")))
        self.assertEqual(len(self.fired), 1)

    def test_canary_modified(self):
        c = self.canaries[0]
        self.h.on_any_event(FileModifiedEvent(str(c)))  # same content (e.g. metadata change): no trigger
        self.assertEqual(self.fired, [])
        overwrite(c, random_bytes())
        self.h.on_any_event(FileModifiedEvent(str(c)))
        self.assertEqual(len(self.fired), 1)

    def test_canary_overwritten_by_move(self):
        self.h.on_any_event(FileMovedEvent(str(self.dir / "other.docx"), str(self.canaries[1])))
        self.assertEqual(len(self.fired), 1)

    def test_canary_check_finds_missing_or_changed(self):
        self.assertIsNone(rg.check_canaries(self.canaries))
        self.canaries[0].unlink()
        self.assertIn("missing", rg.check_canaries(self.canaries))

    def test_broken_file_threshold(self):
        for i in range(rg.BROKEN_THRESHOLD - 1):
            self.h.on_any_event(FileModifiedEvent(self.file(f"f{i}.docx", random_bytes())))
        self.assertEqual(self.fired, [])
        self.h.on_any_event(FileModifiedEvent(self.file("last.docx", random_bytes())))
        self.assertEqual(len(self.fired), 1)

    def test_the_evidence_is_kept_when_it_triggers(self):
        paths = [self.file(f"Report {i}.docx", random_bytes()) for i in range(rg.BROKEN_THRESHOLD)]
        for p in paths:
            self.h.on_any_event(FileModifiedEvent(p))
        self.assertEqual(len(self.fired), 1)
        self.assertEqual(self.h.last_files, paths, "the files as they are named, most recent last")

    def test_same_file_many_events_counts_once(self):
        p = self.file("one.docx", random_bytes())
        for _ in range(50):
            self.h.on_any_event(FileModifiedEvent(p))
        self.assertEqual(self.fired, [])

    def test_extension_threshold(self):
        for i in range(rg.EXT_CHANGE_THRESHOLD - 1):
            self.h.on_any_event(FileMovedEvent(f"{self.dir}\\r{i}.docx", f"{self.dir}\\r{i}.docx.locked"))
        self.assertEqual(self.fired, [])
        self.h.on_any_event(FileMovedEvent(f"{self.dir}\\z.docx", f"{self.dir}\\z.docx.locked"))
        self.assertEqual(len(self.fired), 1)

    def test_temporary_files_of_saves_are_not_counted(self):
        # editors and tools save through "name.ext.tmp.<pid>.<random>" or "name.ext.<number>" and rename it at once
        # (this cut the network on 2026-11-04 while README files were edited in a watched folder)
        for i in range(30):
            for tmp in (f"notes{i}.md.tmp.1724.{os.urandom(6).hex()}", f"package{i}.json.{2348927342 + i}"):
                p = self.file(tmp, b"text")
                self.h.on_any_event(FileCreatedEvent(p))
                self.h.on_any_event(FileMovedEvent(p, p.split(".")[0] + "." + tmp.split(".")[1]))
            p = self.file(f"draft{i}.txt.{os.urandom(4).hex()}", b"text")  # written, then deleted
            self.h.on_any_event(FileCreatedEvent(p))
            self.h.on_any_event(FileDeletedEvent(p))
        self.assertEqual(self.fired, [])
        for i in range(rg.EXT_CHANGE_THRESHOLD):  # files that stay under their new names still count
            self.h.on_any_event(FileCreatedEvent(self.file(f"report{i}.docx.{os.urandom(6).hex()}", b"x")))
        self.assertEqual(len(self.fired), 1)

    def test_ransom_notes_need_several_folders(self):
        for _ in range(5):  # many notes in one folder: still one folder
            self.h.on_any_event(FileCreatedEvent(self.file("a/HOW_TO_DECRYPT.txt", b"pay")))
        self.h.on_any_event(FileCreatedEvent(self.file("b/HOW_TO_DECRYPT.txt", b"pay")))
        self.assertEqual(self.fired, [])
        self.h.on_any_event(FileCreatedEvent(self.file("c/HOW_TO_DECRYPT.txt", b"pay")))
        self.assertEqual(len(self.fired), 1)

    def test_window_expires(self):
        now = [1000.0]
        with mock.patch.object(rg.time, "time", lambda: now[0]):
            for i in range(rg.BROKEN_THRESHOLD - 1):
                self.h.on_any_event(FileModifiedEvent(self.file(f"old{i}.docx", random_bytes())))
            now[0] += rg.WINDOW_SEC + 1
            self.h.on_any_event(FileModifiedEvent(self.file("new.docx", random_bytes())))
        self.assertEqual(self.fired, [])

    def test_repeated_events_for_an_unchanged_file_read_it_once(self):
        p = self.file("notes.txt", b"plain text\n" * 1000)
        reads = []
        real = rg.broken_reason
        with mock.patch.object(rg, "broken_reason", lambda path, st=None: reads.append(path) or real(path, st)):
            for _ in range(3):  # Windows usually reports a save two or three times
                self.h.on_any_event(FileModifiedEvent(p))
            self.assertEqual(len(reads), 1)
            Path(p).write_bytes(random_bytes())  # really changed: checked again right away
            self.h.on_any_event(FileModifiedEvent(p))
            self.assertEqual(len(reads), 2)
            with mock.patch.object(rg, "RECHECK_SEC", 0):  # and an unchanged file is read again later
                self.h.on_any_event(FileModifiedEvent(p))
            self.assertEqual(len(reads), 3)

    def wait_for(self, cond, timeout=10):
        end = time.time() + timeout
        while time.time() < end and not cond():
            time.sleep(0.05)

    def test_documents_encrypted_only_at_the_end_are_caught_once_settled(self):
        self.patch("SETTLE_SEC", 0.2)
        docs = [self.file(f"doc{i}.docx", real_zip()) for i in range(rg.BROKEN_THRESHOLD)]
        for p in docs:
            self.h.on_any_event(FileModifiedEvent(p))
        time.sleep(1)
        self.assertEqual(self.fired, [], "intact documents counted")
        for p in docs:
            encrypt_end(p)
            self.h.on_any_event(FileModifiedEvent(p))
        self.assertEqual(self.fired, [], "judged before the files were left alone")
        self.wait_for(lambda: self.fired)
        self.assertIn("files that look encrypted", self.fired[0])

    def test_a_document_still_being_copied_is_judged_when_complete(self):
        self.patch("SETTLE_SEC", 0.2)
        data = real_zip(100000)
        p = self.file("copy.docx", b"")
        with open(p, "wb") as f:  # half copied: header, but no end yet
            f.write(data[:50000])
            f.flush()
            self.h.on_any_event(FileModifiedEvent(p))
            time.sleep(1)
            self.assertEqual(len(self.h.broken), 0, "a file being copied was judged by its missing end")
            f.write(data[50000:])
        self.h.on_any_event(FileModifiedEvent(p))
        time.sleep(1)
        self.assertEqual(len(self.h.broken), 0)

    def test_encrypted_copies_that_replace_deleted_originals_are_caught(self):
        n = rg.BROKEN_THRESHOLD
        originals = [self.file(f"photo{i}.jpg", b"\xff\xd8\xff\xe0" + random_bytes()) for i in range(n)]
        for i, p in enumerate(originals):
            copy = self.file(f"{os.urandom(5).hex()}.b3c1", random_bytes())  # random name and extension
            if i % 2:  # either order
                self.h.on_any_event(FileCreatedEvent(copy))
                os.remove(p)
                self.h.on_any_event(FileDeletedEvent(p))
            else:
                os.remove(p)
                self.h.on_any_event(FileDeletedEvent(p))
                self.h.on_any_event(FileCreatedEvent(copy))
        self.assertEqual(len(self.fired), 1, "copy-and-delete was not caught")

    def test_deleting_files_while_other_files_appear_is_no_alarm(self):
        a, b = self.dir / "a", self.dir / "b"
        for i in range(20):  # deleted in one folder, compressed files of unknown types arrive in another
            p = self.file(f"a/old{i}.pdf", real_pdf())
            os.remove(p)
            self.h.on_any_event(FileDeletedEvent(p))
            self.h.on_any_event(FileCreatedEvent(self.file(f"b/pack{i}.bin", random_bytes())))
        with mock.patch.object(rg, "PAIR_SEC", 0.5):  # files deleted a while before others arrive: no pairs
            time.sleep(0.6)
            for i in range(20):
                self.h.on_any_event(FileCreatedEvent(self.file(f"a/mod{i}.pak", random_bytes())))
        p = self.file("a/one.docx", real_zip())  # one deleted, many new ones: pairs one
        os.remove(p)
        self.h.on_any_event(FileDeletedEvent(p))
        for i in range(20):
            self.h.on_any_event(FileCreatedEvent(self.file(f"a/save{i}.dat", random_bytes())))
        for i in range(20):  # deleted and replaced by new files that aren't encrypted
            p = self.file(f"c/doc{i}.docx", real_zip())
            os.remove(p)
            self.h.on_any_event(FileDeletedEvent(p))
            self.h.on_any_event(FileCreatedEvent(self.file(f"c/doc{i}.converted", b"text " * 500)))
        self.assertEqual(self.fired, [])
        self.assertLessEqual(len(self.h.broken), 1)
        self.assertTrue(a.is_dir() and b.is_dir())

    def test_temp_and_office_lock_files_ignored(self):
        for i in range(20):
            self.h.on_any_event(FileModifiedEvent(self.file(f"~$doc{i}.docx", random_bytes())))
            self.h.on_any_event(FileModifiedEvent(self.file(f"dl{i}.zip.crdownload", random_bytes())))
        self.assertEqual(self.fired, [])

    def test_bad_event_does_not_crash(self):
        self.h.on_any_event(FileModifiedEvent(b"\xff\xfe-bytes-path"))  # undecodable bytes path
        self.h.on_any_event(FileModifiedEvent(""))
        self.assertEqual(self.fired, [])

    def test_canary_modified_while_not_running_is_reported_and_reset(self):
        c = self.canaries[0]
        overwrite(c, b"tampered")
        with mock.patch.object(rg, "alert") as alert:
            again = rg.plant_canaries([c.parent])
        alert.assert_called_once()
        self.assertEqual(Path(again[0]).read_bytes(), rg.canary_bytes(again[0]))

    def test_canary_files_are_real_office_files_that_never_change(self):
        import zipfile
        from xml.dom import minidom
        # the content must stay byte for byte the same in every version (and with every Python that builds it):
        # otherwise an update would report every installed canary file as modified
        self.assertEqual(hashlib.sha256(rg.CANARY_DOCX).hexdigest(),
                         "379c0bfee8db3ce62250e8c65ef5c37fdbc2726fc2382a99452eb6d1573c1e7b")
        self.assertEqual(hashlib.sha256(rg.CANARY_XLSX).hexdigest(),
                         "e3de85d72ecc82201c17ba04d12ac02cf23a865d09985b0d2f4f9b540441fc34")
        for data, main in ((rg.CANARY_DOCX, "word/document.xml"), (rg.CANARY_XLSX, "xl/worksheets/sheet1.xml")):
            z = zipfile.ZipFile(io.BytesIO(data))
            for part in z.namelist():
                minidom.parseString(z.read(part))
            self.assertIn("請直接關閉，不要修改", z.read(main).decode("utf-8"))
        self.assertEqual(rg.canary_bytes(r"C:\d\!!!_canary_do_not_delete.XLSX"), rg.CANARY_XLSX)
        self.assertEqual(rg.canary_bytes(r"C:\d\zzz_canary_do_not_delete.docx"), rg.CANARY_DOCX)

    def test_old_plain_text_canaries_are_accepted_then_upgraded(self):
        for c in self.canaries:
            overwrite(c, rg.LEGACY_CANARY_BYTES)
        self.assertIsNone(rg.check_canaries(self.canaries))
        self.h.on_any_event(FileModifiedEvent(str(self.canaries[0])))
        self.assertEqual(self.fired, [])
        with mock.patch.object(rg, "alert") as alert:
            rg.plant_canaries([self.dir / "docs"])  # test mode: another monitor may be watching, keep them
            self.assertEqual(self.canaries[0].read_bytes(), rg.LEGACY_CANARY_BYTES)
            rg.plant_canaries([self.dir / "docs"], upgrade=True)
        alert.assert_not_called()
        self.assertTrue(all(c.read_bytes() == rg.canary_bytes(c) for c in self.canaries))

    def test_remove_canaries_handles_recorded_and_legacy_ones(self):
        documents = self.dir / "Documents"
        documents.mkdir()
        for n in rg.LEGACY_CANARY_NAMES:  # the visible ones of versions before 1.7.5
            (documents / n).write_bytes(b"old")
        with mock.patch.object(rg, "_known_folder", lambda name: self.dir / name):
            rg.remove_canaries()
        self.assertEqual(list((self.dir / "docs").iterdir()), [])
        self.assertEqual(list(documents.iterdir()), [])
        self.assertEqual(rg.canary_record(), [])


# ---------------------------------------------------------------- end to end with a real file watcher
class EndToEndTests(TempDirTest):
    def watch(self):
        from watchdog.observers import Observer
        self.fired = []
        canaries = rg.plant_canaries([self.dir])
        h = rg.make_handler(canaries, self.fired.append, dry_run=True)
        obs = Observer()
        obs.schedule(h, str(self.dir), recursive=True)
        obs.start()
        self.addCleanup(lambda: (obs.stop(), obs.join()))
        time.sleep(0.5)
        return canaries

    def wait_for(self, cond, timeout=10):
        end = time.time() + timeout
        while time.time() < end and not cond():
            time.sleep(0.1)

    def test_simulated_ransomware_is_caught(self):
        self.watch()
        work = self.dir / "work"
        work.mkdir()
        for i in range(15):
            (work / f"doc{i}.docx").write_bytes(ZIP_HEAD + random_bytes())
        time.sleep(0.5)
        for i in range(15):  # encrypt in place, then rename like real ransomware does
            p = work / f"doc{i}.docx"
            p.write_bytes(random_bytes())
            p.rename(work / f"doc{i}.docx.locked")
        self.wait_for(lambda: self.fired)
        self.assertTrue(self.fired, "simulated ransomware was not detected")

    def test_deleting_a_canary_is_caught(self):
        canaries = self.watch()
        canaries[0].unlink()
        self.wait_for(lambda: self.fired)
        self.assertTrue(self.fired)

    def test_everyday_work_does_not_trigger(self):
        self.watch()
        photos, build, dl = self.dir / "photos", self.dir / "build", self.dir / "dl"
        for d in (photos, build, dl):
            d.mkdir()
        for i in range(150):  # copy a photo album
            (photos / f"IMG_{i:04}.jpg").write_bytes(b"\xff\xd8\xff\xe1" + random_bytes(20000))
        for i in range(40):  # a JS build with source maps
            (build / f"chunk{i}.js").write_text("console.log(1);\n" * 50)
            (build / f"chunk{i}.js.map").write_text('{"version":3,"sources":[]}')
        for i in range(12):  # torrent / multi-part downloads
            (dl / f"ep{i}.mkv.!qB").write_bytes(b"\x1a\x45\xdf\xa3" + random_bytes(4096))
            (dl / f"archive.zip.{i + 1:03}").write_bytes(random_bytes(4096))
        for i in range(12):  # browser downloads finishing
            p = dl / f"report{i}.pdf.crdownload"
            p.write_bytes(real_pdf(4096))
            p.rename(dl / f"report{i}.pdf")
        for i in range(10):  # web exports that are really HTML
            (dl / f"statement{i}.xls").write_text("<html><table>" + "<tr><td>1</td></tr>" * 400 + "</table></html>")
        docs = self.dir / "docs"
        docs.mkdir()
        for i in range(30):  # documents copied in, then saved Office-style (new file, old one deleted, renamed)
            (docs / f"report{i}.docx").write_bytes(real_zip(30000))
        for i in range(30):
            (docs / f"~WRD{i:04}.tmp").write_bytes(real_zip(30000))
            (docs / f"report{i}.docx").unlink()
            (docs / f"~WRD{i:04}.tmp").rename(docs / f"report{i}.docx")
        time.sleep(3 + rg.SETTLE_SEC)  # documents are judged by their end once left alone
        self.assertEqual(self.fired, [], self.fired[:1])


if __name__ == "__main__":
    unittest.main()
