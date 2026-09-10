from pathlib import Path
import tempfile
import unittest

from scripts.check_docs import check_documents
from scripts.new_session import ROOT, TEMPLATES, create_session


class NotebookTests(unittest.TestCase):
    def test_creates_templates_and_evidence_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = create_session(Path(tmp) / "laboratoire privé")
            for name in TEMPLATES:
                self.assertEqual((dest / name).read_bytes(), (ROOT / "templates" / name).read_bytes())
            for name in ("scans", "evidence", "files", "notes"):
                self.assertTrue((dest / name).is_dir())

    def test_refuses_to_overwrite_notes(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = create_session(Path(tmp) / "lab")
            note = dest / "machine.md"
            note.write_text("My evidence", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                create_session(dest)
            self.assertEqual(note.read_text(encoding="utf-8"), "My evidence")

    def test_refuses_existing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "file"
            dest.touch()
            with self.assertRaises(FileExistsError):
                create_session(dest)

    def test_refuses_repository_destination(self):
        with self.assertRaises(ValueError):
            create_session(ROOT / "private-test-session")


class DocumentationTests(unittest.TestCase):
    def test_missing_local_link_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "README.md").write_text("[Missing](docs/missing.md#section)", encoding="utf-8")
            self.assertEqual(len(check_documents(root)), 1)

    def test_fences_inline_code_external_urls_and_anchors_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "README.md").write_text(
                "```sh\n[fake](no.md)\n```\n~~~\n[fake](no2.md)\n~~~\n"
                "`[fake](no3.md)`\n[web](https://example.org/a)\n[section](#here)\n", encoding="utf-8")
            self.assertEqual(check_documents(root), [])

    def test_relative_encoded_and_angle_bracket_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "docs").mkdir()
            (root / "docs" / "a file.md").write_text("[Home](../README.md)", encoding="utf-8")
            (root / "README.md").write_text(
                "[one](docs/a%20file.md#heading)\n[two](<docs/a file.md>)", encoding="utf-8")
            self.assertEqual(check_documents(root), [])

    def test_link_outside_repository_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "README.md").write_text("[outside](../outside.md)", encoding="utf-8")
            self.assertIn("escapes repository", check_documents(root)[0])


if __name__ == "__main__":
    unittest.main()
