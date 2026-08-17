"""Tests for safe archive reader (zip-slip, bomb, symlink protection)."""

import io
import tarfile
import zipfile
import pytest

from safedev.ingestion.archive import SafeArchiveReader, ArchiveSafetyError
from safedev.core.config import SafetyLimits


def test_safe_path_traversal():
    reader = SafeArchiveReader()
    assert reader._safe_path("foo/bar.py") is True
    assert reader._safe_path("../etc/passwd") is False
    assert reader._safe_path("foo/../../bar.py") is False


def test_zip_extraction_limits():
    limits = SafetyLimits(max_files_per_package=2, max_single_file_bytes=100)
    reader = SafeArchiveReader(limits=limits)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("a.py", b"print('hello')")
        z.writestr("b.py", b"print('world')")
        z.writestr("c.py", b"print('excess')")

    members = reader.read_archive(buf.getvalue(), "test.zip")
    assert len(members) == 2
    names = [name for name, _ in members]
    assert "a.py" in names
    assert "b.py" in names
    assert "c.py" not in names
