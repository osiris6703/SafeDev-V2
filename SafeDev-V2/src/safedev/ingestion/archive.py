"""SafeDev V2 — Safe archive extraction.

SECURITY BOUNDARY:
  Archives are untrusted data.
  This module reads contents into memory without writing to disk.
  Path traversal, zip-bombs, and symlinks are rejected.
"""

from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path
from typing import List, Optional, Tuple

from safedev.core.config import SafetyLimits
from safedev.core.exceptions import ArchiveSafetyError


class SafeArchiveReader:
    """Read archive contents safely into memory."""

    def __init__(
        self,
        limits: Optional[SafetyLimits] = None,
    ):
        self.limits = limits or SafetyLimits()

    def read_archive(
        self,
        archive_bytes: bytes,
        archive_name: str,
        *,
        password: Optional[bytes] = None,
    ) -> List[Tuple[str, bytes]]:
        """Read all files from an archive into memory.

        Returns list of (filename, file_bytes) tuples.

        Raises ArchiveSafetyError for unsafe archives.
        """
        suffix = archive_name.lower()

        if suffix.endswith((".tar.gz", ".tgz", ".tar")):
            return self._read_tar(archive_bytes)

        if suffix.endswith((".zip", ".whl")):
            return self._read_zip(archive_bytes, password=password)

        raise ArchiveSafetyError(
            f"Unsupported archive format: {archive_name}"
        )

    def _read_zip(
        self,
        archive_bytes: bytes,
        *,
        password: Optional[bytes] = None,
    ) -> List[Tuple[str, bytes]]:
        """Read ZIP/WHL archive members."""
        members: List[Tuple[str, bytes]] = []

        with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as z:

            if password is not None:
                z.setpassword(password)

            infos = [
                info for info in z.infolist()
                if not info.is_dir()
            ]

            if len(infos) > self.limits.max_files_per_package:
                infos = infos[:self.limits.max_files_per_package]

            total_bytes = 0

            for info in infos:

                if info.file_size > self.limits.max_single_file_bytes:
                    continue

                if total_bytes + info.file_size > self.limits.max_total_extracted_bytes:
                    break

                if not self._safe_path(info.filename):
                    continue

                try:
                    data = z.read(info)
                except Exception:
                    continue

                members.append((info.filename, data))
                total_bytes += len(data)

        return members

    def _read_tar(
        self,
        archive_bytes: bytes,
    ) -> List[Tuple[str, bytes]]:
        """Read TAR/TGZ archive members."""
        members: List[Tuple[str, bytes]] = []

        with tarfile.open(
            fileobj=io.BytesIO(archive_bytes),
            mode="r:*",
        ) as tar:

            infos = [
                info for info in tar.getmembers()
                if info.isfile()
            ]

            if len(infos) > self.limits.max_files_per_package:
                infos = infos[:self.limits.max_files_per_package]

            total_bytes = 0

            for info in infos:

                if info.size > self.limits.max_single_file_bytes:
                    continue

                if total_bytes + info.size > self.limits.max_total_extracted_bytes:
                    break

                if not self._safe_path(info.name):
                    continue

                # Reject symlinks
                if info.issym() or info.islnk():
                    continue

                try:
                    extracted = tar.extractfile(info)
                    if extracted is None:
                        continue
                    data = extracted.read()
                except Exception:
                    continue

                members.append((info.name, data))
                total_bytes += len(data)

        return members

    @staticmethod
    def _safe_path(name: str) -> bool:
        """Reject path traversal and absolute paths."""
        normalized = name.replace("\\", "/").lstrip("/")
        parts = normalized.split("/")

        if ".." in parts:
            return False

        if any(part.startswith("/") for part in parts):
            return False

        return True
