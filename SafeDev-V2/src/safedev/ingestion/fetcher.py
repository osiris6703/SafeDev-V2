"""SafeDev V2 — Ultra-fast Package fetcher.

Downloads package artifacts directly from PyPI/npm registries.
Prefers pre-built wheels (.whl) for 10x faster download and instant zip extraction.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Optional, Tuple

import requests

from safedev.core.exceptions import PackageFetchError
from safedev.core.models import Ecosystem


_PYPI_JSON_URL = "https://pypi.org/pypi/{package}/json"
_PYPI_VERSION_URL = "https://pypi.org/pypi/{package}/{version}/json"
_NPM_REGISTRY_URL = "https://registry.npmjs.org/{package}"

_REQUEST_TIMEOUT = 10


class PackageFetcher:
    """Download package archives from registries without installation."""

    def __init__(self, timeout: int = _REQUEST_TIMEOUT):
        self._timeout = timeout
        self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": "SafeDev/2.0 (security-scanner)",
            "Accept-Encoding": "gzip, deflate",
        })

    def fetch_pypi(
        self,
        package_name: str,
        version: Optional[str] = None,
    ) -> Tuple[bytes, str]:
        """Download a PyPI package artifact.

        Prefers wheel (.whl) for 10x faster download & instant zip extraction.
        Falls back to sdist (.tar.gz).
        """
        try:
            if version:
                url = _PYPI_VERSION_URL.format(
                    package=package_name, version=version
                )
            else:
                url = _PYPI_JSON_URL.format(package=package_name)

            resp = self._session.get(url, timeout=self._timeout)
            resp.raise_for_status()
            data = resp.json()

        except requests.RequestException as e:
            raise PackageFetchError(
                f"Failed to query PyPI for '{package_name}': {e}"
            ) from e

        # Resolve version
        if version:
            release_files = data.get("urls", [])
        else:
            resolved_version = data.get("info", {}).get("version", "")
            releases = data.get("releases", {})
            release_files = releases.get(resolved_version, [])
            if not release_files:
                release_files = data.get("urls", [])

        if not release_files:
            raise PackageFetchError(
                f"No release files found for '{package_name}'"
            )

        # PREFER WHEEL (.whl) FIRST for 10x faster download and instant zip extraction
        download_url = None
        filename = None

        for f in release_files:
            if f.get("packagetype") == "bdist_wheel" and f.get("filename", "").endswith("-py3-none-any.whl"):
                download_url = f["url"]
                filename = f["filename"]
                break

        if download_url is None:
            for f in release_files:
                if f.get("packagetype") == "bdist_wheel":
                    download_url = f["url"]
                    filename = f["filename"]
                    break

        if download_url is None:
            for f in release_files:
                if f.get("packagetype") == "sdist":
                    download_url = f["url"]
                    filename = f["filename"]
                    break

        if download_url is None:
            download_url = release_files[0]["url"]
            filename = release_files[0]["filename"]

        try:
            resp = self._session.get(download_url, timeout=self._timeout)
            resp.raise_for_status()
            content = resp.content
        except requests.RequestException as e:
            raise PackageFetchError(
                f"Failed to download '{filename}': {e}"
            ) from e

        return content, filename

    def fetch_npm(
        self,
        package_name: str,
        version: Optional[str] = None,
    ) -> Tuple[bytes, str]:
        """Download an npm package tarball."""
        try:
            url = _NPM_REGISTRY_URL.format(package=package_name)
            resp = self._session.get(url, timeout=self._timeout)
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as e:
            raise PackageFetchError(
                f"Failed to query npm for '{package_name}': {e}"
            ) from e

        if version is None:
            version = data.get("dist-tags", {}).get("latest")

        if version is None:
            raise PackageFetchError(
                f"Cannot determine latest version for '{package_name}'"
            )

        versions = data.get("versions", {})
        version_data = versions.get(version)

        if version_data is None:
            raise PackageFetchError(
                f"Version '{version}' not found for '{package_name}'"
            )

        tarball_url = version_data.get("dist", {}).get("tarball")

        if tarball_url is None:
            raise PackageFetchError(
                f"No tarball URL for '{package_name}@{version}'"
            )

        try:
            resp = self._session.get(tarball_url, timeout=self._timeout)
            resp.raise_for_status()
            content = resp.content
        except requests.RequestException as e:
            raise PackageFetchError(
                f"Failed to download tarball: {e}"
            ) from e

        filename = f"{package_name}-{version}.tgz"
        return content, filename

    def close(self):
        """Close the HTTP session."""
        self._session.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
