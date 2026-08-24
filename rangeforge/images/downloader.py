"""Streaming HTTPS transport for trusted manifest URLs."""

from __future__ import annotations

import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Protocol
from urllib.parse import urlparse

from rangeforge import __version__

ProgressCallback = Callable[[int, int | None], None]


class ImageDownloadError(OSError):
    """Raised when a trusted image transfer cannot complete."""


class ImageDownloader(Protocol):
    def download(
        self,
        url: str,
        destination: Path,
        progress: ProgressCallback | None = None,
    ) -> None: ...


class HTTPSImageDownloader:
    def download(
        self,
        url: str,
        destination: Path,
        progress: ProgressCallback | None = None,
    ) -> None:
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ImageDownloadError("Trusted image downloads require an HTTPS URL.")
        request = urllib.request.Request(
            url,
            headers={"User-Agent": f"RangeForge/{__version__}"},
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                length = response.headers.get("Content-Length")
                total = int(length) if length and length.isdigit() else None
                downloaded = 0
                with destination.open("wb") as output:
                    while chunk := response.read(1024 * 1024):
                        output.write(chunk)
                        downloaded += len(chunk)
                        if progress:
                            progress(downloaded, total)
        except (OSError, urllib.error.URLError) as exc:
            raise ImageDownloadError(f"Image download failed: {exc}") from exc
