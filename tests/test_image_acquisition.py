from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from rangeforge.host.models import Architecture
from rangeforge.images.cache import ImageCache
from rangeforge.images.downloader import ImageDownloadError, ProgressCallback
from rangeforge.images.manager import ImageManager, ImageManagerError
from rangeforge.images.models import (
    ArtifactFormat,
    ArtifactState,
    Checksum,
    ImageManifest,
    ImageOS,
    ImageSource,
    ImageSourceType,
)
from rangeforge.images.registry import ImageRegistry
from rangeforge.runtime.models import RuntimeType, VMBackend


def _manifest(content: bytes) -> ImageManifest:
    return ImageManifest(
        id="pull-test-arm64",
        os=ImageOS(family="linux", distribution="ubuntu", version="24.04"),
        architecture=Architecture.ARM64,
        runtimes=(RuntimeType.VM,),
        backends=(VMBackend.UTM,),
        source=ImageSource(
            type=ImageSourceType.OFFICIAL,
            vendor="fixture",
            artifact_format=ArtifactFormat.QCOW2,
            version="test",
            url="https://example.invalid/image.img",
            filename="image.img",
        ),
        checksum=Checksum(value=hashlib.sha256(content).hexdigest()),
    )


class FakeDownloader:
    def __init__(self, content: bytes, *, fail: bool = False) -> None:
        self.content = content
        self.fail = fail
        self.calls = 0
        self.destinations: list[Path] = []

    def download(
        self,
        url: str,
        destination: Path,
        progress: ProgressCallback | None = None,
    ) -> None:
        assert url.startswith("https://")
        assert destination.name.endswith(".partial")
        self.calls += 1
        self.destinations.append(destination)
        destination.write_bytes(self.content[:3])
        if self.fail:
            raise ImageDownloadError("simulated network failure")
        destination.write_bytes(self.content)
        if progress:
            progress(len(self.content), len(self.content))


def test_image_pull_state_transitions(tmp_path: Path) -> None:
    content = b"trusted fixture image"
    manifest = _manifest(content)
    states: list[ArtifactState] = []
    manager = ImageManager(
        ImageRegistry((manifest,)),
        ImageCache(tmp_path / "cache"),
        FakeDownloader(content),
    )
    result = manager.pull(manifest.id, state_callback=states.append)
    assert result.downloaded and not result.reused
    assert states == [
        ArtifactState.DOWNLOADING,
        ArtifactState.VERIFYING,
        ArtifactState.READY,
    ]
    assert manager.verify(manifest.id).valid


def test_invalid_download_checksum_is_rejected(tmp_path: Path) -> None:
    manifest = _manifest(b"expected")
    states: list[ArtifactState] = []
    manager = ImageManager(
        ImageRegistry((manifest,)),
        ImageCache(tmp_path / "cache"),
        FakeDownloader(b"corrupt"),
    )
    with pytest.raises(ImageManagerError, match="Checksum mismatch"):
        manager.pull(manifest.id, state_callback=states.append)
    assert not manager.cache.artifact_path(manifest).exists()
    assert not manager.cache.artifact_path(manifest).with_name("image.img.partial").exists()
    assert ArtifactState.INVALID in states
    assert states[-1] is ArtifactState.MISSING


def test_network_failure_removes_partial_file(tmp_path: Path) -> None:
    content = b"expected"
    manifest = _manifest(content)
    downloader = FakeDownloader(content, fail=True)
    manager = ImageManager(
        ImageRegistry((manifest,)), ImageCache(tmp_path / "cache"), downloader
    )
    with pytest.raises(ImageDownloadError, match="simulated"):
        manager.pull(manifest.id)
    assert downloader.destinations
    assert not downloader.destinations[0].exists()
    assert not manager.cache.artifact_path(manifest).exists()


def test_existing_partial_file_is_safely_replaced(tmp_path: Path) -> None:
    content = b"expected"
    manifest = _manifest(content)
    cache = ImageCache(tmp_path / "cache")
    cache.ensure()
    partial = cache.artifact_path(manifest).with_name("image.img.partial")
    partial.write_bytes(b"stale partial")
    manager = ImageManager(
        ImageRegistry((manifest,)), cache, FakeDownloader(content)
    )
    manager.pull(manifest.id)
    assert not partial.exists()
    assert cache.artifact_path(manifest).read_bytes() == content


def test_existing_valid_source_is_reused(tmp_path: Path) -> None:
    content = b"expected"
    manifest = _manifest(content)
    cache = ImageCache(tmp_path / "cache")
    cache.ensure()
    cache.artifact_path(manifest).write_bytes(content)
    downloader = FakeDownloader(content)
    result = ImageManager(
        ImageRegistry((manifest,)), cache, downloader
    ).pull(manifest.id)
    assert result.reused and not result.downloaded
    assert downloader.calls == 0


def test_imported_source_is_reused_by_pull(tmp_path: Path) -> None:
    content = b"expected"
    manifest = _manifest(content)
    source = tmp_path / "manual.img"
    source.write_bytes(content)
    downloader = FakeDownloader(content)
    manager = ImageManager(
        ImageRegistry((manifest,)), ImageCache(tmp_path / "cache"), downloader
    )
    manager.import_image(source, manifest.id)
    result = manager.pull(manifest.id)
    assert result.reused
    assert downloader.calls == 0


def test_invalid_existing_source_is_not_silently_overwritten(tmp_path: Path) -> None:
    content = b"expected"
    manifest = _manifest(content)
    cache = ImageCache(tmp_path / "cache")
    cache.ensure()
    cache.artifact_path(manifest).write_bytes(b"invalid")
    downloader = FakeDownloader(content)
    manager = ImageManager(ImageRegistry((manifest,)), cache, downloader)
    with pytest.raises(ImageManagerError, match="not overwritten"):
        manager.pull(manifest.id)
    assert downloader.calls == 0
    assert cache.artifact_path(manifest).read_bytes() == b"invalid"
