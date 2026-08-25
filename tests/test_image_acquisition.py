from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from pydantic import ValidationError

from rangeforge.host.models import Architecture
from rangeforge.images.cache import ImageCache
from rangeforge.images.downloader import ImageDownloadError, ProgressCallback
from rangeforge.images.manager import ImageManager, ImageManagerError
from rangeforge.images.models import (
    ArtifactFormat,
    ArtifactState,
    Checksum,
    ImageAcquisitionMethod,
    ImageManifest,
    ImageOS,
    ImageSource,
    ImageSourceType,
    VerificationStatus,
    derive_acquisition_method,
)
from rangeforge.images.registry import ImageRegistry
from rangeforge.images.resolver import ImageResolutionError, ImageResolver
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


def _manifest_dict(**source_overrides: object) -> dict[str, object]:
    source: dict[str, object] = {
        "type": "official",
        "vendor": "fixture",
        "artifact_format": "qcow2",
        "version": "test",
        "filename": "image.img",
    }
    source.update(source_overrides)
    return {
        "id": "acq-test-arm64",
        "os": {"family": "linux", "distribution": "ubuntu", "version": "24.04"},
        "architecture": "arm64",
        "runtimes": ["vm"],
        "backends": ["utm"],
        "source": source,
        "checksum": {"algorithm": "sha256", "value": None},
    }


class TestAcquisitionModel:
    def test_acquisition_methods_are_typed(self) -> None:
        assert ImageAcquisitionMethod.AUTOMATIC.value == "automatic"
        assert ImageAcquisitionMethod.MANUAL.value == "manual"
        assert ImageAcquisitionMethod.BACKEND_MANAGED.value == "backend_managed"

    def test_derivation_rules_are_deterministic(self) -> None:
        assert (
            derive_acquisition_method(
                url="https://example.invalid/image.img", has_backend_reference=False
            )
            is ImageAcquisitionMethod.AUTOMATIC
        )
        assert (
            derive_acquisition_method(url=None, has_backend_reference=True)
            is ImageAcquisitionMethod.BACKEND_MANAGED
        )
        assert (
            derive_acquisition_method(url=None, has_backend_reference=False)
            is ImageAcquisitionMethod.MANUAL
        )

    def test_manifest_defaults_to_automatic_when_url_configured(self) -> None:
        manifest = ImageManifest.model_validate(
            _manifest_dict(url="https://example.invalid/image.img")
        )
        assert manifest.source.acquisition is ImageAcquisitionMethod.AUTOMATIC

    def test_manifest_defaults_to_backend_managed_with_box_reference(self) -> None:
        data = _manifest_dict()
        data["backends"] = ["vagrant"]
        data["vagrant_box"] = {"name": "fixture/test"}
        manifest = ImageManifest.model_validate(data)
        assert manifest.source.acquisition is ImageAcquisitionMethod.BACKEND_MANAGED

    def test_manifest_defaults_to_manual_without_url_or_box(self) -> None:
        manifest = ImageManifest.model_validate(_manifest_dict())
        assert manifest.source.acquisition is ImageAcquisitionMethod.MANUAL

    def test_manual_vagrant_source_may_require_explicit_local_template(self) -> None:
        data = _manifest_dict(acquisition="manual")
        data["backends"] = ["vagrant"]
        manifest = ImageManifest.model_validate(data)
        assert manifest.source.acquisition is ImageAcquisitionMethod.MANUAL
        assert manifest.vagrant_box is None

    def test_manual_source_must_not_configure_url(self) -> None:
        with pytest.raises(ValidationError, match="Manual image sources"):
            ImageManifest.model_validate(
                _manifest_dict(acquisition="manual", url="https://example.invalid/a")
            )

    def test_backend_managed_source_must_not_configure_url(self) -> None:
        with pytest.raises(ValidationError, match="Backend-managed image sources"):
            ImageManifest.model_validate(
                _manifest_dict(
                    acquisition="backend_managed", url="https://example.invalid/a"
                )
            )

    def test_automatic_source_requires_https_url(self) -> None:
        with pytest.raises(ValidationError, match="https"):
            ImageManifest.model_validate(
                _manifest_dict(acquisition="automatic", url="http://example.invalid/a")
            )
        with pytest.raises(ValidationError, match="https"):
            ImageManifest.model_validate(_manifest_dict(acquisition="automatic"))


class TestShippedWindowsDefinitions:
    def test_windows_arm64_definition_has_reviewed_manual_media(self) -> None:
        manifest = ImageRegistry.load().require("windows-11-arm64")
        assert manifest.os.family == "windows"
        assert manifest.os.distribution == "windows"
        assert manifest.os.version == "11"
        assert manifest.architecture is Architecture.ARM64
        assert manifest.runtimes == (RuntimeType.VM,)
        assert manifest.backends == (VMBackend.UTM,)
        assert manifest.source.acquisition is ImageAcquisitionMethod.MANUAL
        assert manifest.source.url is None
        assert manifest.source.version == "25H2-v2"
        assert manifest.source.filename == "Win11_25H2_English_Arm64_v2.iso"
        assert manifest.checksum.value == (
            "638aa2c88e94385b00f4f178d071e3df0b7d9e335577a83bd533b7f2eb65adf0"
        )

    def test_windows_amd64_definition_is_shipped_fail_closed(self) -> None:
        manifest = ImageRegistry.load().require("windows-11-amd64")
        assert manifest.architecture is Architecture.AMD64
        assert manifest.backends == (VMBackend.VAGRANT,)
        assert manifest.source.acquisition is ImageAcquisitionMethod.MANUAL
        assert manifest.source.url is None
        assert manifest.checksum.value is None
        assert manifest.vagrant_box is None


class TestWindowsImageResolution:
    def _resolver(self) -> ImageResolver:
        return ImageResolver(ImageRegistry.load())

    def test_windows_arm64_resolves_for_utm(self) -> None:
        manifest = self._resolver().resolve(
            family="windows",
            distribution="windows",
            version="11",
            architecture=Architecture.ARM64,
            runtime=RuntimeType.VM,
            backend=VMBackend.UTM,
        )
        assert manifest.id == "windows-11-arm64"

    def test_windows_arm64_never_resolves_for_vagrant(self) -> None:
        with pytest.raises(ImageResolutionError):
            self._resolver().resolve(
                family="windows",
                distribution="windows",
                version="11",
                architecture=Architecture.ARM64,
                runtime=RuntimeType.VM,
                backend=VMBackend.VAGRANT,
            )

    def test_windows_arm64_never_resolves_for_amd64(self) -> None:
        with pytest.raises(ImageResolutionError):
            self._resolver().resolve(
                family="windows",
                distribution="windows",
                version="11",
                architecture=Architecture.AMD64,
                runtime=RuntimeType.VM,
                backend=VMBackend.UTM,
            )

    def test_windows_amd64_resolves_for_vagrant(self) -> None:
        manifest = self._resolver().resolve(
            family="windows",
            distribution="windows",
            version="11",
            architecture=Architecture.AMD64,
            runtime=RuntimeType.VM,
            backend=VMBackend.VAGRANT,
        )
        assert manifest.id == "windows-11-amd64"


class TestManualAcquisition:
    def _manual_registry(
        self, checksum: Checksum | None = None
    ) -> tuple[ImageRegistry, ImageManifest]:
        manifest = ImageManifest(
            id="manual-test-arm64",
            os=ImageOS(family="windows", distribution="windows", version="11"),
            architecture=Architecture.ARM64,
            runtimes=(RuntimeType.VM,),
            backends=(VMBackend.UTM,),
            source=ImageSource(
                type=ImageSourceType.OFFICIAL,
                vendor="microsoft",
                artifact_format=ArtifactFormat.ISO,
                version="test",
                filename="manual.iso",
                acquisition=ImageAcquisitionMethod.MANUAL,
            ),
            checksum=checksum or Checksum(),
        )
        return ImageRegistry((manifest,)), manifest

    def test_pull_refuses_manual_media_without_downloading(self, tmp_path: Path) -> None:
        registry, manifest = self._manual_registry(Checksum(value="a" * 64))
        downloader = FakeDownloader(b"x")
        manager = ImageManager(registry, ImageCache(tmp_path / "cache"), downloader)
        with pytest.raises(ImageManagerError, match="images import"):
            manager.pull(manifest.id)
        assert downloader.calls == 0
        assert not manager.cache.artifact_path(manifest).exists()

    def test_import_reaches_ready_only_with_matching_checksum(
        self, tmp_path: Path
    ) -> None:
        content = b"reviewed windows media"
        digest = hashlib.sha256(content).hexdigest()
        registry, manifest = self._manual_registry(Checksum(value=digest))
        manager = ImageManager(registry, ImageCache(tmp_path / "cache"))
        source = tmp_path / "media.iso"
        source.write_bytes(content)
        inspection = manager.import_image(source, manifest.id)
        assert inspection.artifact_state is ArtifactState.READY
        assert manager.verify(manifest.id).valid

    def test_import_checksum_mismatch_is_rejected(self, tmp_path: Path) -> None:
        registry, manifest = self._manual_registry(Checksum(value="b" * 64))
        manager = ImageManager(registry, ImageCache(tmp_path / "cache"))
        source = tmp_path / "media.iso"
        source.write_bytes(b"tampered media")
        with pytest.raises(ImageManagerError, match="Checksum mismatch"):
            manager.import_image(source, manifest.id)

    def test_checksum_pending_media_never_becomes_ready(self, tmp_path: Path) -> None:
        """Media imported against a checksum-pending manifest stays
        unverified and can never become READY."""
        registry, manifest = self._manual_registry()
        manager = ImageManager(registry, ImageCache(tmp_path / "cache"))
        source = tmp_path / "media.iso"
        source.write_bytes(b"unverified media")
        inspection = manager.import_image(source, manifest.id)
        assert inspection.artifact_state is ArtifactState.DOWNLOADED
        assert inspection.artifact_state is not ArtifactState.READY
        result = manager.verify(manifest.id)
        assert result.status is VerificationStatus.UNVERIFIABLE
