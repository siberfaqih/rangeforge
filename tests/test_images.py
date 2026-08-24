from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from rangeforge.host.models import Architecture
from rangeforge.images.cache import ImageCache
from rangeforge.images.manager import ImageManager, ImageManagerError
from rangeforge.images.models import (
    ArtifactFormat,
    Checksum,
    ImageManifest,
    ImageOS,
    ImageSource,
    ImageSourceType,
    VerificationStatus,
)
from rangeforge.images.registry import ImageRegistry, ImageRegistryError
from rangeforge.images.resolver import ImageResolver
from rangeforge.runtime.models import RuntimeType, VMBackend


def _manifest(content: bytes = b"fixture image") -> ImageManifest:
    return ImageManifest(
        id="test-ubuntu-arm64",
        os=ImageOS(family="linux", distribution="ubuntu", version="24.04"),
        architecture=Architecture.ARM64,
        runtimes=(RuntimeType.VM,),
        backends=(VMBackend.UTM,),
        source=ImageSource(
            type=ImageSourceType.OFFICIAL,
            vendor="fixture",
            artifact_format=ArtifactFormat.QCOW2,
            version="test",
            filename="test-image.iso",
        ),
        checksum=Checksum(value=hashlib.sha256(content).hexdigest()),
    )


def test_image_manifest_parsing() -> None:
    registry = ImageRegistry.load()
    arm = registry.require("ubuntu-24.04-arm64")
    assert arm.architecture is Architecture.ARM64
    assert arm.backends == (VMBackend.UTM,)


def test_invalid_image_manifest_rejection(tmp_path: Path) -> None:
    definition = tmp_path / "invalid.yaml"
    definition.write_text(
        """
id: invalid-image
os: {family: linux, distribution: ubuntu, version: '24.04'}
architecture: arm64
runtimes: [vm]
backends: []
source: {type: official, vendor: fixture, filename: image.iso}
checksum: {algorithm: sha256, value: not-a-checksum}
""",
        encoding="utf-8",
    )
    with pytest.raises(ImageRegistryError, match="invalid"):
        ImageRegistry.load(tmp_path)


def test_image_resolution_by_architecture() -> None:
    registry = ImageRegistry.load()
    resolver = ImageResolver(registry)
    arm = resolver.resolve(
        family="linux",
        distribution="ubuntu",
        version="24.04",
        architecture=Architecture.ARM64,
        runtime=RuntimeType.VM,
        backend=VMBackend.UTM,
    )
    amd = resolver.resolve(
        family="linux",
        distribution="ubuntu",
        version="24.04",
        architecture=Architecture.AMD64,
        runtime=RuntimeType.VM,
        backend=VMBackend.VAGRANT,
    )
    assert arm.id == "ubuntu-24.04-arm64"
    assert amd.id == "ubuntu-24.04-amd64"


def test_image_cache_paths_are_configurable(tmp_path: Path) -> None:
    cache = ImageCache(tmp_path / "rangeforge-images")
    assert cache.downloads == tmp_path / "rangeforge-images" / "downloads"
    assert cache.template_path("image", VMBackend.UTM).is_relative_to(tmp_path)
    assert not cache.root.exists()
    cache.ensure()
    assert cache.status() == "ready"


def test_checksum_validation_success(tmp_path: Path) -> None:
    content = b"fixture image"
    manifest = _manifest(content)
    cache = ImageCache(tmp_path / "images")
    cache.ensure()
    cache.artifact_path(manifest).write_bytes(content)
    result = ImageManager(ImageRegistry((manifest,)), cache).verify(manifest.id)
    assert result.status is VerificationStatus.VALID
    assert result.actual_sha256 == hashlib.sha256(content).hexdigest()


def test_checksum_validation_failure(tmp_path: Path) -> None:
    manifest = _manifest()
    cache = ImageCache(tmp_path / "images")
    cache.ensure()
    cache.artifact_path(manifest).write_bytes(b"tampered")
    result = ImageManager(ImageRegistry((manifest,)), cache).verify(manifest.id)
    assert result.status is VerificationStatus.INVALID
    assert not result.valid


def test_import_behavior_verifies_and_registers(tmp_path: Path) -> None:
    content = b"fixture image"
    manifest = _manifest(content)
    source = tmp_path / "downloaded.iso"
    source.write_bytes(content)
    cache = ImageCache(tmp_path / "cache")
    inspection = ImageManager(ImageRegistry((manifest,)), cache).import_image(
        source, manifest.id
    )
    assert inspection.artifact_state.value == "ready"
    assert inspection.artifact_path.read_bytes() == content
    assert cache.metadata_path(manifest.id).is_file()


def test_import_rejects_checksum_mismatch(tmp_path: Path) -> None:
    manifest = _manifest()
    source = tmp_path / "wrong.iso"
    source.write_bytes(b"wrong")
    manager = ImageManager(ImageRegistry((manifest,)), ImageCache(tmp_path / "cache"))
    with pytest.raises(ImageManagerError, match="Checksum mismatch"):
        manager.import_image(source, manifest.id)
    assert not manager.cache.root.exists()


def test_source_and_template_readiness_are_distinct(tmp_path: Path) -> None:
    content = b"fixture image"
    manifest = _manifest(content)
    source = tmp_path / "source.iso"
    source.write_bytes(content)
    manager = ImageManager(
        ImageRegistry((manifest,)), ImageCache(tmp_path / "cache")
    )
    inspection = manager.import_image(source, manifest.id)
    assert inspection.artifact_state.value == "ready"
    assert inspection.template_states[VMBackend.UTM].value == "missing"
