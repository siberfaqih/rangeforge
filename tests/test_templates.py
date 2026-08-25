from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
import yaml

from rangeforge.host.models import Architecture
from rangeforge.images.cache import ImageCache
from rangeforge.images.manager import ImageManager, ImageManagerError
from rangeforge.images.models import (
    ArtifactFormat,
    BaseTemplate,
    Checksum,
    ImageAcquisitionMethod,
    ImageManifest,
    ImageOS,
    ImageSource,
    ImageSourceType,
    TemplateState,
)
from rangeforge.images.registry import ImageRegistry
from rangeforge.images.templates import TemplateManager, template_fingerprint, template_id
from rangeforge.runtime.models import RuntimeType, VMBackend


class FakeTemplateBackend:
    def __init__(self, references: set[str]) -> None:
        self.references = references

    def available(self) -> bool:
        return True

    def template_exists(self, reference: str) -> bool:
        return reference in self.references


def _manager(tmp_path: Path) -> tuple[ImageManager, ImageManifest]:
    content = b"template source"
    manifest = ImageManifest(
        id="template-test-arm64",
        os=ImageOS(family="linux", distribution="ubuntu", version="24.04"),
        architecture=Architecture.ARM64,
        runtimes=(RuntimeType.VM,),
        backends=(VMBackend.UTM,),
        source=ImageSource(
            type=ImageSourceType.OFFICIAL,
            vendor="fixture",
            artifact_format=ArtifactFormat.QCOW2,
            version="test",
            filename="template-source.img",
        ),
        checksum=Checksum(value=hashlib.sha256(content).hexdigest()),
    )
    cache = ImageCache(tmp_path / "cache")
    cache.ensure()
    cache.artifact_path(manifest).write_bytes(content)
    return ImageManager(ImageRegistry((manifest,)), cache), manifest


def test_template_fingerprint_is_deterministic() -> None:
    first = template_fingerprint("image", "a" * 64, VMBackend.UTM)
    second = template_fingerprint("image", "a" * 64, VMBackend.UTM)
    changed = template_fingerprint("image", "b" * 64, VMBackend.UTM)
    assert first == second
    assert first != changed


def test_template_metadata_parsing_and_readiness(tmp_path: Path) -> None:
    manager, manifest = _manager(tmp_path)
    reference = f"rf-base-{manifest.id}"
    templates = TemplateManager(manager)
    prepared = templates.prepare(
        manifest.id,
        VMBackend.UTM,
        FakeTemplateBackend({reference}),
    )
    parsed = manager.cache.load_template(manifest.id, VMBackend.UTM)
    assert parsed == prepared
    assert templates.state(manifest.id, VMBackend.UTM) is TemplateState.READY
    assert manager.inspect(manifest.id).template_states[VMBackend.UTM] is TemplateState.READY


def test_tampered_template_fingerprint_is_stale(tmp_path: Path) -> None:
    manager, manifest = _manager(tmp_path)
    reference = f"rf-base-{manifest.id}"
    templates = TemplateManager(manager)
    templates.prepare(
        manifest.id,
        VMBackend.UTM,
        FakeTemplateBackend({reference}),
    )
    path = manager.cache.template_metadata_path(manifest.id, VMBackend.UTM)
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data["fingerprint"] = "0" * 64
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    assert manager.cache.template_state(manifest.id, VMBackend.UTM) is TemplateState.STALE


def test_windows_template_identity_follows_image_id() -> None:
    """The reusable Windows base template keeps the generic rf-base- naming."""
    assert template_id("windows-11-arm64") == "rf-base-windows-11-arm64"


def test_checksum_pending_windows_source_cannot_prepare_template(
    tmp_path: Path,
) -> None:
    """A checksum-pending Windows manifest can never yield a READY source,
    so template preparation must fail closed."""
    manifest = ImageManifest(
        id="windows-template-test-arm64",
        os=ImageOS(family="windows", distribution="windows", version="11"),
        architecture=Architecture.ARM64,
        runtimes=(RuntimeType.VM,),
        backends=(VMBackend.UTM,),
        source=ImageSource(
            type=ImageSourceType.OFFICIAL,
            vendor="microsoft",
            artifact_format=ArtifactFormat.ISO,
            version="test",
            filename="windows-template-test.iso",
            acquisition=ImageAcquisitionMethod.MANUAL,
        ),
        checksum=Checksum(),
    )
    cache = ImageCache(tmp_path / "cache")
    cache.ensure()
    manager = ImageManager(ImageRegistry((manifest,)), cache)
    templates = TemplateManager(manager)
    with pytest.raises(ImageManagerError, match="not READY"):
        templates.prepare(
            manifest.id,
            VMBackend.UTM,
            FakeTemplateBackend({f"rf-base-{manifest.id}"}),
        )
    assert (
        manager.inspect(manifest.id).template_states[VMBackend.UTM]
        is TemplateState.MISSING
    )


def test_checksum_pending_template_display_is_stale(tmp_path: Path) -> None:
    """A READY template record must never display as READY for a
    checksum-pending image; inspection reports STALE so the displayed
    template state stays consistent with lifecycle refusal."""
    manifest = ImageManifest(
        id="stale-display-arm64",
        os=ImageOS(family="windows", distribution="windows", version="11"),
        architecture=Architecture.ARM64,
        runtimes=(RuntimeType.VM,),
        backends=(VMBackend.UTM,),
        source=ImageSource(
            type=ImageSourceType.OFFICIAL,
            vendor="microsoft",
            artifact_format=ArtifactFormat.ISO,
            version="test",
            filename="stale-display.iso",
            acquisition=ImageAcquisitionMethod.MANUAL,
        ),
        checksum=Checksum(),
    )
    cache = ImageCache(tmp_path / "cache")
    cache.ensure()
    manager = ImageManager(ImageRegistry((manifest,)), cache)
    forged = BaseTemplate(
        id=template_id(manifest.id),
        image_id=manifest.id,
        backend=VMBackend.UTM,
        architecture=Architecture.ARM64,
        reference=template_id(manifest.id),
        status=TemplateState.READY,
        source_checksum="a" * 64,
        schema_version=1,
        created_by_version="test",
        fingerprint=template_fingerprint(manifest.id, "a" * 64, VMBackend.UTM),
    )
    path = cache.template_metadata_path(manifest.id, VMBackend.UTM)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(forged.model_dump(mode="json")), encoding="utf-8")
    assert (
        manager.inspect(manifest.id).template_states[VMBackend.UTM]
        is TemplateState.STALE
    )


def test_manual_vagrant_image_requires_explicit_existing_template(
    tmp_path: Path,
) -> None:
    content = b"reviewed windows amd64 media"
    manifest = ImageManifest(
        id="windows-11-amd64",
        os=ImageOS(family="windows", distribution="windows", version="11"),
        architecture=Architecture.AMD64,
        runtimes=(RuntimeType.VM,),
        backends=(VMBackend.VAGRANT,),
        source=ImageSource(
            type=ImageSourceType.OFFICIAL,
            vendor="microsoft",
            artifact_format=ArtifactFormat.ISO,
            version="test",
            filename="windows-11-amd64.iso",
            acquisition=ImageAcquisitionMethod.MANUAL,
        ),
        checksum=Checksum(value=hashlib.sha256(content).hexdigest()),
    )
    cache = ImageCache(tmp_path / "cache")
    cache.ensure()
    cache.artifact_path(manifest).write_bytes(content)
    manager = ImageManager(ImageRegistry((manifest,)), cache)
    templates = TemplateManager(manager)
    reference = "rf-base-windows-11-amd64"

    with pytest.raises(ImageManagerError, match="explicit --template-name"):
        templates.prepare(
            manifest.id,
            VMBackend.VAGRANT,
            FakeTemplateBackend({reference}),
        )

    prepared = templates.prepare(
        manifest.id,
        VMBackend.VAGRANT,
        FakeTemplateBackend({reference}),
        reference=reference,
    )
    assert prepared.reference == reference
    assert prepared.status is TemplateState.READY


def test_manual_vagrant_template_rejects_unsafe_reference(tmp_path: Path) -> None:
    content = b"reviewed windows amd64 media"
    manifest = ImageManifest(
        id="windows-11-amd64",
        os=ImageOS(family="windows", distribution="windows", version="11"),
        architecture=Architecture.AMD64,
        runtimes=(RuntimeType.VM,),
        backends=(VMBackend.VAGRANT,),
        source=ImageSource(
            type=ImageSourceType.OFFICIAL,
            vendor="microsoft",
            artifact_format=ArtifactFormat.ISO,
            version="test",
            filename="windows-11-amd64.iso",
            acquisition=ImageAcquisitionMethod.MANUAL,
        ),
        checksum=Checksum(value=hashlib.sha256(content).hexdigest()),
    )
    cache = ImageCache(tmp_path / "cache")
    cache.ensure()
    cache.artifact_path(manifest).write_bytes(content)
    templates = TemplateManager(ImageManager(ImageRegistry((manifest,)), cache))
    unsafe = 'bad"; system("touch /tmp/nope")'

    with pytest.raises(ImageManagerError, match="Invalid Vagrant box reference"):
        templates.prepare(
            manifest.id,
            VMBackend.VAGRANT,
            FakeTemplateBackend({unsafe}),
            reference=unsafe,
        )
