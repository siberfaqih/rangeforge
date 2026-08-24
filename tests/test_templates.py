from __future__ import annotations

import hashlib
from pathlib import Path

import yaml

from rangeforge.host.models import Architecture
from rangeforge.images.cache import ImageCache
from rangeforge.images.manager import ImageManager
from rangeforge.images.models import (
    ArtifactFormat,
    Checksum,
    ImageManifest,
    ImageOS,
    ImageSource,
    ImageSourceType,
    TemplateState,
)
from rangeforge.images.registry import ImageRegistry
from rangeforge.images.templates import TemplateManager, template_fingerprint
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
