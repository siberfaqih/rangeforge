"""Safe local image inspection, import, verification, and removal."""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

import yaml

from rangeforge.images.cache import ImageCache
from rangeforge.images.models import (
    ArtifactState,
    ImageInspection,
    ImageManifest,
    VerificationResult,
    VerificationStatus,
)
from rangeforge.images.registry import ImageRegistry


class ImageManagerError(ValueError):
    """Raised when a requested local image operation cannot complete safely."""


class ImageManager:
    def __init__(self, registry: ImageRegistry, cache: ImageCache) -> None:
        self.registry = registry
        self.cache = cache

    def list(self) -> tuple[ImageInspection, ...]:
        return tuple(self.inspect(item.id) for item in self.registry.all())

    def inspect(self, image_id: str) -> ImageInspection:
        manifest = self.registry.require(image_id)
        artifact_path = self.cache.artifact_path(manifest)
        verification = self.verify(image_id)
        state = {
            VerificationStatus.VALID: ArtifactState.READY,
            VerificationStatus.INVALID: ArtifactState.INVALID,
            VerificationStatus.MISSING: ArtifactState.MISSING,
            VerificationStatus.UNVERIFIABLE: ArtifactState.DOWNLOADED,
        }[verification.status]
        return ImageInspection(
            manifest=manifest,
            artifact_path=artifact_path,
            artifact_state=state,
            template_states={
                backend: self.cache.template_state(image_id, backend)
                for backend in manifest.backends
            },
        )

    def resolve(self, image_id: str) -> ImageManifest:
        return self.registry.require(image_id)

    def verify(self, image_id: str) -> VerificationResult:
        manifest = self.registry.require(image_id)
        path = self.cache.artifact_path(manifest)
        expected = manifest.checksum.value
        if not path.is_file():
            return VerificationResult(
                image_id=image_id,
                status=VerificationStatus.MISSING,
                expected_sha256=expected,
                artifact_path=path,
                message="Source artifact is not cached.",
            )
        if expected is None:
            return VerificationResult(
                image_id=image_id,
                status=VerificationStatus.UNVERIFIABLE,
                artifact_path=path,
                message="The registry does not configure a checksum for this image.",
            )
        actual = self._sha256(path)
        valid = actual.lower() == expected.lower()
        return VerificationResult(
            image_id=image_id,
            status=VerificationStatus.VALID if valid else VerificationStatus.INVALID,
            expected_sha256=expected.lower(),
            actual_sha256=actual,
            artifact_path=path,
            message="Checksum is valid." if valid else "Checksum mismatch.",
        )

    def import_image(self, source: Path, image_id: str) -> ImageInspection:
        manifest = self.registry.require(image_id)
        source = source.expanduser().resolve()
        if not source.is_file():
            raise ImageManagerError(f"Import source is not a file: {source}")
        expected = manifest.checksum.value
        actual = self._sha256(source)
        if expected is not None and actual.lower() != expected.lower():
            raise ImageManagerError(
                f"Checksum mismatch for '{image_id}'. Expected {expected.lower()}, got {actual}."
            )

        self.cache.ensure()
        destination = self.cache.artifact_path(manifest)
        if destination.exists() and destination.resolve() != source:
            existing_hash = self._sha256(destination)
            if existing_hash != actual:
                raise ImageManagerError(
                    f"Refusing to overwrite a different cached artifact: {destination}"
                )
        elif destination.resolve() != source:
            shutil.copy2(source, destination)

        state = ArtifactState.READY if expected is not None else ArtifactState.DOWNLOADED
        record = {
            "image_id": image_id,
            "artifact_path": str(destination),
            "source_path": str(source),
            "sha256": actual,
            "state": state.value,
        }
        self.cache.metadata_path(image_id).write_text(
            yaml.safe_dump(record, sort_keys=False), encoding="utf-8"
        )
        return self.inspect(image_id)

    def download(self, image_id: str) -> None:
        manifest = self.registry.require(image_id)
        if manifest.source.url is None:
            raise ImageManagerError(
                f"Image '{image_id}' has no trusted download URL configured."
            )
        raise ImageManagerError("Remote image pulling is not implemented in Phase 2A.")

    def remove(self, image_id: str) -> bool:
        manifest = self.registry.require(image_id)
        removed = False
        for path in (
            self.cache.artifact_path(manifest),
            self.cache.metadata_path(image_id),
        ):
            if path.is_file():
                path.unlink()
                removed = True
        return removed

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

