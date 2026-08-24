"""Safe resolve, download, checksum, cache, inspect, and remove operations."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from pathlib import Path

import yaml

from rangeforge.artifacts.cache import ArtifactCache
from rangeforge.artifacts.models import (
    ArtifactInspection,
    ArtifactManifest,
    ArtifactPullResult,
    ArtifactVerification,
)
from rangeforge.artifacts.registry import ArtifactRegistry
from rangeforge.images.downloader import HTTPSImageDownloader, ImageDownloader, ProgressCallback
from rangeforge.images.models import ArtifactState, VerificationStatus


class ArtifactManagerError(ValueError):
    """Raised when an artifact operation cannot complete safely."""


class ArtifactManager:
    def __init__(
        self,
        registry: ArtifactRegistry,
        cache: ArtifactCache,
        downloader: ImageDownloader | None = None,
    ) -> None:
        self.registry = registry
        self.cache = cache
        self.downloader = downloader or HTTPSImageDownloader()

    def list(self) -> tuple[ArtifactInspection, ...]:
        return tuple(self.inspect(item.id) for item in self.registry.all())

    def inspect(self, artifact_id: str) -> ArtifactInspection:
        manifest = self.registry.require(artifact_id)
        verification = self.verify(artifact_id)
        state = {
            VerificationStatus.VALID: ArtifactState.READY,
            VerificationStatus.INVALID: ArtifactState.INVALID,
            VerificationStatus.MISSING: ArtifactState.MISSING,
            VerificationStatus.UNVERIFIABLE: ArtifactState.INVALID,
        }[verification.status]
        return ArtifactInspection(
            manifest=manifest,
            path=self.cache.artifact_path(manifest),
            state=state,
        )

    def verify(self, artifact_id: str) -> ArtifactVerification:
        manifest = self.registry.require(artifact_id)
        path = self.cache.artifact_path(manifest)
        expected = manifest.checksum.value.lower()
        if not path.is_file():
            return ArtifactVerification(
                artifact_id=artifact_id,
                status=VerificationStatus.MISSING,
                expected_sha256=expected,
                path=path,
                message="Artifact is not cached.",
            )
        actual = self._sha256(path)
        valid = actual == expected
        return ArtifactVerification(
            artifact_id=artifact_id,
            status=VerificationStatus.VALID if valid else VerificationStatus.INVALID,
            expected_sha256=expected,
            actual_sha256=actual,
            path=path,
            message="Checksum is valid." if valid else "Checksum mismatch.",
        )

    def pull(
        self,
        artifact_id: str,
        *,
        replace_invalid: bool = False,
        progress: ProgressCallback | None = None,
        state_callback: Callable[[ArtifactState], None] | None = None,
    ) -> ArtifactPullResult:
        manifest = self.registry.require(artifact_id)
        destination = self.cache.artifact_path(manifest)
        if destination.exists():
            existing = self.verify(artifact_id)
            if existing.valid:
                self._emit(state_callback, ArtifactState.READY)
                return ArtifactPullResult(
                    inspection=self.inspect(artifact_id), downloaded=False, reused=True
                )
            if not replace_invalid:
                raise ArtifactManagerError(
                    f"Cached artifact is invalid and was not overwritten: {destination}. "
                    "Use --replace-invalid to replace it explicitly."
                )

        self.cache.ensure()
        partial = destination.with_name(f"{destination.name}.partial")
        if partial.exists():
            partial.unlink()
        self._emit(state_callback, ArtifactState.DOWNLOADING)
        try:
            self.downloader.download(manifest.source.url, partial, progress)
            self._emit(state_callback, ArtifactState.DOWNLOADED)
            self._emit(state_callback, ArtifactState.VERIFYING)
            actual = self._sha256(partial)
            expected = manifest.checksum.value.lower()
            if actual != expected:
                self._emit(state_callback, ArtifactState.INVALID)
                raise ArtifactManagerError(
                    f"Checksum mismatch for '{artifact_id}'. Expected {expected}, got {actual}."
                )
            partial.replace(destination)
            self._write_record(manifest, destination, actual)
            self._emit(state_callback, ArtifactState.READY)
            return ArtifactPullResult(
                inspection=self.inspect(artifact_id), downloaded=True, reused=False
            )
        except Exception:
            if partial.exists():
                partial.unlink()
            raise

    def remove(self, artifact_id: str) -> bool:
        manifest = self.registry.require(artifact_id)
        removed = False
        for path in (self.cache.artifact_path(manifest), self.cache.metadata_path(artifact_id)):
            if path.is_file():
                path.unlink()
                removed = True
        return removed

    def _write_record(self, manifest: ArtifactManifest, destination: Path, checksum: str) -> None:
        path = self.cache.metadata_path(manifest.id)
        path.write_text(
            yaml.safe_dump(
                {
                    "artifact_id": manifest.id,
                    "version": manifest.version,
                    "filename": manifest.filename,
                    "sha256": checksum,
                    "state": ArtifactState.READY.value,
                },
                sort_keys=False,
            ),
            encoding="utf-8",
        )

    @staticmethod
    def _emit(callback: Callable[[ArtifactState], None] | None, state: ArtifactState) -> None:
        if callback:
            callback(state)

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
