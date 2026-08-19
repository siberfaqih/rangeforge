"""Deterministic loading of trusted image manifest definitions."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from rangeforge.images.models import ImageManifest


class ImageRegistryError(ValueError):
    """Raised when image registry data is missing, duplicated, or invalid."""


class ImageRegistry:
    def __init__(self, manifests: tuple[ImageManifest, ...]) -> None:
        self._manifests: dict[str, ImageManifest] = {}
        for manifest in sorted(manifests, key=lambda item: item.id):
            if manifest.id in self._manifests:
                raise ImageRegistryError(f"Duplicate image id: {manifest.id}")
            self._manifests[manifest.id] = manifest

    @classmethod
    def load(cls, directory: Path | None = None) -> ImageRegistry:
        definitions = directory or Path(__file__).parent / "definitions"
        manifests: list[ImageManifest] = []
        try:
            paths = sorted(definitions.glob("*.yaml"))
            if not paths:
                raise ImageRegistryError(f"No image definitions found in {definitions}")
            for path in paths:
                document = yaml.safe_load(path.read_text(encoding="utf-8"))
                records = document if isinstance(document, list) else [document]
                manifests.extend(ImageManifest.model_validate(record) for record in records)
            return cls(tuple(manifests))
        except ImageRegistryError:
            raise
        except (OSError, yaml.YAMLError, ValidationError, TypeError) as exc:
            raise ImageRegistryError(f"Image registry is invalid: {exc}") from exc

    def all(self) -> tuple[ImageManifest, ...]:
        return tuple(self._manifests[key] for key in sorted(self._manifests))

    def get(self, image_id: str) -> ImageManifest | None:
        return self._manifests.get(image_id)

    def require(self, image_id: str) -> ImageManifest:
        manifest = self.get(image_id)
        if manifest is None:
            raise ImageRegistryError(f"Unknown image: {image_id}")
        return manifest
