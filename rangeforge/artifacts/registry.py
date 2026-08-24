"""Curated local artifact registry; no live discovery is permitted."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from rangeforge.artifacts.models import ArtifactManifest


class ArtifactRegistryError(ValueError):
    """Raised when curated artifact definitions are invalid."""


class ArtifactRegistry:
    def __init__(self, artifacts: tuple[ArtifactManifest, ...]) -> None:
        self._artifacts: dict[str, ArtifactManifest] = {}
        for artifact in artifacts:
            if artifact.id in self._artifacts:
                raise ArtifactRegistryError(f"Duplicate artifact id: {artifact.id}")
            self._artifacts[artifact.id] = artifact

    @classmethod
    def load(cls, path: Path | None = None) -> ArtifactRegistry:
        source = path or Path(__file__).parent / "definitions.yaml"
        try:
            document = yaml.safe_load(source.read_text(encoding="utf-8"))
            if not isinstance(document, list) or not document:
                raise ArtifactRegistryError("Artifact registry must contain a non-empty list.")
            return cls(tuple(ArtifactManifest.model_validate(item) for item in document))
        except ArtifactRegistryError:
            raise
        except (OSError, yaml.YAMLError, ValidationError, TypeError) as exc:
            raise ArtifactRegistryError(f"Artifact registry is invalid: {exc}") from exc

    def get(self, artifact_id: str) -> ArtifactManifest | None:
        return self._artifacts.get(artifact_id)

    def require(self, artifact_id: str) -> ArtifactManifest:
        artifact = self.get(artifact_id)
        if artifact is None:
            raise ArtifactRegistryError(f"Unknown artifact: {artifact_id}")
        return artifact

    def all(self) -> tuple[ArtifactManifest, ...]:
        return tuple(self._artifacts[key] for key in sorted(self._artifacts))
