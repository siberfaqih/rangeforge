"""Load complete CVE bundles from the versioned local registry."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from rangeforge.artifacts.registry import ArtifactRegistry
from rangeforge.cve.models import (
    CVEKnowledge,
    CVEManifest,
    CVEPrimitive,
    CVERegistryDocument,
)
from rangeforge.cve.registry import CVERegistry, CVERegistryError
from rangeforge.profiles.loader import ProfileLoader, ProfileLoadError


class CVELoadError(ValueError):
    """Raised when a CVE bundle cannot be trusted or loaded."""


class CVELoader:
    def __init__(self, directory: Path | None = None) -> None:
        self.directory = directory or Path(__file__).parent / "definitions"

    def load(self, artifacts: ArtifactRegistry | None = None) -> CVERegistry:
        artifact_registry = artifacts or ArtifactRegistry.load()
        try:
            document = CVERegistryDocument.model_validate(
                yaml.safe_load((self.directory / "registry.yaml").read_text(encoding="utf-8"))
            )
            records: list[CVEPrimitive] = []
            for directory in sorted(path for path in self.directory.iterdir() if path.is_dir()):
                manifest = CVEManifest.model_validate(
                    yaml.safe_load((directory / "manifest.yaml").read_text(encoding="utf-8"))
                )
                knowledge = CVEKnowledge.model_validate(
                    yaml.safe_load((directory / "knowledge.yaml").read_text(encoding="utf-8"))
                )
                for filename in (f"{manifest.provisioner}.sh", f"{manifest.validator}.sh"):
                    if not (directory / filename).is_file():
                        raise CVELoadError(
                            f"CVE '{manifest.cve.id}' is missing runtime file {filename}."
                        )
                for profile_id in manifest.primitive.profiles:
                    profile = ProfileLoader().load(profile_id)
                    if manifest.primitive.id not in profile.allowed_techniques:
                        raise CVELoadError(
                            f"CVE primitive '{manifest.primitive.id}' is not explicitly "
                            f"allowed by profile '{profile_id}'."
                        )
                records.append(
                    CVEPrimitive(
                        manifest=manifest,
                        knowledge=knowledge,
                        definition_path=directory,
                    )
                )
            if not records:
                raise CVELoadError("CVE registry contains no definitions.")
            return CVERegistry(document.registry_version, tuple(records), artifact_registry)
        except CVELoadError:
            raise
        except CVERegistryError as exc:
            raise CVELoadError(str(exc)) from exc
        except ProfileLoadError as exc:
            raise CVELoadError(str(exc)) from exc
        except (OSError, yaml.YAMLError, ValidationError, TypeError) as exc:
            raise CVELoadError(f"CVE registry is invalid: {exc}") from exc
