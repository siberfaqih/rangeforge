"""Load runtime primitive manifests, knowledge, and script assets."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from rangeforge.cve.registry import CVERegistry
from rangeforge.primitives.registry import PrimitiveRegistry
from rangeforge.runtime_primitives.models import (
    CVERuntimeBinding,
    PrimitiveKnowledge,
    RuntimeArtifactReference,
    RuntimePrimitive,
    RuntimePrimitiveManifest,
    RuntimeSupportDeclaration,
)
from rangeforge.runtime_primitives.registry import RuntimePrimitiveRegistry


class RuntimePrimitiveLoadError(ValueError):
    """Raised when runtime primitive data is incomplete or inconsistent."""


class RuntimePrimitiveLoader:
    def __init__(self, directory: Path | None = None) -> None:
        self.directory = directory or Path(__file__).parent / "definitions"

    def load(
        self,
        primitives: PrimitiveRegistry,
        cves: CVERegistry | None = None,
    ) -> RuntimePrimitiveRegistry:
        records: list[RuntimePrimitive] = []
        try:
            for directory in sorted(path for path in self.directory.iterdir() if path.is_dir()):
                manifest = RuntimePrimitiveManifest.model_validate(
                    yaml.safe_load((directory / "manifest.yaml").read_text(encoding="utf-8"))
                )
                knowledge = PrimitiveKnowledge.model_validate(
                    yaml.safe_load((directory / "knowledge.yaml").read_text(encoding="utf-8"))
                )
                primitive = primitives.require(manifest.primitive)
                if not set(manifest.platforms).issubset(primitive.platforms):
                    raise RuntimePrimitiveLoadError(
                        f"Runtime manifest platform does not match primitive '{primitive.id}'."
                    )
                if not set(manifest.architectures).issubset(primitive.architectures):
                    raise RuntimePrimitiveLoadError(
                        f"Runtime manifest architecture does not match primitive '{primitive.id}'."
                    )
                for filename in (f"{manifest.provisioner}.sh", f"{manifest.validator}.sh"):
                    if not (directory / filename).is_file():
                        raise RuntimePrimitiveLoadError(
                            f"Runtime primitive '{primitive.id}' is missing {filename}."
                        )
                records.append(
                    RuntimePrimitive(
                        primitive=primitive,
                        manifest=manifest,
                        knowledge=knowledge,
                        definition_path=directory,
                    )
                )
            if cves is not None:
                records.extend(self._cve_runtime_primitives(cves))
            if not records:
                raise RuntimePrimitiveLoadError(
                    f"No runtime primitive definitions found in {self.directory}."
                )
            return RuntimePrimitiveRegistry(tuple(records), self.directory)
        except RuntimePrimitiveLoadError:
            raise
        except KeyError as exc:
            raise RuntimePrimitiveLoadError(str(exc)) from exc
        except (OSError, yaml.YAMLError, ValidationError, TypeError) as exc:
            raise RuntimePrimitiveLoadError(
                f"Runtime primitive definitions are invalid: {exc}"
            ) from exc

    @staticmethod
    def _cve_runtime_primitives(cves: CVERegistry) -> tuple[RuntimePrimitive, ...]:
        records: list[RuntimePrimitive] = []
        for item in cves.all():
            definition = item.manifest
            for architecture in definition.architectures:
                if not definition.artifact_ids_for(architecture):
                    raise RuntimePrimitiveLoadError(
                        f"CVE '{definition.cve.id}' has no artifact set for {architecture.value}."
                    )
            artifacts = tuple(
                RuntimeArtifactReference(
                    id=artifact.id,
                    filename=artifact.filename,
                    version=artifact.version,
                    sha256=artifact.checksum.value,
                    architectures=next(
                        requirement.architectures
                        for requirement in definition.artifacts
                        if requirement.id == artifact.id
                    ),
                )
                for artifact in cves.artifacts.all()
                if any(
                    requirement.id == artifact.id
                    for requirement in definition.artifacts
                )
            )
            manifest = RuntimePrimitiveManifest(
                primitive=definition.primitive.id,
                platforms=definition.platforms,
                architectures=definition.architectures,
                runtime_support=tuple(
                    RuntimeSupportDeclaration.model_validate(item.model_dump())
                    for item in definition.runtime_support
                ),
                provisioner=definition.provisioner,
                validator=definition.validator,
            )
            records.append(
                RuntimePrimitive(
                    primitive=definition.primitive,
                    manifest=manifest,
                    knowledge=PrimitiveKnowledge(
                        objective=item.knowledge.learning_objective,
                        concepts=item.knowledge.concepts,
                        success_state=item.knowledge.success_state.value,
                    ),
                    definition_path=item.definition_path,
                    cve=CVERuntimeBinding(
                        cve_id=definition.cve.id,
                        registry_version=cves.version,
                        definition_version=definition.definition_version,
                        vendor=definition.cve.vendor,
                        product=definition.cve.product,
                        expected_version=definition.service.expected_version,
                        service_name=definition.service.name,
                        service_port=definition.service.port,
                        service_user=definition.service.user,
                        authentication_required=definition.service.authentication_required,
                        artifacts=artifacts,
                        expected_checks=definition.validation.expected_checks,
                    ),
                )
            )
        return tuple(records)
