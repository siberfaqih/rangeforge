"""Versioned, default-deny registry of locally curated CVE primitives."""

from __future__ import annotations

from rangeforge.artifacts.registry import ArtifactRegistry
from rangeforge.cve.models import CVEPrimitive
from rangeforge.host.models import Architecture
from rangeforge.models import Primitive, TrainingProfile
from rangeforge.runtime.models import RuntimeType, VMBackend


class CVERegistryError(ValueError):
    """Raised when curated CVE data is incomplete or inconsistent."""


class CVERegistry:
    def __init__(
        self,
        version: int,
        primitives: tuple[CVEPrimitive, ...],
        artifacts: ArtifactRegistry,
    ) -> None:
        self.version = version
        self.artifacts = artifacts
        self._by_cve: dict[str, CVEPrimitive] = {}
        self._by_primitive: dict[str, CVEPrimitive] = {}
        for item in primitives:
            cve_id = item.manifest.cve.id
            primitive_id = item.manifest.primitive.id
            if cve_id in self._by_cve:
                raise CVERegistryError(f"Duplicate CVE id: {cve_id}")
            if primitive_id in self._by_primitive:
                raise CVERegistryError(f"Duplicate CVE primitive id: {primitive_id}")
            for requirement in item.manifest.artifacts:
                artifact = artifacts.get(requirement.id)
                if artifact is None:
                    raise CVERegistryError(
                        f"CVE '{cve_id}' references unknown artifact '{requirement.id}'."
                    )
                if not set(requirement.architectures).issubset(artifact.architectures):
                    raise CVERegistryError(
                        f"Artifact '{requirement.id}' does not support its declared "
                        "CVE architectures."
                    )
            for architecture in item.manifest.architectures:
                if not item.manifest.artifact_ids_for(architecture):
                    raise CVERegistryError(
                        f"CVE '{cve_id}' has no artifacts for {architecture.value}."
                    )
            self._by_cve[cve_id] = item
            self._by_primitive[primitive_id] = item

    def all(self) -> tuple[CVEPrimitive, ...]:
        return tuple(self._by_cve[key] for key in sorted(self._by_cve))

    def get(self, identifier: str) -> CVEPrimitive | None:
        return self._by_cve.get(identifier.upper()) or self._by_primitive.get(identifier)

    def require(self, identifier: str) -> CVEPrimitive:
        item = self.get(identifier)
        if item is None:
            raise CVERegistryError(f"Unknown curated CVE: {identifier}")
        return item

    def get_by_primitive(self, primitive_id: str) -> CVEPrimitive | None:
        return self._by_primitive.get(primitive_id)

    def logical_primitives(self) -> tuple[Primitive, ...]:
        return tuple(item.manifest.primitive for item in self.all())

    def compatible_ids(
        self,
        *,
        profile: TrainingProfile,
        platform: str,
        architecture: Architecture,
        runtime: RuntimeType,
        backend: VMBackend | None,
    ) -> tuple[str, ...]:
        guest = profile.runtime_defaults.get(platform)
        if guest is None:
            return ()
        return tuple(
            item.manifest.primitive.id
            for item in self.all()
            if item.manifest.primitive.id in profile.allowed_techniques
            and set(item.manifest.primitive.categories).issubset(profile.allowed_categories)
            and not set(item.manifest.primitive.categories).intersection(
                profile.forbidden_categories
            )
            and item.manifest.supports(
                profile=profile.id,
                platform=platform,
                architecture=architecture,
                runtime=runtime,
                backend=backend,
                family=guest.family,
                distribution=guest.distribution,
                version=guest.version,
            )
        )
