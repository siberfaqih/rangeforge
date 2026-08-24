"""Trusted CVE primitive metadata and compatibility contracts."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from rangeforge.host.models import Architecture
from rangeforge.models import AccessState, Primitive, StrictModel
from rangeforge.runtime.models import RuntimeType, VMBackend


class CVERuntimeSupport(StrictModel):
    runtime: RuntimeType
    backends: tuple[VMBackend, ...] = ()
    realism: Literal["real", "simulated"] = "real"

    @model_validator(mode="after")
    def vm_requires_backend(self) -> CVERuntimeSupport:
        if self.runtime is RuntimeType.VM and not self.backends:
            raise ValueError("VM CVE runtime support must declare a backend")
        return self


class CVEIdentity(StrictModel):
    id: str = Field(pattern=r"^CVE-(?:19|20)\d{2}-\d{4,}$")
    vendor: str
    product: str
    affected_version: str
    advisory: str

    @model_validator(mode="after")
    def advisory_is_https(self) -> CVEIdentity:
        if not self.advisory.startswith("https://"):
            raise ValueError("CVE advisory must use HTTPS")
        return self


class CVEService(StrictModel):
    category: str
    name: str
    protocol: str
    expected_version: str
    port: int = Field(ge=1, le=65535)
    user: str
    authentication_required: bool


class CVEAttackRole(StrictModel):
    requires: tuple[AccessState, ...] = Field(min_length=1)
    provides: AccessState


class BaseGuestConstraint(StrictModel):
    family: str
    distribution: str
    versions: tuple[str, ...] = Field(min_length=1)


class CVEArtifactRequirement(StrictModel):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]*$")
    architectures: tuple[Architecture, ...] = Field(min_length=1)


class CVEValidationSpec(StrictModel):
    mandatory_levels: tuple[
        str,
        ...,
    ] = Field(min_length=1)
    expected_checks: tuple[str, ...] = Field(min_length=1)


class CVEManifest(StrictModel):
    definition_version: int = Field(ge=1)
    primitive: Primitive
    cve: CVEIdentity
    service: CVEService
    attack_role: CVEAttackRole
    platforms: tuple[Literal["linux"], ...] = Field(min_length=1)
    architectures: tuple[Architecture, ...] = Field(min_length=1)
    runtime_support: tuple[CVERuntimeSupport, ...] = Field(min_length=1)
    base_guest: BaseGuestConstraint
    artifacts: tuple[CVEArtifactRequirement, ...] = Field(min_length=1)
    provisioner: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    validator: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    validation: CVEValidationSpec
    public_exploit_exists: bool

    @model_validator(mode="after")
    def logical_and_runtime_metadata_agree(self) -> CVEManifest:
        if tuple(self.primitive.requires.states) != self.attack_role.requires:
            raise ValueError("CVE attack role requirements do not match its primitive")
        if self.primitive.provides.state is not self.attack_role.provides:
            raise ValueError("CVE attack role result does not match its primitive")
        if not set(self.platforms).issubset(self.primitive.platforms):
            raise ValueError("CVE platforms must be a subset of primitive platforms")
        if not set(self.architectures).issubset(self.primitive.architectures):
            raise ValueError("CVE architectures must be a subset of primitive architectures")
        if Architecture.UNSUPPORTED in self.architectures:
            raise ValueError("CVE architecture cannot be unsupported")
        return self

    def supports(
        self,
        *,
        profile: str,
        platform: str,
        architecture: Architecture,
        runtime: RuntimeType,
        backend: VMBackend | None,
        family: str,
        distribution: str,
        version: str,
    ) -> bool:
        runtime_matches = any(
            declaration.runtime is runtime
            and (runtime is RuntimeType.DOCKER or backend in declaration.backends)
            for declaration in self.runtime_support
        )
        return (
            profile in self.primitive.profiles
            and platform in self.platforms
            and architecture in self.architectures
            and runtime_matches
            and family == self.base_guest.family
            and distribution == self.base_guest.distribution
            and version in self.base_guest.versions
        )

    def artifact_ids_for(self, architecture: Architecture) -> tuple[str, ...]:
        return tuple(
            item.id for item in self.artifacts if architecture in item.architectures
        )


class CVEKnowledge(StrictModel):
    learning_objective: str
    concepts: tuple[str, ...] = Field(min_length=1)
    prerequisites: tuple[str, ...] = Field(min_length=1)
    success_state: AccessState
    instructor_steps: tuple[str, ...] = Field(min_length=1)


class CVEPrimitive(StrictModel):
    manifest: CVEManifest
    knowledge: CVEKnowledge
    definition_path: Path


class CVERegistryDocument(StrictModel):
    registry_version: int = Field(ge=1)
