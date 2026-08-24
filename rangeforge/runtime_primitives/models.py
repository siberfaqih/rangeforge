"""Typed contracts for runtime-capable primitives and deployed validation."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from rangeforge.host.models import Architecture
from rangeforge.models import Primitive, StrictModel
from rangeforge.runtime.models import RuntimeType, VMBackend


class RuntimeRealism(StrEnum):
    REAL = "real"
    SIMULATED = "simulated"


class RuntimeSupportDeclaration(StrictModel):
    runtime: RuntimeType
    backends: tuple[VMBackend, ...] = ()
    realism: RuntimeRealism = RuntimeRealism.REAL

    @model_validator(mode="after")
    def vm_requires_backend(self) -> RuntimeSupportDeclaration:
        if self.runtime is RuntimeType.VM and not self.backends:
            raise ValueError("VM runtime support must declare at least one backend")
        return self


class RuntimePrimitiveManifest(StrictModel):
    primitive: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    platforms: tuple[Literal["linux"], ...] = Field(min_length=1)
    architectures: tuple[Architecture, ...] = Field(min_length=1)
    runtime_support: tuple[RuntimeSupportDeclaration, ...] = Field(min_length=1)
    provisioner: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    validator: str = Field(pattern=r"^[a-z][a-z0-9_]*$")


class PrimitiveKnowledge(StrictModel):
    objective: str
    concepts: tuple[str, ...] = Field(min_length=1)
    success_state: str


class RuntimeArtifactReference(StrictModel):
    id: str
    filename: str
    version: str
    sha256: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    architectures: tuple[Architecture, ...] = Field(min_length=1)


class CVERuntimeBinding(StrictModel):
    cve_id: str = Field(pattern=r"^CVE-(?:19|20)\d{2}-\d{4,}$")
    registry_version: int = Field(ge=1)
    definition_version: int = Field(ge=1)
    vendor: str
    product: str
    expected_version: str
    service_name: str
    service_port: int = Field(ge=1, le=65535)
    service_user: str
    authentication_required: bool
    artifacts: tuple[RuntimeArtifactReference, ...] = Field(min_length=1)
    expected_checks: tuple[str, ...] = Field(min_length=1)

    def artifacts_for(self, architecture: Architecture) -> tuple[RuntimeArtifactReference, ...]:
        return tuple(item for item in self.artifacts if architecture in item.architectures)


class RuntimePrimitive(StrictModel):
    primitive: Primitive
    manifest: RuntimePrimitiveManifest
    knowledge: PrimitiveKnowledge
    definition_path: Path | None = None
    cve: CVERuntimeBinding | None = None


class ScenarioRuntimeConfiguration(StrictModel):
    schema_version: str = "phase3-v1"
    scenario_id: str
    service_account: str
    scenario_user: str
    audit_user: str
    management_account: str
    scenario_credential: str
    local_flag: str
    proof_flag: str
    service_port: int = Field(ge=1024, le=65535)


class ProvisioningStep(StrictModel):
    primitive: str
    order: int = Field(ge=1)
    provisioner: str
    validator: str


class ProvisioningPlan(StrictModel):
    scenario_id: str
    runtime: RuntimeType
    backend: VMBackend
    architecture: Architecture
    machine_name: str
    steps: tuple[ProvisioningStep, ...] = Field(min_length=1)
    flags: tuple[Literal["local", "proof"], ...] = ("local", "proof")
    artifacts: tuple[RuntimeArtifactReference, ...] = ()
    cve_registry_version: int = Field(default=1, ge=1)
    configuration_fingerprint: str
    plan_fingerprint: str


class LockedBaseImage(StrictModel):
    id: str
    fingerprint: str


class LockedPrimitive(StrictModel):
    id: str
    version: int = Field(ge=1)
    cve_id: str | None = None
    service_version: str | None = None
    artifacts: tuple[RuntimeArtifactReference, ...] = ()


class ScenarioRuntimeLock(StrictModel):
    schema_version: str = "phase4-v1"
    scenario_id: str
    seed: int
    profile: str
    runtime: RuntimeType
    backend: VMBackend
    architecture: Architecture
    cve_registry_version: int = Field(ge=1)
    base_image: LockedBaseImage
    primitives: tuple[LockedPrimitive, ...] = Field(min_length=1)


class RuntimeCheck(StrictModel):
    name: str
    passed: bool
    detail: str = ""


class PrimitiveValidation(StrictModel):
    primitive: str
    valid: bool
    checks: tuple[RuntimeCheck, ...] = ()


class FlagValidation(StrictModel):
    flag: Literal["local.txt", "proof.txt"]
    valid: bool
    checks: tuple[RuntimeCheck, ...] = ()


class NegativeValidation(StrictModel):
    name: str
    triggered: bool
    detail: str = ""


class RuntimeValidationResult(StrictModel):
    scenario_id: str
    backend: VMBackend
    primitives: tuple[PrimitiveValidation, ...]
    flags: tuple[FlagValidation, ...]
    negative_checks: tuple[NegativeValidation, ...]
    status: Literal["valid", "invalid"]

    @property
    def valid(self) -> bool:
        return self.status == "valid"
