"""Strongly typed runtime, backend, and planning models."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from rangeforge.host.models import Architecture, HostInfo
from rangeforge.models import StrictModel


class RuntimeType(StrEnum):
    DOCKER = "docker"
    VM = "vm"


class VMBackend(StrEnum):
    UTM = "utm"
    VAGRANT = "vagrant"


class BackendType(StrEnum):
    DOCKER = "docker"
    UTM = "utm"
    VAGRANT = "vagrant"


class BackendCapability(StrEnum):
    DEPENDENCY_DETECTION = "dependency_detection"
    VERSION_INSPECTION = "version_inspection"
    IMAGE_INSPECTION = "image_inspection"
    VM_LISTING = "vm_listing"


class BackendStatus(StrictModel):
    backend: BackendType
    available: bool
    executable: Path | None = None
    version: str | None = None
    architecture: Architecture | None = None
    capabilities: tuple[BackendCapability, ...] = ()
    details: tuple[str, ...] = ()


class RuntimeResolution(StrictModel):
    runtime: RuntimeType
    backend: VMBackend | None = None
    guest_architecture: Architecture
    compatible: bool
    reason: str
    errors: tuple[str, ...] = ()


class GuestPlan(StrictModel):
    family: str
    distribution: str
    version: str
    architecture: Architecture
    image_id: str | None = None


class ImagePlanStatus(StrictModel):
    source: str
    template: str


class RuntimePlan(StrictModel):
    scenario_id: str
    host: HostInfo
    runtime: RuntimeResolution
    backend_status: BackendStatus | None = None
    guest: GuestPlan | None = None
    image_status: ImagePlanStatus | None = None
    compatible: bool
    deployable: bool
    issues: tuple[str, ...] = ()
    next_action: str

