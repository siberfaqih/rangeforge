"""Strongly typed runtime, backend, and planning models."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import Field

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


class GuestPlatform(StrEnum):
    """Logical guest platform families RangeForge can reason about."""

    LINUX = "linux"
    WINDOWS = "windows"


class ExecutionLanguage(StrEnum):
    """Execution languages available for primitive provisioning on a guest."""

    SHELL = "shell"
    POWERSHELL = "powershell"
    PYTHON = "python"


class ManagementTransportKind(StrEnum):
    """Infrastructure control channels used to reach an owned scenario VM."""

    QEMU_GUEST_AGENT = "qemu_guest_agent"
    VAGRANT_SSH = "vagrant_ssh"


class ManagementOutcome(StrEnum):
    """Typed distinction between guest completion and transport failure."""

    COMPLETED = "completed"
    TRANSPORT_FAILURE = "transport_failure"
    TIMEOUT = "timeout"


class BackendCapability(StrEnum):
    DEPENDENCY_DETECTION = "dependency_detection"
    VERSION_INSPECTION = "version_inspection"
    IMAGE_INSPECTION = "image_inspection"
    VM_LISTING = "vm_listing"
    VM_CLONE = "vm_clone"
    VM_START = "vm_start"
    VM_STOP = "vm_stop"
    VM_DESTROY = "vm_destroy"
    GUEST_IP = "guest_ip"


class VMState(StrEnum):
    NOT_BUILT = "not_built"
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    MISSING = "missing"
    ERROR = "error"
    UNKNOWN = "unknown"


class ManagementState(StrEnum):
    NOT_READY = "not_ready"
    WAITING = "waiting"
    READY = "ready"
    UNAVAILABLE = "unavailable"


class ProvisioningState(StrEnum):
    NOT_PROVISIONED = "not_provisioned"
    PROVISIONING = "provisioning"
    COMPLETE = "complete"
    FAILED = "failed"


class RuntimeValidationState(StrEnum):
    NOT_RUN = "not_run"
    VALID = "valid"
    INVALID = "invalid"


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
    acquisition: str
    source: str
    template: str


class CVEArtifactPlanStatus(StrictModel):
    id: str
    version: str
    sha256: str
    status: Literal["missing", "ready", "invalid"]


class CVEPlanStatus(StrictModel):
    primitive: str
    cve_id: str
    product: str
    expected_version: str
    artifacts: tuple[CVEArtifactPlanStatus, ...] = Field(min_length=1)


class RuntimePlan(StrictModel):
    scenario_id: str
    host: HostInfo
    runtime: RuntimeResolution
    backend_status: BackendStatus | None = None
    guest: GuestPlan | None = None
    image_status: ImagePlanStatus | None = None
    cve_status: tuple[CVEPlanStatus, ...] = ()
    compatible: bool
    deployable: bool
    issues: tuple[str, ...] = ()
    next_action: str


class VMIdentity(StrictModel):
    name: str
    managed_id: str
    state: VMState
    # Backend-native resource identity. For UTM this is the VM UUID and for
    # Vagrant it is the stable scenario-environment fingerprint, both captured
    # at build time. ``None`` when the metadata predates backend-aware builds;
    # such legacy metadata is never sufficient for Windows mutation. The
    # environment fingerprint must never be replaced by a provider machine ID:
    # it is the stable identity that survives a ``vagrant destroy --force``
    # leaving the Vagrantfile behind.
    resource_id: str | None = None
    # Optional provider-side machine ID (for example the VirtualBox/VMware
    # machine UUID that Vagrant records in ``.vagrant/machines/<name>/
    # <provider>/id`` after the first ``up``). ``None`` during build, and
    # only validated when present; it is additional evidence, never a
    # replacement for ``resource_id``.
    provider_id: str | None = None


class RuntimeTemplateReference(StrictModel):
    image_id: str
    template_id: str
    name: str
    fingerprint: str


class RuntimeGuestState(StrictModel):
    architecture: Architecture
    ip: str | None = None
    management: ManagementState = ManagementState.NOT_READY
    # Persisted guest product and version (for example ``windows`` and
    # ``11``) so status can render the guest OS without consulting mutable
    # guest state. ``None`` for legacy metadata that predates them.
    product: str | None = None
    version: str | None = None
    # Persisted guest platform and management identity. ``None`` means the
    # metadata predates platform-aware builds; legacy metadata is only ever
    # read back as Linux-capable and never as Windows-capable.
    platform: GuestPlatform | None = None
    management_transport: ManagementTransportKind | None = None
    execution_language: ExecutionLanguage | None = None


class LifecycleFailure(StrictModel):
    """Bounded, non-secret lifecycle failure classification.

    ``classification`` is a stable machine-readable token (for example
    ``management_unavailable`` or ``start_timeout``); ``message`` is a
    short, bounded human-readable detail. Credentials, scripts, flags, and
    secret output must never be persisted here.
    """

    classification: str
    message: str = ""


class ManagementResult(StrictModel):
    """Typed result of one management-transport operation.

    ``COMPLETED`` carries the guest process exit code in ``exit_code``.
    ``TRANSPORT_FAILURE`` and ``TIMEOUT`` never carry a guest exit code and
    bound their diagnostics so script content, encoded payloads, credentials,
    or secret canaries can never leak into errors, logs, or metadata.
    """

    outcome: ManagementOutcome
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    detail: str | None = None
    marker_verified: bool = False


class ProvisioningStatus(StrictModel):
    state: ProvisioningState = ProvisioningState.NOT_PROVISIONED
    completed_primitives: tuple[str, ...] = ()
    active_primitive: str | None = None
    plan_fingerprint: str | None = None
    error: str | None = None


class RuntimeValidationStatus(StrictModel):
    state: RuntimeValidationState = RuntimeValidationState.NOT_RUN
    result_path: str | None = None


class RuntimeMetadata(StrictModel):
    scenario_id: str
    profile: str
    runtime: RuntimeType
    backend: VMBackend
    vm: VMIdentity
    template: RuntimeTemplateReference
    guest: RuntimeGuestState
    provisioning: ProvisioningStatus = ProvisioningStatus()
    validation: RuntimeValidationStatus = RuntimeValidationStatus()
    # Deterministic ownership fingerprint binding schema, managed ID,
    # backend, backend-native identity, expected name, template identity and
    # fingerprint, guest platform, and architecture. ``None`` for legacy
    # metadata that predates fingerprint-aware builds.
    ownership_fingerprint: str | None = None
    # Bounded non-secret lifecycle failure record; ``None`` when the last
    # operation did not fail.
    failure: LifecycleFailure | None = None
    metadata_version: int = 4


class LifecycleResult(StrictModel):
    changed: bool
    message: str
    metadata: RuntimeMetadata | None = None
    # Evidence-based ownership confirmation for CLI rendering. ``None`` when
    # there is no persisted metadata to verify; ``True`` only when persisted
    # ownership metadata validated AND the backend-native identity agreed with
    # the persisted identity; ``False`` on any ownership conflict, including a
    # foreign same-name backend resource. The CLI renders VERIFIED only from
    # this typed evidence, never from message parsing.
    ownership_verified: bool | None = None
