"""Typed guest platform concepts and centralized guest capability metadata.

Guest platform knowledge is data-driven and centralized here so runtime
planning can make deterministic compatibility decisions without hardcoding
platform transitions anywhere else. Valid host/runtime/backend combinations
are reused from the authoritative runtime resolver policy instead of being
duplicated as independent sets. Windows guests are recognized for VM-based
compatibility planning on native ARM64/AMD64 hosts only; Docker, member-server
and domain-controller roles, and execution languages remain denied, and no
cross-architecture emulation is permitted.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from types import MappingProxyType

from rangeforge.host.models import Architecture, HostInfo
from rangeforge.models import StrictModel
from rangeforge.runtime.models import RuntimeType, VMBackend
from rangeforge.runtime.resolver import VM_HOST_BACKENDS

_SUPPORTED_HOST_ARCHITECTURES = frozenset({Architecture.ARM64, Architecture.AMD64})


class GuestPlatform(StrEnum):
    """Logical guest platform families RangeForge can reason about."""

    LINUX = "linux"
    WINDOWS = "windows"


class GuestRole(StrEnum):
    """Role a guest machine plays inside an authorized training scenario."""

    STANDALONE = "standalone"
    MEMBER_SERVER = "member_server"
    DOMAIN_CONTROLLER = "domain_controller"


class ExecutionLanguage(StrEnum):
    """Execution languages available for primitive provisioning on a guest."""

    SHELL = "shell"
    POWERSHELL = "powershell"
    PYTHON = "python"


class GuestCapabilities(StrictModel):
    """Data-driven capability metadata for one guest platform.

    This is the single source of truth for what a guest platform supports.
    Absence means "not supported" (default-deny). Valid host and VM-backend
    combinations are not duplicated here; they are reused from the
    authoritative resolver policy (``VM_HOST_BACKENDS``).
    """

    platform: GuestPlatform
    runtimes: tuple[RuntimeType, ...] = ()
    architectures: tuple[Architecture, ...] = ()
    execution_languages: tuple[ExecutionLanguage, ...] = ()
    roles: tuple[GuestRole, ...] = ()
    cross_architecture_emulation: bool = False


_LINUX_CAPABILITIES = GuestCapabilities(
    platform=GuestPlatform.LINUX,
    runtimes=(RuntimeType.DOCKER, RuntimeType.VM),
    architectures=(Architecture.ARM64, Architecture.AMD64),
    execution_languages=(ExecutionLanguage.SHELL, ExecutionLanguage.PYTHON),
    roles=(GuestRole.STANDALONE,),
)

# Phase 5.2: Windows guests are recognized for VM-based compatibility
# planning on native ARM64/AMD64 hosts. Docker, member-server and
# domain-controller roles, and execution languages remain denied, and
# cross-architecture emulation stays forbidden. Deployment readiness is
# separately gated on reviewed media checksums; capability metadata never
# makes an image ready.
_WINDOWS_CAPABILITIES = GuestCapabilities(
    platform=GuestPlatform.WINDOWS,
    runtimes=(RuntimeType.VM,),
    architectures=(Architecture.ARM64, Architecture.AMD64),
    roles=(GuestRole.STANDALONE,),
    execution_languages=(),
    cross_architecture_emulation=False,
)

GUEST_CAPABILITIES: Mapping[GuestPlatform, GuestCapabilities] = MappingProxyType(
    {
        GuestPlatform.LINUX: _LINUX_CAPABILITIES,
        GuestPlatform.WINDOWS: _WINDOWS_CAPABILITIES,
    }
)


class GuestCompatibility(StrictModel):
    """Deterministic result of a guest capability check.

    ``platform`` is ``None`` when the requested family maps to no known
    guest platform; such requests are never compatible.
    """

    platform: GuestPlatform | None
    compatible: bool
    reason: str
    errors: tuple[str, ...] = ()


class GuestCompatibilityError(ValueError):
    """Raised when a guest platform is unknown to RangeForge."""


def guest_capabilities(platform: GuestPlatform) -> GuestCapabilities:
    """Return the read-only capability metadata for a known guest platform."""
    try:
        return GUEST_CAPABILITIES[platform]
    except KeyError:
        raise GuestCompatibilityError(
            f"Unknown guest platform: {platform!r}."
        ) from None


def _platform_from_value(value: str) -> GuestPlatform | None:
    normalized = value.strip().lower()
    for platform in GuestPlatform:
        if platform.value == normalized:
            return platform
    return None


def check_guest_compatibility(
    *,
    platform: str,
    family: str,
    runtime: RuntimeType,
    backend: VMBackend | None,
    architecture: Architecture,
    host: HostInfo,
) -> GuestCompatibility:
    """Check a requested guest configuration against capability metadata.

    The check is pure and deterministic and fails closed. The scenario
    platform and the profile guest/image family must resolve to the same
    known guest platform; otherwise the request is rejected before any
    image resolution. A combination is compatible only when the platform
    explicitly supports the runtime and architecture, the VM backend
    matches the authoritative host policy in ``VM_HOST_BACKENDS``, and the
    guest architecture matches the host without silent cross-architecture
    emulation.
    """
    errors: list[str] = []

    scenario_platform = _platform_from_value(platform)
    family_platform = _platform_from_value(family)

    if scenario_platform is None:
        errors.append(f"Unknown guest platform: {platform!r}.")
    if family_platform is None:
        errors.append(f"Unknown guest family: {family!r}.")
    if (
        scenario_platform is not None
        and family_platform is not None
        and scenario_platform is not family_platform
    ):
        errors.append(
            f"Guest family '{family}' does not match scenario platform "
            f"'{platform}'; the profile guest requirement and the scenario "
            "platform must describe the same guest platform."
        )

    resolved = scenario_platform or family_platform

    if resolved is None:
        return GuestCompatibility(
            platform=None,
            compatible=False,
            reason="; ".join(errors),
            errors=tuple(errors),
        )

    capabilities = guest_capabilities(resolved)

    if runtime not in capabilities.runtimes:
        supported = ", ".join(item.value for item in capabilities.runtimes) or "none"
        errors.append(
            f"Guest platform '{resolved.value}' does not support runtime "
            f"'{runtime.value}' (supported: {supported})."
        )

    if architecture not in capabilities.architectures:
        supported = (
            ", ".join(item.value for item in capabilities.architectures) or "none"
        )
        errors.append(
            f"Guest platform '{resolved.value}' does not support guest architecture "
            f"'{architecture.value}' (supported: {supported})."
        )

    if runtime is RuntimeType.VM:
        expected = VM_HOST_BACKENDS.get((host.os, host.architecture))
        if expected is None:
            errors.append(
                "No VM backend is configured for host "
                f"{host.os.value}/{host.architecture.value}."
            )
        elif backend is None:
            errors.append(
                f"Guest platform '{resolved.value}' requires a VM backend, "
                "but none was resolved."
            )
        elif backend is not expected:
            errors.append(
                f"VM backend '{backend.value}' is not valid for host "
                f"{host.os.value}/{host.architecture.value}; "
                f"'{expected.value}' is required."
            )

    if (
        not capabilities.cross_architecture_emulation
        and host.architecture in _SUPPORTED_HOST_ARCHITECTURES
        and architecture is not host.architecture
    ):
        errors.append(
            f"Guest architecture '{architecture.value}' does not match host "
            f"architecture '{host.architecture.value}'; silent cross-architecture "
            "emulation or substitution is not permitted."
        )

    if errors:
        reason = (
            f"Guest platform '{resolved.value}' is not compatible with the "
            f"requested {runtime.value} deployment."
        )
    else:
        reason = (
            f"Guest platform '{resolved.value}' supports {runtime.value} on "
            f"{architecture.value}."
        )

    return GuestCompatibility(
        platform=resolved,
        compatible=not errors,
        reason=reason,
        errors=tuple(errors),
    )
