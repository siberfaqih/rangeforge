"""Runtime resolution and non-destructive deployment planning."""

from rangeforge.runtime.guest import (
    GUEST_CAPABILITIES,
    ExecutionLanguage,
    GuestCapabilities,
    GuestCompatibility,
    GuestCompatibilityError,
    GuestPlatform,
    GuestRole,
    check_guest_compatibility,
)
from rangeforge.runtime.models import RuntimeType, VMBackend
from rangeforge.runtime.resolver import VM_HOST_BACKENDS, RuntimeResolver

__all__ = [
    "GUEST_CAPABILITIES",
    "VM_HOST_BACKENDS",
    "ExecutionLanguage",
    "GuestCapabilities",
    "GuestCompatibility",
    "GuestCompatibilityError",
    "GuestPlatform",
    "GuestRole",
    "RuntimeResolver",
    "RuntimeType",
    "VMBackend",
    "check_guest_compatibility",
]
