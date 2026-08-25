"""Locked, deterministic runtime and VM-backend selection policy."""

from collections.abc import Mapping
from types import MappingProxyType

from rangeforge.host.models import Architecture, HostInfo, HostOS
from rangeforge.models import Primitive
from rangeforge.runtime.models import RuntimeResolution, RuntimeType, VMBackend

# Authoritative mapping of supported host OS/architecture combinations to
# their required VM backend. The resolver and guest capability checks share
# this single read-only policy; neither duplicates nor widens it.
VM_HOST_BACKENDS: Mapping[tuple[HostOS, Architecture], VMBackend] = MappingProxyType(
    {
        (HostOS.DARWIN, Architecture.ARM64): VMBackend.UTM,
        (HostOS.DARWIN, Architecture.AMD64): VMBackend.VAGRANT,
        (HostOS.LINUX, Architecture.AMD64): VMBackend.VAGRANT,
        (HostOS.WINDOWS, Architecture.AMD64): VMBackend.VAGRANT,
    }
)


class RuntimeResolver:
    def resolve(
        self,
        requested: RuntimeType,
        host: HostInfo,
        primitives: tuple[Primitive, ...] = (),
        *,
        guest_architecture: Architecture | None = None,
    ) -> RuntimeResolution:
        """Resolve runtime/backend policy for a host.

        ``guest_architecture`` records the scenario-requested guest
        architecture on the resolution when provided; it never influences
        host or backend selection, which come exclusively from
        ``VM_HOST_BACKENDS``. When omitted, the guest architecture falls
        back to the host architecture for backward compatibility.
        """
        effective_guest_architecture = (
            guest_architecture if guest_architecture is not None else host.architecture
        )
        errors = self._primitive_errors(requested, host.architecture, primitives)
        if host.os is HostOS.UNSUPPORTED or host.architecture is Architecture.UNSUPPORTED:
            errors.append(
                f"Unsupported host: {host.os.value}/{host.architecture.value}."
            )

        if requested is RuntimeType.DOCKER:
            reason = "Docker runtime uses Docker directly; no VM backend is selected."
            return RuntimeResolution(
                runtime=requested,
                backend=None,
                guest_architecture=effective_guest_architecture,
                compatible=not errors,
                reason=reason,
                errors=tuple(errors),
            )

        backend = VM_HOST_BACKENDS.get((host.os, host.architecture))
        if backend is None:
            errors.append(
                "Unsupported for VM runtime in the current RangeForge version: "
                f"{host.os.value}/{host.architecture.value}."
            )
            reason = "No safe VM backend is configured for this host combination."
        elif backend is VMBackend.UTM:
            reason = "macOS ARM64 host uses UTM directly."
        else:
            reason = "AMD64 VM hosts use Vagrant."
        return RuntimeResolution(
            runtime=requested,
            backend=backend,
            guest_architecture=effective_guest_architecture,
            compatible=backend is not None and not errors,
            reason=reason,
            errors=tuple(dict.fromkeys(errors)),
        )

    @staticmethod
    def _primitive_errors(
        runtime: RuntimeType,
        architecture: Architecture,
        primitives: tuple[Primitive, ...],
    ) -> list[str]:
        errors: list[str] = []
        for primitive in primitives:
            if runtime.value not in primitive.runtime_support:
                errors.append(
                    f"Primitive '{primitive.id}' does not support runtime '{runtime.value}'."
                )
            if architecture.value not in primitive.architectures:
                supported = ", ".join(primitive.architectures)
                errors.append(
                    f"Primitive '{primitive.id}' is incompatible with architecture "
                    f"'{architecture.value}' (supports: {supported})."
                )
        return errors
