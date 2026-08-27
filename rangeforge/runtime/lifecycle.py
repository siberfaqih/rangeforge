"""First clean-base scenario VM lifecycle orchestration."""

from __future__ import annotations

import shutil
import time
from collections.abc import Callable
from pathlib import Path

from rangeforge.host.models import HostInfo
from rangeforge.images.manager import ImageManagerError
from rangeforge.images.models import VagrantBox
from rangeforge.images.templates import TemplateManager
from rangeforge.models import Scenario
from rangeforge.runtime.backends.base import BackendOperationError
from rangeforge.runtime.backends.utm import UTMBackend
from rangeforge.runtime.backends.vagrant import VagrantBackend
from rangeforge.runtime.guest import GuestPlatform
from rangeforge.runtime.management import (
    ManagementTransportError,
    effective_guest_platform,
    management_language,
    management_transport_kind,
    probe_windows_management,
)
from rangeforge.runtime.metadata import (
    RuntimeMetadataError,
    RuntimeMetadataStore,
    scenario_managed_id,
    scenario_vm_name,
)
from rangeforge.runtime.models import (
    LifecycleResult,
    ManagementState,
    RuntimeGuestState,
    RuntimeMetadata,
    RuntimePlan,
    RuntimeTemplateReference,
    VMBackend,
    VMIdentity,
    VMState,
)


class LifecycleError(RuntimeError):
    """Raised for expected, actionable lifecycle failures."""


_WINDOWS_MANAGEMENT_SETTLE_SECONDS = 10.0


def _guest_platform_from_family(family: str) -> GuestPlatform:
    """Resolve a profile guest family onto its typed guest platform."""
    normalized = family.strip().lower()
    for platform in GuestPlatform:
        if platform.value == normalized:
            return platform
    raise LifecycleError(f"Unknown guest family: {family!r}.")


def _scenario_platform(scenario: Scenario) -> GuestPlatform | None:
    """Resolve the scenario's requested platform; ``None`` when unknown."""
    normalized = scenario.scenario.platform.strip().lower()
    for platform in GuestPlatform:
        if platform.value == normalized:
            return platform
    return None


def _reject_cross_platform_metadata(metadata: RuntimeMetadata, platform: GuestPlatform) -> None:
    """Fail closed when persisted metadata disagrees with the guest platform.

    Metadata written before platform-aware builds carries no platform and is
    only ever treated as Linux. Silently treating such a record as Linux would
    bypass the fixed Windows readiness probe entirely — a running Windows
    clone could be marked READY from backend IP discovery alone — so a
    disagreeing persisted record must be cleared explicitly.
    """
    persisted = effective_guest_platform(metadata)
    if persisted is platform:
        return
    raise LifecycleError(
        "Persisted runtime metadata describes guest platform "
        f"'{persisted.value}', which does not match the scenario guest "
        f"platform '{platform.value}'. Metadata written by earlier versions "
        "cannot be reconciled for this platform; run destroy to clear stale "
        "metadata before rebuilding."
    )


class ScenarioLifecycle:
    def __init__(
        self,
        *,
        template_manager: TemplateManager,
        host: HostInfo,
        utm: UTMBackend,
        vagrant: VagrantBackend,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self.template_manager = template_manager
        self.host = host
        self.utm = utm
        self.vagrant = vagrant
        self.sleeper = sleeper

    def build(
        self,
        scenario: Scenario,
        scenario_path: Path,
        plan: RuntimePlan,
    ) -> LifecycleResult:
        self._require_deployable(plan)
        assert plan.runtime.backend is not None
        assert plan.guest is not None and plan.guest.image_id is not None
        backend = plan.runtime.backend
        platform = _guest_platform_from_family(plan.guest.family)
        if platform is GuestPlatform.WINDOWS and backend is VMBackend.VAGRANT:
            # Enforced before any backend runner call: Windows management is
            # UTM/QGA-only and Windows Vagrant remains explicitly unsupported.
            raise LifecycleError(
                "Windows Vagrant management is unsupported; Windows scenarios "
                "require the UTM backend with the QEMU Guest Agent."
            )
        template = self.template_manager.require_ready(plan.guest.image_id, backend)
        if template.architecture != self.host.architecture:
            raise LifecycleError(
                f"Template architecture '{template.architecture.value}' does not match host "
                f"architecture '{self.host.architecture.value}'."
            )

        store = RuntimeMetadataStore(scenario_path)
        existing = store.load()
        if existing:
            store.validate_ownership(scenario, existing)
            _reject_cross_platform_metadata(existing, platform)
            if self._resource_exists(existing, store):
                return LifecycleResult(
                    changed=False,
                    message="Scenario VM already exists.",
                    metadata=existing,
                )
            raise LifecycleError(
                "Runtime metadata exists but the managed scenario resource is missing. "
                "Run destroy to clear stale metadata before rebuilding."
            )

        name = scenario_vm_name(scenario)
        if backend is VMBackend.UTM:
            if not self.utm.available():
                raise LifecycleError("UTM backend required but UTM is not installed.")
            if self.utm.vm_exists(name):
                raise LifecycleError(
                    f"Refusing to claim existing UTM VM '{name}' without RangeForge metadata."
                )
            self._backend_call(self.utm.clone, template.reference, name)
        else:
            if not self.vagrant.available():
                raise LifecycleError("Vagrant backend required but Vagrant is unavailable.")
            manifest = self.template_manager.image_manager.registry.require(template.image_id)
            box = manifest.vagrant_box or VagrantBox(name=template.reference)
            if store.vagrant_directory.exists():
                raise LifecycleError(
                    "Refusing to claim an existing Vagrant runtime directory without metadata."
                )
            self.vagrant.prepare_environment(
                store.vagrant_directory, box, name
            )

        metadata = RuntimeMetadata(
            scenario_id=scenario.scenario.id,
            profile=scenario.scenario.profile,
            runtime=plan.runtime.runtime,
            backend=backend,
            vm=VMIdentity(
                name=name,
                managed_id=scenario_managed_id(scenario),
                state=VMState.STOPPED,
            ),
            template=RuntimeTemplateReference(
                image_id=template.image_id,
                template_id=template.id,
                name=template.reference,
                fingerprint=template.fingerprint,
            ),
            guest=RuntimeGuestState(
                architecture=template.architecture,
                platform=platform,
                management_transport=management_transport_kind(backend),
                execution_language=management_language(platform, backend),
            ),
        )
        store.save(metadata)
        return LifecycleResult(
            changed=True,
            message="Scenario VM was built from the prepared base template.",
            metadata=metadata,
        )

    def up(
        self,
        scenario: Scenario,
        scenario_path: Path,
        plan: RuntimePlan,
        *,
        timeout: float = 60,
    ) -> LifecycleResult:
        built = self.build(scenario, scenario_path, plan)
        metadata = built.metadata
        assert metadata is not None
        store = RuntimeMetadataStore(scenario_path)
        windows_guest = effective_guest_platform(metadata) is GuestPlatform.WINDOWS
        state = self._state(metadata, store)
        wedged_ready_probe: tuple[str, ...] | None = None
        if state is VMState.RUNNING and metadata.guest.management is ManagementState.READY:
            if not windows_guest:
                return LifecycleResult(
                    changed=False,
                    message="Scenario VM is already running and management is ready.",
                    metadata=metadata,
                )
            # A previously READY Windows channel may have wedged since the
            # last probe (the exact failure mode the transport defends
            # against). Readiness is re-verified here, never assumed; if the
            # re-probe fails, control falls through so the persisted state
            # converges to RUNNING + UNAVAILABLE below.
            self.sleeper(_WINDOWS_MANAGEMENT_SETTLE_SECONDS)
            ready_now, failed_checks = self._verify_windows_management(
                scenario, scenario_path
            )
            if ready_now:
                return LifecycleResult(
                    changed=False,
                    message="Scenario VM is already running and management is ready.",
                    metadata=metadata,
                )
            wedged_ready_probe = failed_checks or ("management_probe_failed",)

        starting = metadata.model_copy(
            update={
                "vm": metadata.vm.model_copy(update={"state": VMState.STARTING}),
                "guest": metadata.guest.model_copy(
                    update={"management": ManagementState.WAITING}
                ),
            }
        )
        store.save(starting)
        if state is not VMState.RUNNING:
            if metadata.backend is VMBackend.UTM:
                self._backend_call(self.utm.start, metadata.vm.name)
            else:
                self._backend_call(self.vagrant.start, store.vagrant_directory)

        deadline = time.monotonic() + timeout
        current = VMState.STARTING
        while time.monotonic() <= deadline:
            current = self._state(metadata, store)
            if current is VMState.RUNNING:
                break
            self.sleeper(min(1.0, max(timeout, 0.0)))
        if current is not VMState.RUNNING:
            failed = starting.model_copy(
                update={"vm": starting.vm.model_copy(update={"state": VMState.ERROR})}
            )
            store.save(failed)
            raise LifecycleError("Scenario VM did not reach RUNNING before the timeout.")

        addresses = self._ip_addresses(metadata, store)
        while not addresses and time.monotonic() <= deadline:
            self.sleeper(min(1.0, max(timeout, 0.01)))
            addresses = self._ip_addresses(metadata, store)
        # IP discovery alone never proves Windows management readiness; an
        # owned running Windows clone must pass the fixed internal probe.
        if wedged_ready_probe is not None:
            # The stale-READY re-probe already ran above and failed.
            ready, failed_checks = False, wedged_ready_probe
        elif windows_guest:
            # UTM can report a QGA-backed IP before the Windows guest agent's
            # file and exec RPC channels are stable. Starting PowerShell in
            # that interval can wedge command RPC until the guest restarts.
            # This bounded settle window does not imply readiness; the fixed
            # ownership-gated probe below remains the only READY signal.
            self.sleeper(_WINDOWS_MANAGEMENT_SETTLE_SECONDS)
            ready, failed_checks = self._verify_windows_management(scenario, scenario_path)
        else:
            ready = bool(addresses)
            failed_checks = ()
        running = starting.model_copy(
            update={
                "vm": starting.vm.model_copy(update={"state": VMState.RUNNING}),
                "guest": starting.guest.model_copy(
                    update={
                        "ip": addresses[0] if addresses else None,
                        "management": (
                            ManagementState.READY
                            if ready
                            else ManagementState.UNAVAILABLE
                        ),
                    }
                ),
            }
        )
        store.save(running)
        if ready:
            message = "Scenario VM is running and management is ready."
        elif failed_checks:
            message = (
                "Scenario VM is running, but guest management readiness checks "
                f"failed: {', '.join(failed_checks)}."
            )
        else:
            message = (
                "Scenario VM is running, but guest management connectivity is not ready."
            )
        return LifecycleResult(changed=True, message=message, metadata=running)

    def status(self, scenario: Scenario, scenario_path: Path) -> LifecycleResult:
        store = RuntimeMetadataStore(scenario_path)
        metadata = store.load()
        if metadata is None:
            return LifecycleResult(changed=False, message="Scenario VM is not built.")
        store.validate_ownership(scenario, metadata)
        scenario_platform = _scenario_platform(scenario)
        if scenario_platform is not None:
            _reject_cross_platform_metadata(metadata, scenario_platform)
        state = self._state(metadata, store)
        addresses = self._ip_addresses(metadata, store) if state is VMState.RUNNING else ()
        failed_checks: tuple[str, ...] = ()
        if effective_guest_platform(metadata) is GuestPlatform.WINDOWS:
            # Windows management readiness comes only from the internal probe.
            # A persisted READY is re-probed while the clone is running; a
            # channel that wedged after its previous successful probe must be
            # downgraded instead of reporting READY indefinitely.
            if (
                state is VMState.RUNNING
                and metadata.guest.management is ManagementState.READY
            ):
                ready, failed_checks = self._verify_windows_management(
                    scenario, scenario_path
                )
                management = (
                    ManagementState.READY
                    if ready
                    else ManagementState.UNAVAILABLE
                )
            else:
                management = (
                    metadata.guest.management
                    if state is VMState.RUNNING
                    else ManagementState.NOT_READY
                )
        else:
            management = (
                ManagementState.READY if addresses else ManagementState.NOT_READY
            )
        updated = metadata.model_copy(
            update={
                "vm": metadata.vm.model_copy(update={"state": state}),
                "guest": metadata.guest.model_copy(
                    update={
                        "ip": addresses[0] if addresses else None,
                        "management": management,
                    }
                ),
            }
        )
        store.save(updated)
        message = "Runtime status refreshed."
        if failed_checks:
            message += " Windows management checks failed: " + ", ".join(failed_checks) + "."
        return LifecycleResult(changed=False, message=message, metadata=updated)

    def destroy(self, scenario: Scenario, scenario_path: Path) -> LifecycleResult:
        store = RuntimeMetadataStore(scenario_path)
        metadata = store.load()
        if metadata is None:
            store.remove()
            return LifecycleResult(changed=False, message="Scenario VM is already absent.")
        store.validate_ownership(scenario, metadata)
        if metadata.backend is VMBackend.UTM:
            if self.utm.vm_exists(metadata.vm.name):
                state = self.utm.vm_state(metadata.vm.name)
                if state in {VMState.RUNNING, VMState.STARTING}:
                    self._backend_call(self.utm.stop, metadata.vm.name, force=True)
                    deadline = time.monotonic() + 30
                    while (
                        self.utm.vm_state(metadata.vm.name) is not VMState.STOPPED
                        and time.monotonic() <= deadline
                    ):
                        self.sleeper(0.5)
                self._backend_call(self.utm.delete, metadata.vm.name)
        else:
            if self.vagrant.environment_exists(store.vagrant_directory):
                self._backend_call(self.vagrant.delete, store.vagrant_directory)
                self._remove_vagrant_directory(store)
        store.remove()
        return LifecycleResult(changed=True, message="Scenario VM was destroyed.")

    def _verify_windows_management(
        self, scenario: Scenario, scenario_path: Path
    ) -> tuple[bool, tuple[str, ...]]:
        """Probe management readiness on an owned running Windows UTM clone.

        The probe never targets a shared base template: transport construction
        validates persisted ownership metadata first. Any failure leaves
        management NOT_READY/UNAVAILABLE.
        """
        try:
            probe = probe_windows_management(
                scenario,
                scenario_path,
                host=self.host,
                utm=self.utm,
                vagrant=self.vagrant,
                template_manager=self.template_manager,
                expected_architecture=self.host.architecture,
            )
        except (
            ManagementTransportError,
            ImageManagerError,
            RuntimeMetadataError,
            OSError,
        ):
            # Persisted-metadata races, tampering, template-registry failures,
            # and probe setup failures (for example a temporary file error)
            # must leave management unavailable instead of escaping from up().
            return False, ("management_transport_unavailable",)
        failed = tuple(check.name for check in probe.checks if not check.passed)
        return probe.ok, failed

    def _resource_exists(
        self, metadata: RuntimeMetadata, store: RuntimeMetadataStore
    ) -> bool:
        if metadata.backend is VMBackend.UTM:
            return self.utm.vm_exists(metadata.vm.name)
        return self.vagrant.environment_exists(store.vagrant_directory)

    def _state(
        self, metadata: RuntimeMetadata, store: RuntimeMetadataStore
    ) -> VMState:
        if metadata.backend is VMBackend.UTM:
            return self.utm.vm_state(metadata.vm.name)
        return self.vagrant.vm_state(store.vagrant_directory)

    def _ip_addresses(
        self, metadata: RuntimeMetadata, store: RuntimeMetadataStore
    ) -> tuple[str, ...]:
        if metadata.backend is VMBackend.UTM:
            return self.utm.ip_addresses(metadata.vm.name)
        return self.vagrant.ip_addresses(store.vagrant_directory)

    @staticmethod
    def _backend_call(operation: Callable[..., object], *args: object, **kwargs: object) -> None:
        try:
            operation(*args, **kwargs)
        except BackendOperationError as exc:
            raise LifecycleError(str(exc)) from exc

    @staticmethod
    def _require_deployable(plan: RuntimePlan) -> None:
        if not plan.compatible:
            detail = "; ".join(plan.issues) or "runtime plan is incompatible"
            raise LifecycleError(f"Cannot build scenario: {detail}")
        if not plan.deployable:
            raise LifecycleError(
                "Cannot build scenario until the source image, base template, and backend "
                f"are READY. Next action: {plan.next_action}"
            )
        if plan.runtime.backend is None:
            raise LifecycleError("Phase 2B lifecycle currently supports VM runtime only.")

    @staticmethod
    def _remove_vagrant_directory(store: RuntimeMetadataStore) -> None:
        directory = store.vagrant_directory
        if directory.is_symlink():
            directory.unlink()
        elif directory.is_dir() and directory.parent == store.runtime_dir:
            shutil.rmtree(directory)
