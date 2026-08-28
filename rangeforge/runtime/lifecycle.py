"""First clean-base scenario VM lifecycle orchestration."""

from __future__ import annotations

import shutil
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from rangeforge.host.models import HostInfo
from rangeforge.images.manager import ImageManagerError
from rangeforge.images.models import BaseTemplate, VagrantBox
from rangeforge.images.templates import TemplateManager
from rangeforge.models import Scenario
from rangeforge.runtime.backends.base import BackendOperationError
from rangeforge.runtime.backends.utm import UTMBackend
from rangeforge.runtime.backends.vagrant import (
    VagrantBackend,
    vagrant_environment_fingerprint,
)
from rangeforge.runtime.guest import GuestPlatform
from rangeforge.runtime.management import (
    ManagementTransportError,
    effective_guest_platform,
    management_language,
    management_transport_kind,
    probe_windows_management,
)
from rangeforge.runtime.metadata import (
    METADATA_SCHEMA_VERSION,
    RuntimeMetadataError,
    RuntimeMetadataStore,
    ownership_fingerprint,
    scenario_managed_id,
    scenario_vm_name,
)
from rangeforge.runtime.models import (
    LifecycleFailure,
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
from rangeforge.runtime.resolver import VM_HOST_BACKENDS

# Number of seconds to wait for a stop request to converge to STOPPED.
_STOP_CONVERGENCE_TIMEOUT = 60.0
# Number of seconds to wait for a start request to converge to RUNNING.
_START_CONVERGENCE_TIMEOUT = 120.0
# Bounded, non-secret classification tokens used in persisted failure records.
_FAILURE_START_TIMEOUT = "start_timeout"
_FAILURE_MANAGEMENT_UNAVAILABLE = "management_unavailable"
_FAILURE_STOP_TIMEOUT = "stop_timeout"


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


@dataclass(frozen=True)
class _BackendState:
    """Reconciled backend state plus an optional ownership conflict message."""

    state: VMState
    conflict: str | None = None


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

    # ------------------------------------------------------------------
    # Shared pre-mutation gates
    # ------------------------------------------------------------------

    def _require_deployable(self, plan: RuntimePlan) -> None:
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

    def _expected_backend(self) -> VMBackend:
        expected = VM_HOST_BACKENDS.get((self.host.os, self.host.architecture))
        if expected is None:
            raise LifecycleError(
                f"No VM backend is configured for host "
                f"{self.host.os.value}/{self.host.architecture.value}."
            )
        return expected

    def _preflight_plan(self, scenario: Scenario, plan: RuntimePlan) -> None:
        """Shared plan/scenario/host/backend consistency gate before mutation.

        The planner remains authoritative for compatibility decisions; this
        gate only verifies that the supplied plan is consistent with the
        scenario being operated on and the detected host before any backend
        mutation. It never re-derives compatibility policy.
        """
        self._require_deployable(plan)
        if plan.scenario_id != scenario.scenario.id:
            raise LifecycleError(
                f"Runtime plan belongs to scenario '{plan.scenario_id}', not "
                f"'{scenario.scenario.id}'."
            )
        # Compare normalized host policy identity (OS, architecture, Apple
        # Silicon), not executable paths: two host observations on the same
        # machine with different backend executable paths are the same
        # normalized host. Host/backend/architecture substitution is still
        # rejected below through the backend and guest-architecture checks.
        plan_host = (
            plan.host.os,
            plan.host.architecture,
            plan.host.apple_silicon,
        )
        current_host = (
            self.host.os,
            self.host.architecture,
            self.host.apple_silicon,
        )
        if plan_host != current_host:
            raise LifecycleError(
                "Runtime plan was built for a different normalized host and cannot "
                "be used for this lifecycle operation."
            )
        assert plan.runtime.backend is not None
        expected = self._expected_backend()
        if plan.runtime.backend is not expected:
            raise LifecycleError(
                f"Runtime plan backend '{plan.runtime.backend.value}' does not match "
                f"the host-required backend '{expected.value}'."
            )
        assert plan.guest is not None
        scenario_platform = _scenario_platform(scenario)
        if scenario_platform is not None:
            plan_platform = _guest_platform_from_family(plan.guest.family)
            if plan_platform is not scenario_platform:
                raise LifecycleError(
                    f"Runtime plan guest family '{plan.guest.family}' does not match "
                    f"the scenario platform '{scenario_platform.value}'."
                )
        if plan.guest.architecture is not self.host.architecture:
            raise LifecycleError(
                f"Runtime plan guest architecture '{plan.guest.architecture.value}' "
                f"does not match host architecture '{self.host.architecture.value}'."
            )

    def _preflight_ownership(
        self, scenario: Scenario, metadata: RuntimeMetadata, store: RuntimeMetadataStore
    ) -> None:
        """Shared persisted-ownership + host/backend/platform consistency gate.

        Used by plan-less operations (status, stop, destroy) and by build/up
        after planning. Fails closed on any disagreement before a mutation.
        """
        store.validate_ownership(scenario, metadata)
        scenario_platform = _scenario_platform(scenario)
        if scenario_platform is not None:
            _reject_cross_platform_metadata(metadata, scenario_platform)
        if metadata.backend is not self._expected_backend():
            raise LifecycleError(
                f"Persisted backend '{metadata.backend.value}' is not valid for host "
                f"{self.host.os.value}/{self.host.architecture.value}."
            )
        if metadata.guest.architecture is not self.host.architecture:
            raise LifecycleError(
                f"Persisted guest architecture '{metadata.guest.architecture.value}' "
                f"does not match host architecture '{self.host.architecture.value}'."
            )
        if metadata.backend is VMBackend.UTM:
            if not self.utm.available():
                raise LifecycleError("UTM backend required but UTM is not installed.")
        else:
            if not self.vagrant.available():
                raise LifecycleError("Vagrant backend required but Vagrant is unavailable.")

    # ------------------------------------------------------------------
    # Backend state reconciliation
    # ------------------------------------------------------------------

    def _backend_state(
        self, metadata: RuntimeMetadata, store: RuntimeMetadataStore
    ) -> _BackendState:
        """Reconcile actual backend state against persisted identity.

        New backend-aware metadata is reconciled strictly by backend-native
        identity. Legacy metadata (without a resource identity) falls back to
        name-based lookup to preserve historical Linux behavior; it is never
        upgraded into strict ownership and can never represent Windows.
        """
        resource_id = metadata.vm.resource_id
        if metadata.backend is VMBackend.UTM:
            if resource_id is None:
                record = self.utm.find_by_name(metadata.vm.name)
                if record is None:
                    return _BackendState(state=VMState.MISSING)
                return _BackendState(state=record.vm_state)
            record = self.utm.find_by_uuid(resource_id)
            if record is None:
                foreign = self.utm.find_by_name(metadata.vm.name)
                if foreign is not None:
                    return _BackendState(
                        state=VMState.UNKNOWN,
                        conflict=(
                            f"Existing UTM VM '{metadata.vm.name}' has a different "
                            "backend identity than this scenario's persisted UUID."
                        ),
                    )
                return _BackendState(state=VMState.MISSING)
            if record.name != metadata.vm.name:
                return _BackendState(
                    state=VMState.UNKNOWN,
                    conflict=(
                        f"UTM resource UUID '{resource_id}' is named '{record.name}', "
                        f"not '{metadata.vm.name}'."
                    ),
                )
            return _BackendState(state=record.vm_state)
        if not self.vagrant.environment_exists(store.vagrant_directory):
            return _BackendState(state=VMState.MISSING)
        if resource_id is not None:
            fingerprint = vagrant_environment_fingerprint(
                store.vagrant_directory,
                metadata.vm.name,
                self._vagrant_box_for(metadata, store),
            )
            if fingerprint != resource_id:
                return _BackendState(
                    state=VMState.UNKNOWN,
                    conflict=(
                        "The scenario Vagrant environment fingerprint does not match "
                        "the persisted environment identity."
                    ),
                )
        # The provider machine ID is secondary evidence recorded after boot;
        # it is validated only when both the persisted record and the current
        # backend expose one. A missing machine ID (for example a halted or
        # never-booted environment) never invalidates ownership, and the
        # provider ID never replaces the stable environment fingerprint.
        provider_id = metadata.vm.provider_id
        if provider_id is not None:
            machine_id = self.vagrant.machine_id(store.vagrant_directory)
            if machine_id is not None and machine_id != provider_id:
                return _BackendState(
                    state=VMState.UNKNOWN,
                    conflict=(
                        "The scenario Vagrant provider machine ID does not match "
                        "the persisted provider identity."
                    ),
                )
        return _BackendState(state=self.vagrant.vm_state(store.vagrant_directory))

    def _resource_identity_agrees(
        self, metadata: RuntimeMetadata, store: RuntimeMetadataStore
    ) -> _BackendState:
        """Reconcile the persisted resource identity against the backend."""
        return self._backend_state(metadata, store)

    def _vagrant_box_for(
        self, metadata: RuntimeMetadata, store: RuntimeMetadataStore
    ) -> VagrantBox:
        manifest = self.template_manager.image_manager.registry.require(
            metadata.template.image_id
        )
        return manifest.vagrant_box or VagrantBox(name=metadata.template.name)

    def _ip_addresses(
        self, metadata: RuntimeMetadata, store: RuntimeMetadataStore
    ) -> tuple[str, ...]:
        if metadata.backend is VMBackend.UTM:
            return self.utm.ip_addresses(metadata.vm.name, uuid=metadata.vm.resource_id)
        return self.vagrant.ip_addresses(store.vagrant_directory)

    # ------------------------------------------------------------------
    # Build
    # ------------------------------------------------------------------

    def build(
        self,
        scenario: Scenario,
        scenario_path: Path,
        plan: RuntimePlan,
    ) -> LifecycleResult:
        self._preflight_plan(scenario, plan)
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
        if template.image_id != plan.guest.image_id:
            raise LifecycleError(
                f"Prepared template image '{template.image_id}' does not match the "
                f"plan image '{plan.guest.image_id}'."
            )

        store = RuntimeMetadataStore(scenario_path)
        existing = store.load()
        if existing:
            self._preflight_ownership(scenario, existing, store)
            self._verify_idempotent_build(existing, store, plan, template)
            return LifecycleResult(
                changed=False,
                message="Scenario VM already exists.",
                metadata=existing,
                ownership_verified=True,
            )

        name = scenario_vm_name(scenario)
        if backend is VMBackend.UTM:
            if not self.utm.available():
                raise LifecycleError("UTM backend required but UTM is not installed.")
            existing_record = self.utm.find_by_name(name)
            if existing_record is not None:
                raise LifecycleError(
                    f"Refusing to claim existing UTM VM '{name}' without RangeForge metadata."
                )
            if not self.utm.template_exists(template.reference):
                raise LifecycleError(
                    f"Prepared base template '{template.reference}' is not present in the "
                    "UTM backend; prepare it before cloning."
                )
            self._backend_call(self.utm.clone, template.reference, name)
            record = self.utm.find_by_name(name)
            if record is None:
                raise LifecycleError(
                    f"Scenario clone '{name}' was created but its backend identity could "
                    "not be established; the resource is an orphan and must be resolved "
                    "manually."
                )
            if record.name != name or record.vm_state is not VMState.STOPPED:
                raise LifecycleError(
                    f"Scenario clone '{name}' was created but is not a stopped VM "
                    "matching the expected identity."
                )
            resource_id = record.uuid
        else:
            if not self.vagrant.available():
                raise LifecycleError("Vagrant backend required but Vagrant is unavailable.")
            manifest = self.template_manager.image_manager.registry.require(template.image_id)
            box = manifest.vagrant_box or VagrantBox(name=template.reference)
            if store.vagrant_directory.exists():
                raise LifecycleError(
                    "Refusing to claim an existing Vagrant runtime directory without metadata."
                )
            if not self.vagrant.template_exists(template.reference):
                raise LifecycleError(
                    f"Prepared base template '{template.reference}' is not present in the "
                    "Vagrant backend; prepare it before cloning."
                )
            self.vagrant.prepare_environment(
                store.vagrant_directory, box, name
            )
            resource_id = vagrant_environment_fingerprint(
                store.vagrant_directory, name, box
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
                resource_id=resource_id,
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
                product=plan.guest.distribution,
                version=plan.guest.version,
                management_transport=management_transport_kind(backend),
                execution_language=management_language(platform, backend),
            ),
            metadata_version=METADATA_SCHEMA_VERSION,
        )
        metadata = metadata.model_copy(
            update={"ownership_fingerprint": ownership_fingerprint(metadata)}
        )
        store.save(metadata)
        return LifecycleResult(
            changed=True,
            message="Scenario VM was built from the prepared base template.",
            metadata=metadata,
            ownership_verified=True,
        )

    def _verify_idempotent_build(
        self,
        metadata: RuntimeMetadata,
        store: RuntimeMetadataStore,
        plan: RuntimePlan,
        template: BaseTemplate,
    ) -> None:
        """Return unchanged only when every persisted identity agrees.

        The current plan must match persisted host/backend/image/platform and
        architecture identity, template provenance and fingerprint must match
        the current selected template, and the backend-native resource must
        exist with matching identity. A missing resource is stale state that
        build must never silently replace.
        """
        assert plan.guest is not None and plan.guest.image_id is not None
        if plan.guest.image_id != metadata.template.image_id:
            raise LifecycleError(
                "Persisted runtime metadata references a different image than the "
                "current runtime plan."
            )
        if plan.guest.architecture is not metadata.guest.architecture:
            raise LifecycleError(
                "Persisted guest architecture does not match the current runtime plan."
            )
        if plan.runtime.backend is not metadata.backend:
            raise LifecycleError(
                "Persisted runtime metadata uses a different backend than the current "
                "runtime plan."
            )
        if (
            template.id,
            template.reference,
            template.fingerprint,
        ) != (
            metadata.template.template_id,
            metadata.template.name,
            metadata.template.fingerprint,
        ):
            raise LifecycleError(
                "Persisted base-template identity does not match the current prepared "
                "template; the shared template changed since this scenario was built."
            )
        state = self._resource_identity_agrees(metadata, store)
        if state.conflict is not None:
            raise LifecycleError(f"Ownership conflict: {state.conflict}")
        if state.state in {VMState.MISSING, VMState.NOT_BUILT}:
            raise LifecycleError(
                "Runtime metadata exists but the managed scenario resource is missing. "
                "Run destroy to clear stale metadata before rebuilding."
            )

    # ------------------------------------------------------------------
    # Up
    # ------------------------------------------------------------------

    def up(
        self,
        scenario: Scenario,
        scenario_path: Path,
        plan: RuntimePlan,
        *,
        timeout: float = _START_CONVERGENCE_TIMEOUT,
    ) -> LifecycleResult:
        built = self.build(scenario, scenario_path, plan)
        metadata = built.metadata
        assert metadata is not None
        store = RuntimeMetadataStore(scenario_path)
        # One total operation deadline bounds start convergence, address
        # refresh, settle behavior, and the Phase 5.3 readiness probe.
        deadline = time.monotonic() + max(0.0, timeout)
        windows_guest = effective_guest_platform(metadata) is GuestPlatform.WINDOWS
        state = self._backend_state(metadata, store)
        if state.conflict is not None:
            raise LifecycleError(f"Ownership conflict: {state.conflict}")
        # F-4: non-actionable backend states must fail closed before any
        # mutation, before persisting STARTING, and before issuing a start.
        if state.state is VMState.UNKNOWN:
            raise LifecycleError(
                "Scenario VM backend state is unknown; refusing to start."
            )
        if state.state in {VMState.MISSING, VMState.NOT_BUILT}:
            raise LifecycleError(
                "Scenario VM is missing from the backend; run destroy to clear stale "
                "metadata."
            )
        wedged_ready_probe: tuple[str, ...] | None = None
        if state.state is VMState.RUNNING and metadata.guest.management is ManagementState.READY:
            if not windows_guest:
                return LifecycleResult(
                    changed=False,
                    message="Scenario VM is already running and management is ready.",
                    metadata=metadata,
                    ownership_verified=True,
                )
            # A previously READY Windows channel may have wedged since the
            # last probe. Readiness is re-verified here, never assumed, under
            # the remaining operation deadline.
            remaining = max(0.0, deadline - time.monotonic())
            self.sleeper(min(_WINDOWS_MANAGEMENT_SETTLE_SECONDS, remaining))
            remaining = max(0.0, deadline - time.monotonic())
            ready_now, failed_checks = self._verify_windows_management(
                scenario, scenario_path, budget=remaining
            )
            if ready_now:
                return LifecycleResult(
                    changed=False,
                    message="Scenario VM is already running and management is ready.",
                    metadata=metadata,
                    ownership_verified=True,
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
        starting = starting.model_copy(update={"failure": None})
        store.save(starting)
        # F-3: A start is issued exactly once, only from STOPPED. STARTING
        # (already starting) polls without a duplicate start. RUNNING skips
        # start entirely. Non-actionable states were already rejected above.
        if state.state is VMState.STOPPED:
            if metadata.backend is VMBackend.UTM:
                self._backend_call(
                    self.utm.start, metadata.vm.name, uuid=metadata.vm.resource_id
                )
            else:
                self._backend_call(self.vagrant.start, store.vagrant_directory)

        # F-9: track the last truthful observed backend state; on timeout it
        # is persisted alongside the failure classification, not overwritten
        # with a synthetic ERROR.
        current: VMState = state.state
        while time.monotonic() <= deadline:
            reconciled = self._backend_state(metadata, store)
            if reconciled.conflict is not None:
                raise LifecycleError(f"Ownership conflict: {reconciled.conflict}")
            current = reconciled.state
            if current is VMState.RUNNING:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            # F-12: poll sleep clamped to remaining deadline.
            self.sleeper(min(1.0, remaining))
        if current is not VMState.RUNNING:
            failed = starting.model_copy(
                update={
                    "vm": starting.vm.model_copy(update={"state": current}),
                    "failure": LifecycleFailure(
                        classification=_FAILURE_START_TIMEOUT,
                        message="Scenario VM did not reach RUNNING before the deadline.",
                    ),
                }
            )
            store.save(failed)
            raise LifecycleError("Scenario VM did not reach RUNNING before the deadline.")

        addresses = self._ip_addresses(metadata, store)
        while not addresses and time.monotonic() <= deadline:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            # F-12: address poll sleep clamped to remaining deadline.
            self.sleeper(min(1.0, remaining))
            addresses = self._ip_addresses(metadata, store)
        # IP discovery alone never proves Windows management readiness; an
        # owned running Windows clone must pass the fixed internal probe.
        if wedged_ready_probe is not None:
            # The stale-READY re-probe already ran above and failed.
            ready, failed_checks = False, wedged_ready_probe
        elif windows_guest:
            # F-6: the settle window is bounded by the remaining operation
            # deadline, and no management operation is issued after expiry.
            remaining = max(0.0, deadline - time.monotonic())
            self.sleeper(min(_WINDOWS_MANAGEMENT_SETTLE_SECONDS, remaining))
            remaining = max(0.0, deadline - time.monotonic())
            if remaining <= 0:
                ready, failed_checks = False, ("operation_deadline_expired",)
            else:
                ready, failed_checks = self._verify_windows_management(
                    scenario, scenario_path, budget=remaining
                )
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
        if not ready and windows_guest:
            # Only Windows management readiness is a hard lifecycle
            # requirement (the Phase 5.3 probe). Linux readiness stays
            # IP-based per the established semantics: RUNNING without an
            # address returns success with management UNAVAILABLE and no
            # contradictory failure record.
            running = running.model_copy(
                update={
                    "failure": LifecycleFailure(
                        classification=_FAILURE_MANAGEMENT_UNAVAILABLE,
                        message=(
                            "Scenario VM is running but Windows management readiness "
                            "could not be established."
                        ),
                    )
                }
            )
        # Persist the Vagrant provider machine ID once it becomes available
        # after boot. The stable environment fingerprint in ``resource_id``
        # is never replaced (F-1/F-5); the provider ID is additional evidence
        # stored in the separate ``provider_id`` field.
        if metadata.backend is VMBackend.VAGRANT:
            machine_id = self.vagrant.machine_id(store.vagrant_directory)
            if machine_id and running.vm.provider_id != machine_id:
                running = running.model_copy(
                    update={
                        "vm": running.vm.model_copy(
                            update={"provider_id": machine_id}
                        )
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
        if not ready and windows_guest:
            # Management failure must produce an explicit lifecycle failure and
            # nonzero CLI exit while preserving the truthful persisted state.
            raise LifecycleError(message)
        return LifecycleResult(
            changed=True,
            message=message,
            metadata=running,
            ownership_verified=True,
        )

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def status(self, scenario: Scenario, scenario_path: Path) -> LifecycleResult:
        store = RuntimeMetadataStore(scenario_path)
        metadata = store.load()
        if metadata is None:
            return self._status_unbuilt(scenario, store)
        self._preflight_ownership(scenario, metadata, store)
        reconciled = self._backend_state(metadata, store)
        if reconciled.conflict is not None:
            return LifecycleResult(
                changed=False,
                message=f"Ownership conflict: {reconciled.conflict}",
                metadata=metadata,
                ownership_verified=False,
            )
        state = reconciled.state
        addresses = self._ip_addresses(metadata, store) if state is VMState.RUNNING else ()
        failed_checks: tuple[str, ...] = ()
        if effective_guest_platform(metadata) is GuestPlatform.WINDOWS:
            if state is VMState.RUNNING:
                # Every running Windows clone is re-probed regardless of its
                # persisted management state; stale READY is never trusted and
                # a false NOT_READY can recover here.
                ready, failed_checks = self._verify_windows_management(
                    scenario, scenario_path
                )
                management = ManagementState.READY if ready else ManagementState.UNAVAILABLE
            else:
                management = ManagementState.NOT_READY
        else:
            management = (
                ManagementState.READY if addresses else ManagementState.NOT_READY
            )
        # A failure record describes the last failed lifecycle operation.
        # Once status observes a fully healthy state (running with ready
        # management, or cleanly stopped), the stale record no longer
        # reflects backend reality and is cleared.
        healthy = (
            state is VMState.RUNNING and management is ManagementState.READY
        ) or (state is VMState.STOPPED and management is ManagementState.NOT_READY)
        updated = metadata.model_copy(
            update={
                "vm": metadata.vm.model_copy(update={"state": state}),
                "guest": metadata.guest.model_copy(
                    update={
                        "ip": addresses[0] if addresses else None,
                        "management": management,
                    }
                ),
                "failure": None if healthy else metadata.failure,
            }
        )
        changed = updated != metadata
        if changed:
            store.save(updated)
        message = "Runtime status refreshed."
        if failed_checks:
            message += " Windows management checks failed: " + ", ".join(failed_checks) + "."
        return LifecycleResult(
            changed=changed,
            message=message,
            metadata=updated,
            ownership_verified=True,
        )

    def _status_unbuilt(
        self, scenario: Scenario, store: RuntimeMetadataStore
    ) -> LifecycleResult:
        """No metadata: report NOT_BUILT or an ownership conflict.

        An existing expected-name backend object without metadata is a
        conflict that must never be adopted.
        """
        name = scenario_vm_name(scenario)
        expected = self._expected_backend()
        if expected is VMBackend.UTM:
            if self.utm.find_by_name(name) is not None:
                return LifecycleResult(
                    changed=False,
                    message=(
                        f"Existing UTM VM '{name}' has no RangeForge metadata; "
                        "ownership conflict, refusing to adopt."
                    ),
                )
        elif store.vagrant_directory.exists():
            return LifecycleResult(
                changed=False,
                message=(
                    "Existing Vagrant runtime directory has no RangeForge metadata; "
                    "ownership conflict, refusing to adopt."
                ),
            )
        return LifecycleResult(changed=False, message="Scenario VM is not built.")

    # ------------------------------------------------------------------
    # Stop
    # ------------------------------------------------------------------

    def stop(
        self,
        scenario: Scenario,
        scenario_path: Path,
        *,
        timeout: float = _STOP_CONVERGENCE_TIMEOUT,
    ) -> LifecycleResult:
        store = RuntimeMetadataStore(scenario_path)
        metadata = store.load()
        if metadata is None:
            return LifecycleResult(changed=False, message="Scenario VM is not built.")
        self._preflight_ownership(scenario, metadata, store)
        reconciled = self._backend_state(metadata, store)
        if reconciled.conflict is not None:
            raise LifecycleError(f"Ownership conflict: {reconciled.conflict}")
        state = reconciled.state
        if state is VMState.STOPPED:
            return LifecycleResult(
                changed=False,
                message="Scenario VM is already stopped.",
                metadata=metadata,
                ownership_verified=True,
            )
        if state is VMState.UNKNOWN:
            raise LifecycleError(
                "Scenario VM backend state is unknown; refusing to stop."
            )
        if state in {VMState.MISSING, VMState.NOT_BUILT}:
            raise LifecycleError(
                "Scenario VM is missing from the backend; run destroy to clear stale "
                "metadata."
            )
        stopping = metadata.model_copy(
            update={
                "vm": metadata.vm.model_copy(update={"state": VMState.STOPPING}),
                "guest": metadata.guest.model_copy(
                    update={"management": ManagementState.NOT_READY}
                ),
                "failure": None,
            }
        )
        store.save(stopping)
        # Documented limitation: stop requests are not interlocked. Two
        # concurrent stop() calls may each observe RUNNING, persist STOPPING,
        # and issue one backend stop request each. Duplicate stop requests
        # converge to the same STOPPED state and the last metadata write wins;
        # ownership validation still gates every write, but callers must not
        # run concurrent stop() operations against one scenario expecting
        # exactly-one-request semantics.
        # F-14: a stop request is issued exactly once, from RUNNING or
        # STARTING. A VM already STOPPING must continue polling without a
        # duplicate stop request.
        if state in {VMState.RUNNING, VMState.STARTING}:
            if metadata.backend is VMBackend.UTM:
                self._backend_call(
                    self.utm.stop, metadata.vm.name, force=False, uuid=metadata.vm.resource_id
                )
            else:
                self._backend_call(self.vagrant.stop, store.vagrant_directory)
        deadline = time.monotonic() + max(0.0, timeout)
        current = VMState.STOPPING
        while time.monotonic() <= deadline:
            reconciled = self._backend_state(metadata, store)
            if reconciled.conflict is not None:
                raise LifecycleError(f"Ownership conflict: {reconciled.conflict}")
            current = reconciled.state
            if current is VMState.STOPPED:
                break
            if current is VMState.UNKNOWN:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            self.sleeper(min(0.5, remaining))
        if current is not VMState.STOPPED:
            failed = stopping.model_copy(
                update={
                    "vm": stopping.vm.model_copy(update={"state": current}),
                    "failure": LifecycleFailure(
                        classification=_FAILURE_STOP_TIMEOUT,
                        message="Scenario VM did not reach STOPPED before the deadline.",
                    ),
                }
            )
            store.save(failed)
            raise LifecycleError("Scenario VM did not stop before the deadline.")
        stopped = stopping.model_copy(
            update={
                "vm": stopping.vm.model_copy(update={"state": VMState.STOPPED}),
                "guest": stopping.guest.model_copy(update={"ip": None}),
            }
        )
        store.save(stopped)
        return LifecycleResult(
            changed=True,
            message="Scenario VM was stopped.",
            metadata=stopped,
            ownership_verified=True,
        )

    # ------------------------------------------------------------------
    # Destroy
    # ------------------------------------------------------------------

    def destroy(self, scenario: Scenario, scenario_path: Path) -> LifecycleResult:
        store = RuntimeMetadataStore(scenario_path)
        metadata = store.load()
        if metadata is None:
            store.remove()
            return LifecycleResult(changed=False, message="Scenario VM is already absent.")
        self._preflight_ownership(scenario, metadata, store)
        reconciled = self._backend_state(metadata, store)
        if reconciled.conflict is not None:
            raise LifecycleError(f"Ownership conflict: {reconciled.conflict}")
        state = reconciled.state
        if state in {VMState.RUNNING, VMState.STARTING, VMState.STOPPING}:
            # Stop convergence is mandatory before any delete; a timeout must
            # never continue into deletion. A VM already STOPPING receives no
            # duplicate stop request; polling below converges it.
            if state in {VMState.RUNNING, VMState.STARTING}:
                if metadata.backend is VMBackend.UTM:
                    self._backend_call(
                        self.utm.stop,
                        metadata.vm.name,
                        force=True,
                        uuid=metadata.vm.resource_id,
                    )
                else:
                    self._backend_call(self.vagrant.stop, store.vagrant_directory)
            deadline = time.monotonic() + _STOP_CONVERGENCE_TIMEOUT
            current = VMState.STOPPING
            while time.monotonic() <= deadline:
                recon = self._backend_state(metadata, store)
                if recon.conflict is not None:
                    raise LifecycleError(f"Ownership conflict: {recon.conflict}")
                current = recon.state
                if current is VMState.STOPPED:
                    break
                if current is VMState.UNKNOWN:
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self.sleeper(min(0.5, remaining))
            if current is not VMState.STOPPED:
                raise LifecycleError(
                    "Scenario VM did not stop before the deadline; refusing to delete."
                )
        elif state in {VMState.UNKNOWN}:
            raise LifecycleError(
                "Scenario VM backend state is unknown; refusing to delete."
            )
        elif state in {VMState.MISSING, VMState.NOT_BUILT}:
            # Stale metadata: the owned resource is absent. Only clear metadata
            # when no same-name foreign resource exists (checked above: no
            # conflict was reported).
            store.remove()
            return LifecycleResult(
                changed=True,
                message="Scenario runtime metadata was removed (VM was missing).",
                ownership_verified=True,
            )

        if metadata.backend is VMBackend.UTM:
            self._backend_call(
                self.utm.delete, metadata.vm.name, uuid=metadata.vm.resource_id
            )
            # F-2: absence is confirmed against the exact backend identity —
            # UUID for backend-aware metadata, name for legacy records — and
            # never against a leftover marker such as a preserved Vagrantfile.
            if metadata.vm.resource_id is not None:
                absent = self.utm.find_by_uuid(metadata.vm.resource_id) is None
            else:
                absent = self.utm.find_by_name(metadata.vm.name) is None
            if not absent:
                raise LifecycleError(
                    "Scenario VM deletion was not confirmed; runtime metadata is "
                    "retained for retry."
                )
        else:
            if store.vagrant_directory.exists():
                self._backend_call(self.vagrant.delete, store.vagrant_directory)
                # ``vagrant destroy --force`` leaves the Vagrantfile behind, so
                # environment_exists() is not a machine-absence signal. The
                # provider machine ID file is authoritative: when it is gone,
                # the machine is gone and the scenario-local directory may be
                # safely removed.
                if self.vagrant.machine_id(store.vagrant_directory) is not None:
                    raise LifecycleError(
                        "Scenario Vagrant machine deletion was not confirmed; "
                        "runtime metadata is retained for retry."
                    )
                self._remove_vagrant_directory(store)
        store.remove()
        return LifecycleResult(
            changed=True,
            message="Scenario VM was destroyed.",
            ownership_verified=True,
        )

    # ------------------------------------------------------------------
    # Windows management probe
    # ------------------------------------------------------------------

    def _verify_windows_management(
        self,
        scenario: Scenario,
        scenario_path: Path,
        *,
        budget: float | None = None,
    ) -> tuple[bool, tuple[str, ...]]:
        """Probe management readiness on an owned running Windows UTM clone.

        The probe never targets a shared base template: transport construction
        validates persisted ownership metadata first. Any failure leaves
        management NOT_READY/UNAVAILABLE. ``budget`` is the remaining operation
        deadline when the probe is invoked from ``up``.
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
                total_budget=budget,
            )
        except (
            ManagementTransportError,
            ImageManagerError,
            RuntimeMetadataError,
            BackendOperationError,
            OSError,
        ):
            # Persisted-metadata races, tampering, template-registry failures,
            # backend identity conflicts, and probe setup failures (for example
            # a temporary file error) must leave management unavailable instead
            # of escaping from up().
            return False, ("management_transport_unavailable",)
        failed = tuple(check.name for check in probe.checks if not check.passed)
        return probe.ok, failed

    @staticmethod
    def _backend_call(operation: Callable[..., object], *args: object, **kwargs: object) -> None:
        try:
            operation(*args, **kwargs)
        except BackendOperationError as exc:
            raise LifecycleError(str(exc)) from exc

    @staticmethod
    def _remove_vagrant_directory(store: RuntimeMetadataStore) -> None:
        directory = store.vagrant_directory
        if directory.is_symlink():
            directory.unlink()
        elif directory.is_dir() and directory.parent == store.runtime_dir:
            shutil.rmtree(directory)
