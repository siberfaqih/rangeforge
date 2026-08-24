"""First clean-base scenario VM lifecycle orchestration."""

from __future__ import annotations

import shutil
import time
from collections.abc import Callable
from pathlib import Path

from rangeforge.host.models import HostInfo
from rangeforge.images.templates import TemplateManager
from rangeforge.models import Scenario
from rangeforge.runtime.backends.base import BackendOperationError
from rangeforge.runtime.backends.utm import UTMBackend
from rangeforge.runtime.backends.vagrant import VagrantBackend
from rangeforge.runtime.metadata import (
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
            if manifest.vagrant_box is None:
                raise LifecycleError("Trusted Vagrant box metadata is missing.")
            if store.vagrant_directory.exists():
                raise LifecycleError(
                    "Refusing to claim an existing Vagrant runtime directory without metadata."
                )
            self.vagrant.prepare_environment(
                store.vagrant_directory, manifest.vagrant_box, name
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
            guest=RuntimeGuestState(architecture=template.architecture),
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
        state = self._state(metadata, store)
        if state is VMState.RUNNING and metadata.guest.management is ManagementState.READY:
            return LifecycleResult(
                changed=False,
                message="Scenario VM is already running and management is ready.",
                metadata=metadata,
            )

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
        ready = bool(addresses)
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
        message = (
            "Scenario VM is running and management is ready."
            if ready
            else "Scenario VM is running, but guest management connectivity is not ready."
        )
        return LifecycleResult(changed=True, message=message, metadata=running)

    def status(self, scenario: Scenario, scenario_path: Path) -> LifecycleResult:
        store = RuntimeMetadataStore(scenario_path)
        metadata = store.load()
        if metadata is None:
            return LifecycleResult(changed=False, message="Scenario VM is not built.")
        store.validate_ownership(scenario, metadata)
        state = self._state(metadata, store)
        addresses = self._ip_addresses(metadata, store) if state is VMState.RUNNING else ()
        updated = metadata.model_copy(
            update={
                "vm": metadata.vm.model_copy(update={"state": state}),
                "guest": metadata.guest.model_copy(
                    update={
                        "ip": addresses[0] if addresses else None,
                        "management": (
                            ManagementState.READY
                            if addresses
                            else ManagementState.NOT_READY
                        ),
                    }
                ),
            }
        )
        store.save(updated)
        return LifecycleResult(changed=False, message="Runtime status refreshed.", metadata=updated)

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
