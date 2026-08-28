from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

import pytest

from rangeforge.host.models import Architecture, HostInfo, HostOS
from rangeforge.images.cache import ImageCache
from rangeforge.images.manager import ImageManager
from rangeforge.images.models import (
    ArtifactFormat,
    Checksum,
    ImageAcquisitionMethod,
    ImageManifest,
    ImageOS,
    ImageSource,
    ImageSourceType,
    VagrantBox,
)
from rangeforge.images.registry import ImageRegistry
from rangeforge.images.resolver import ImageResolver
from rangeforge.images.templates import TemplateManager
from rangeforge.models import Scenario, TrainingProfile
from rangeforge.primitives.registry import PrimitiveRegistry
from rangeforge.runtime.backends.base import BackendOperationError
from rangeforge.runtime.backends.utm import UTMInventoryRecord
from rangeforge.runtime.backends.vagrant import VagrantBackend, map_vagrant_state
from rangeforge.runtime.guest import ExecutionLanguage, GuestPlatform
from rangeforge.runtime.lifecycle import LifecycleError, ScenarioLifecycle
from rangeforge.runtime.metadata import (
    RuntimeMetadataError,
    RuntimeMetadataStore,
    ownership_fingerprint,
    scenario_managed_id,
    scenario_vm_name,
)
from rangeforge.runtime.models import (
    BackendStatus,
    BackendType,
    GuestPlan,
    ImagePlanStatus,
    LifecycleFailure,
    ManagementState,
    ManagementTransportKind,
    RuntimeGuestState,
    RuntimeMetadata,
    RuntimePlan,
    RuntimeResolution,
    RuntimeTemplateReference,
    RuntimeType,
    VMBackend,
    VMIdentity,
    VMState,
)
from rangeforge.runtime.planner import RuntimePlanner
from rangeforge.serialization.yaml import ScenarioYamlSerializer


class FakeUTM:
    def __init__(self, template_name: str) -> None:
        self.vms: dict[str, dict] = {
            template_name: {"uuid": "template-uuid", "state": VMState.STOPPED}
        }
        self.clones: list[tuple[str, str]] = []
        self.deleted: list[str] = []
        self.started: list[str] = []
        self.stopped: list[str] = []
        # Simulates a transient ``utmctl list`` failure: inventory lookups
        # raise like the real backend instead of reporting absence, so
        # lifecycle callers must fail closed and retain metadata.
        self.fail_inventory = False

    def available(self) -> bool:
        return True

    def template_exists(self, reference: str) -> bool:
        return reference in self.vms

    def vm_exists(self, name: str) -> bool:
        return name in self.vms

    def find_by_name(self, name: str) -> UTMInventoryRecord | None:
        if self.fail_inventory:
            raise BackendOperationError("utmctl list failed (transient).")
        entry = self.vms.get(name)
        if entry is None:
            return None
        return UTMInventoryRecord(
            uuid=entry["uuid"], name=name, state=entry["state"].value
        )

    def find_by_uuid(self, uuid: str) -> UTMInventoryRecord | None:
        if self.fail_inventory:
            raise BackendOperationError("utmctl list failed (transient).")
        for name, entry in self.vms.items():
            if entry["uuid"] == uuid:
                return UTMInventoryRecord(
                    uuid=uuid, name=name, state=entry["state"].value
                )
        return None

    def clone(self, template: str, name: str) -> None:
        assert template in self.vms
        self.vms[name] = {"uuid": f"uuid-{name}", "state": VMState.STOPPED}
        self.clones.append((template, name))

    def start(self, name: str, *, uuid: str | None = None) -> None:
        self.vms[name]["state"] = VMState.RUNNING
        self.started.append(name)

    def stop(self, name: str, *, force: bool = False, uuid: str | None = None) -> None:
        self.vms[name]["state"] = VMState.STOPPED
        self.stopped.append(name)

    def delete(self, name: str, *, uuid: str | None = None) -> None:
        self.vms.pop(name)
        self.deleted.append(name)

    def vm_state(self, name: str, *, uuid: str | None = None) -> VMState:
        if uuid is not None:
            record = self.find_by_uuid(uuid)
            if record is None:
                return VMState.MISSING
            if record.name != name:
                raise BackendOperationError("Ownership conflict: UUID belongs to a different name.")
            return record.vm_state
        entry = self.vms.get(name)
        if entry is None:
            return VMState.NOT_BUILT
        return entry["state"]

    def ip_addresses(self, name: str, *, uuid: str | None = None) -> tuple[str, ...]:
        entry = self.vms.get(name)
        if entry is None:
            return ()
        return ("192.168.64.50",) if entry["state"] is VMState.RUNNING else ()


class FakeVagrant:
    def __init__(self, references: set[str]) -> None:
        self.references = references
        self.prepared_boxes: list[VagrantBox] = []
        # Raw machine-readable ``vagrant status`` state token. It is always
        # parsed through the real production mapping (``map_vagrant_state``),
        # so this fake cannot mask a parser defect: a freshly prepared
        # environment has no machine yet (``not created``), exactly like a
        # real ``vagrant up`` target before the first boot.
        self.state_token = "not created"
        # Simulate ``vagrant destroy --force`` failing to remove the provider
        # machine ID: deletion is unconfirmed and metadata must be retained.
        self.fail_delete = False
        self.environments: set[Path] = set()

    def available(self) -> bool:
        return True

    def template_exists(self, reference: str) -> bool:
        return reference in self.references

    def prepare_environment(
        self, directory: Path, box: VagrantBox, vm_name: str = "rangeforge"
    ) -> Path:
        self.prepared_boxes.append(box)
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "Vagrantfile"
        path.write_text(f"# {vm_name}: {box.name}\n", encoding="utf-8")
        self.environments.add(directory)
        return path

    def environment_exists(self, directory: Path) -> bool:
        return (directory / "Vagrantfile").is_file()

    def machine_id(self, directory: Path) -> str | None:
        machine_root = directory / ".vagrant" / "machines"
        if not machine_root.is_dir():
            return None
        id_files = list(machine_root.glob("*/*/id"))
        if len(id_files) != 1:
            return None
        try:
            return id_files[0].read_text(encoding="utf-8").strip() or None
        except OSError:
            return None

    def vm_state(self, directory: Path) -> VMState:
        # Matches the real VagrantBackend: the environment (Vagrantfile) is
        # the resource, and raw machine-readable tokens are interpreted by
        # the production mapping. ``not created`` therefore reports STOPPED
        # (startable and cleanable); transitional tokens report UNKNOWN.
        if not self.environment_exists(directory):
            return VMState.NOT_BUILT
        return map_vagrant_state([self.state_token])

    def ip_addresses(self, directory: Path) -> tuple[str, ...]:
        return ("192.168.64.60",) if self.state_token == "running" else ()

    def start(self, directory: Path) -> None:
        self.state_token = "running"
        # Real Vagrant persists the provider machine ID under .vagrant after
        # the first boot; the Vagrantfile stays in place.
        machine_root = directory / ".vagrant" / "machines" / "default" / "virtualbox"
        machine_root.mkdir(parents=True, exist_ok=True)
        (machine_root / "id").write_text("provider-machine-id-1234", encoding="utf-8")

    def stop(self, directory: Path) -> None:
        self.state_token = "poweroff"

    def delete(self, directory: Path) -> None:
        # Real `vagrant destroy --force` removes the provider machine (the
        # .vagrant hierarchy) but leaves the Vagrantfile and directory behind.
        if self.fail_delete:
            # Simulated partial failure: the provider machine ID survives, so
            # deletion is unconfirmed and the lifecycle must retain metadata.
            self.state_token = "poweroff"
            return
        self.state_token = "not created"
        machine_root = directory / ".vagrant"
        if machine_root.exists():
            shutil.rmtree(machine_root)


def _host() -> HostInfo:
    return HostInfo(
        os=HostOS.DARWIN,
        architecture=Architecture.ARM64,
        apple_silicon=True,
    )


def _environment(
    tmp_path: Path,
    scenario: Scenario,
    profile: TrainingProfile,
    primitives: PrimitiveRegistry,
    *,
    prepare_template: bool = True,
) -> tuple[ScenarioLifecycle, RuntimePlan, Path, ImageManager, FakeUTM]:
    content = b"clean base source"
    manifest = ImageManifest(
        id="ubuntu-24.04-arm64",
        os=ImageOS(family="linux", distribution="ubuntu", version="24.04"),
        architecture=Architecture.ARM64,
        runtimes=(RuntimeType.VM,),
        backends=(VMBackend.UTM,),
        source=ImageSource(
            type=ImageSourceType.OFFICIAL,
            vendor="fixture",
            artifact_format=ArtifactFormat.QCOW2,
            version="test",
            filename="ubuntu.img",
        ),
        checksum=Checksum(value=hashlib.sha256(content).hexdigest()),
    )
    image_registry = ImageRegistry((manifest,))
    cache = ImageCache(tmp_path / "images")
    cache.ensure()
    cache.artifact_path(manifest).write_bytes(content)
    manager = ImageManager(image_registry, cache)
    template_name = "rf-base-ubuntu-24.04-arm64"
    fake_utm = FakeUTM(template_name)
    templates = TemplateManager(manager)
    if prepare_template:
        templates.prepare(manifest.id, VMBackend.UTM, fake_utm)

    planner = RuntimePlanner(
        profile=profile,
        primitive_registry=primitives,
        image_resolver=ImageResolver(image_registry),
        image_manager=manager,
        backend_status_provider=lambda *_: BackendStatus(
            backend=BackendType.UTM, available=True
        ),
    )
    plan = planner.plan(scenario, requested_runtime=RuntimeType.VM, host=_host())
    scenario_path = ScenarioYamlSerializer().dump(scenario, tmp_path / "scenarios")
    lifecycle = ScenarioLifecycle(
        template_manager=templates,
        host=_host(),
        utm=fake_utm,  # type: ignore[arg-type]
        vagrant=VagrantBackend(None),
        sleeper=lambda _: None,
    )
    return lifecycle, plan, scenario_path, manager, fake_utm


def test_scenario_vm_naming_and_identity_are_deterministic(scenario: Scenario) -> None:
    assert scenario_vm_name(scenario) == "rf-1337"
    assert scenario_vm_name(scenario) == scenario_vm_name(scenario)
    assert scenario_managed_id(scenario) == scenario_managed_id(scenario)


def test_runtime_metadata_serialization(
    scenario: Scenario,
    profile: TrainingProfile,
    registry: PrimitiveRegistry,
    tmp_path: Path,
) -> None:
    lifecycle, plan, scenario_path, _, _ = _environment(
        tmp_path, scenario, profile, registry
    )
    result = lifecycle.build(scenario, scenario_path, plan)
    loaded = RuntimeMetadataStore(scenario_path).load()
    assert loaded == result.metadata
    assert loaded is not None
    assert loaded.vm.name == "rf-1337"
    assert loaded.vm.state is VMState.STOPPED


def test_build_requires_ready_template(
    scenario: Scenario,
    profile: TrainingProfile,
    registry: PrimitiveRegistry,
    tmp_path: Path,
) -> None:
    lifecycle, plan, scenario_path, _, _ = _environment(
        tmp_path, scenario, profile, registry, prepare_template=False
    )
    assert not plan.deployable
    with pytest.raises(LifecycleError, match="READY"):
        lifecycle.build(scenario, scenario_path, plan)


def test_clean_utm_build_up_status_destroy_lifecycle(
    scenario: Scenario,
    profile: TrainingProfile,
    registry: PrimitiveRegistry,
    tmp_path: Path,
) -> None:
    lifecycle, plan, scenario_path, manager, utm = _environment(
        tmp_path, scenario, profile, registry
    )
    assert plan.deployable
    built = lifecycle.build(scenario, scenario_path, plan)
    assert built.changed
    assert utm.clones == [("rf-base-ubuntu-24.04-arm64", "rf-1337")]
    repeated = lifecycle.build(scenario, scenario_path, plan)
    assert not repeated.changed

    running = lifecycle.up(scenario, scenario_path, plan, timeout=0.1)
    assert running.metadata is not None
    assert running.metadata.vm.state is VMState.RUNNING
    assert running.metadata.guest.ip == "192.168.64.50"
    refreshed = lifecycle.status(scenario, scenario_path)
    assert refreshed.metadata is not None
    assert refreshed.metadata.vm.state is VMState.RUNNING

    artifact = manager.cache.artifact_path(manager.registry.require("ubuntu-24.04-arm64"))
    template_metadata = manager.cache.template_metadata_path(
        "ubuntu-24.04-arm64", VMBackend.UTM
    )
    destroyed = lifecycle.destroy(scenario, scenario_path)
    assert destroyed.changed
    assert utm.deleted == ["rf-1337"]
    assert artifact.is_file()
    assert template_metadata.is_file()
    assert scenario_path.is_file()
    assert RuntimeMetadataStore(scenario_path).load() is None
    repeated_destroy = lifecycle.destroy(scenario, scenario_path)
    assert not repeated_destroy.changed


def test_linux_utm_build_up_stop_status_up_destroy_lifecycle(
    scenario: Scenario,
    profile: TrainingProfile,
    registry: PrimitiveRegistry,
    tmp_path: Path,
) -> None:
    """Linux UTM regression: generic stop() preserves the clone and is idempotent."""
    lifecycle, plan, scenario_path, manager, utm = _environment(
        tmp_path, scenario, profile, registry
    )
    lifecycle.build(scenario, scenario_path, plan)
    running = lifecycle.up(scenario, scenario_path, plan, timeout=0.1)
    assert running.metadata is not None
    assert running.metadata.vm.state is VMState.RUNNING

    stopped = lifecycle.stop(scenario, scenario_path)
    assert stopped.changed
    assert stopped.metadata is not None
    assert stopped.metadata.vm.state is VMState.STOPPED
    assert stopped.metadata.guest.management is ManagementState.NOT_READY
    # The clone survives a stop.
    assert utm.vm_state("rf-1337") is VMState.STOPPED

    repeated_stop = lifecycle.stop(scenario, scenario_path)
    assert not repeated_stop.changed
    assert utm.stopped == ["rf-1337"]

    refreshed = lifecycle.status(scenario, scenario_path)
    assert refreshed.metadata is not None
    assert refreshed.metadata.vm.state is VMState.STOPPED
    assert refreshed.metadata.guest.ip is None

    up_again = lifecycle.up(scenario, scenario_path, plan, timeout=0.1)
    assert up_again.metadata is not None
    assert up_again.metadata.vm.state is VMState.RUNNING
    assert utm.started == ["rf-1337", "rf-1337"]

    lifecycle.destroy(scenario, scenario_path)
    assert utm.deleted == ["rf-1337"]
    assert manager.cache.artifact_path(
        manager.registry.require("ubuntu-24.04-arm64")
    ).is_file()


def test_architecture_mismatch_is_rejected_before_clone(
    scenario: Scenario,
    profile: TrainingProfile,
    registry: PrimitiveRegistry,
    tmp_path: Path,
) -> None:
    lifecycle, plan, scenario_path, _, utm = _environment(
        tmp_path, scenario, profile, registry
    )
    mismatched = ScenarioLifecycle(
        template_manager=lifecycle.template_manager,
        host=HostInfo(
            os=HostOS.LINUX,
            architecture=Architecture.AMD64,
            apple_silicon=False,
        ),
        utm=utm,  # type: ignore[arg-type]
        vagrant=VagrantBackend(None),
    )
    forced_plan = plan.model_copy(
        update={
            "runtime": RuntimeResolution(
                runtime=RuntimeType.VM,
                backend=VMBackend.UTM,
                guest_architecture=Architecture.ARM64,
                compatible=True,
                reason="test",
            ),
            "compatible": True,
            "deployable": True,
        }
    )
    # The plan was built for the ARM64 host; the lifecycle is constructed for
    # an AMD64 host, so the shared pre-mutation host gate rejects it before
    # any backend call.
    with pytest.raises(LifecycleError, match="different normalized host"):
        mismatched.build(scenario, scenario_path, forced_plan)
    assert not utm.clones


def test_status_model_parsing_round_trip(
    scenario: Scenario,
    profile: TrainingProfile,
    registry: PrimitiveRegistry,
    tmp_path: Path,
) -> None:
    lifecycle, plan, scenario_path, _, _ = _environment(
        tmp_path, scenario, profile, registry
    )
    lifecycle.build(scenario, scenario_path, plan)
    store = RuntimeMetadataStore(scenario_path)
    metadata = store.load()
    assert metadata is not None
    store.save(
        metadata.model_copy(
            update={"vm": metadata.vm.model_copy(update={"state": VMState.UNKNOWN})}
        )
    )
    parsed = store.load()
    assert parsed is not None
    assert parsed.vm.state is VMState.UNKNOWN


def test_destroy_rejects_tampered_ownership_metadata(
    scenario: Scenario,
    profile: TrainingProfile,
    registry: PrimitiveRegistry,
    tmp_path: Path,
) -> None:
    lifecycle, plan, scenario_path, manager, utm = _environment(
        tmp_path, scenario, profile, registry
    )
    lifecycle.build(scenario, scenario_path, plan)
    store = RuntimeMetadataStore(scenario_path)
    metadata = store.load()
    assert metadata is not None
    store.save(
        metadata.model_copy(
            update={
                "vm": metadata.vm.model_copy(update={"managed_id": "not-owned"})
            }
        )
    )
    with pytest.raises(RuntimeMetadataError, match="identity does not match"):
        lifecycle.destroy(scenario, scenario_path)
    assert utm.vm_exists("rf-1337")
    assert manager.cache.artifact_path(
        manager.registry.require("ubuntu-24.04-arm64")
    ).is_file()


def test_manual_vagrant_template_reference_builds_scenario_environment(
    scenario: Scenario,
    tmp_path: Path,
) -> None:
    content = b"reviewed linux amd64 media"
    manifest = ImageManifest(
        id="ubuntu-24.04-amd64",
        os=ImageOS(family="linux", distribution="ubuntu", version="24.04"),
        architecture=Architecture.AMD64,
        runtimes=(RuntimeType.VM,),
        backends=(VMBackend.VAGRANT,),
        source=ImageSource(
            type=ImageSourceType.OFFICIAL,
            vendor="canonical",
            artifact_format=ArtifactFormat.ISO,
            version="test",
            filename="ubuntu-24.04-amd64.iso",
            acquisition=ImageAcquisitionMethod.MANUAL,
        ),
        checksum=Checksum(value=hashlib.sha256(content).hexdigest()),
    )
    cache = ImageCache(tmp_path / "images")
    cache.ensure()
    cache.artifact_path(manifest).write_bytes(content)
    manager = ImageManager(ImageRegistry((manifest,)), cache)
    templates = TemplateManager(manager)
    reference = "rf-base-ubuntu-24.04-amd64"
    vagrant = FakeVagrant({reference})
    templates.prepare(
        manifest.id,
        VMBackend.VAGRANT,
        vagrant,
        reference=reference,
    )

    host = HostInfo(os=HostOS.LINUX, architecture=Architecture.AMD64, apple_silicon=False)
    plan = RuntimePlan(
        scenario_id=scenario.scenario.id,
        host=host,
        runtime=RuntimeResolution(
            runtime=RuntimeType.VM,
            backend=VMBackend.VAGRANT,
            guest_architecture=Architecture.AMD64,
            compatible=True,
            reason="AMD64 VM hosts use Vagrant.",
        ),
        backend_status=BackendStatus(backend=BackendType.VAGRANT, available=True),
        guest=GuestPlan(
            family="linux",
            distribution="ubuntu",
            version="24.04",
            architecture=Architecture.AMD64,
            image_id=manifest.id,
        ),
        image_status=ImagePlanStatus(
            acquisition="manual", source="ready", template="ready"
        ),
        compatible=True,
        deployable=True,
        next_action="Runtime prerequisites are ready for the scenario lifecycle.",
    )
    scenario_path = ScenarioYamlSerializer().dump(scenario, tmp_path / "scenarios")
    lifecycle = ScenarioLifecycle(
        template_manager=templates,
        host=host,
        utm=FakeUTM("unused"),  # type: ignore[arg-type]
        vagrant=vagrant,  # type: ignore[arg-type]
        sleeper=lambda _: None,
    )

    result = lifecycle.build(scenario, scenario_path, plan)
    assert result.changed
    assert vagrant.prepared_boxes == [VagrantBox(name=reference)]
    assert result.metadata is not None
    assert result.metadata.template.name == reference
    assert result.metadata.guest.platform is GuestPlatform.LINUX
    assert result.metadata.guest.management_transport is ManagementTransportKind.VAGRANT_SSH
    assert result.metadata.guest.execution_language is ExecutionLanguage.SHELL


def test_linux_vagrant_build_up_stop_destroy_lifecycle(
    scenario: Scenario,
    tmp_path: Path,
) -> None:
    """Linux Vagrant regression: generic lifecycle with environment identity.

    The fake models a genuinely fresh environment: before ``up`` the machine
    token is ``not created``, which the production mapping reports as STOPPED
    (startable and cleanable). This proves a freshly built Vagrant environment
    can converge through up() and destroy() without a synthetic UNKNOWN.
    """
    content = b"reviewed linux amd64 media"
    manifest = ImageManifest(
        id="ubuntu-24.04-amd64",
        os=ImageOS(family="linux", distribution="ubuntu", version="24.04"),
        architecture=Architecture.AMD64,
        runtimes=(RuntimeType.VM,),
        backends=(VMBackend.VAGRANT,),
        source=ImageSource(
            type=ImageSourceType.OFFICIAL,
            vendor="canonical",
            artifact_format=ArtifactFormat.ISO,
            version="test",
            filename="ubuntu-24.04-amd64.iso",
            acquisition=ImageAcquisitionMethod.MANUAL,
        ),
        checksum=Checksum(value=hashlib.sha256(content).hexdigest()),
    )
    cache = ImageCache(tmp_path / "images")
    cache.ensure()
    cache.artifact_path(manifest).write_bytes(content)
    manager = ImageManager(ImageRegistry((manifest,)), cache)
    templates = TemplateManager(manager)
    reference = "rf-base-ubuntu-24.04-amd64"
    vagrant = FakeVagrant({reference})
    templates.prepare(
        manifest.id,
        VMBackend.VAGRANT,
        vagrant,
        reference=reference,
    )

    host = HostInfo(os=HostOS.LINUX, architecture=Architecture.AMD64, apple_silicon=False)
    plan = RuntimePlan(
        scenario_id=scenario.scenario.id,
        host=host,
        runtime=RuntimeResolution(
            runtime=RuntimeType.VM,
            backend=VMBackend.VAGRANT,
            guest_architecture=Architecture.AMD64,
            compatible=True,
            reason="AMD64 VM hosts use Vagrant.",
        ),
        backend_status=BackendStatus(backend=BackendType.VAGRANT, available=True),
        guest=GuestPlan(
            family="linux",
            distribution="ubuntu",
            version="24.04",
            architecture=Architecture.AMD64,
            image_id=manifest.id,
        ),
        image_status=ImagePlanStatus(
            acquisition="manual", source="ready", template="ready"
        ),
        compatible=True,
        deployable=True,
        next_action="Runtime prerequisites are ready for the scenario lifecycle.",
    )
    scenario_path = ScenarioYamlSerializer().dump(scenario, tmp_path / "scenarios")
    lifecycle = ScenarioLifecycle(
        template_manager=templates,
        host=host,
        utm=FakeUTM("unused"),  # type: ignore[arg-type]
        vagrant=vagrant,  # type: ignore[arg-type]
        sleeper=lambda _: None,
    )

    built = lifecycle.build(scenario, scenario_path, plan)
    assert built.changed
    assert built.metadata is not None
    assert built.metadata.vm.resource_id is not None
    assert built.metadata.ownership_fingerprint is not None
    # A freshly prepared environment has no machine yet; the never-created
    # state is startable and cleanable (STOPPED), never UNKNOWN.
    assert built.metadata.vm.state is VMState.STOPPED
    assert built.metadata.vm.provider_id is None

    running = lifecycle.up(scenario, scenario_path, plan, timeout=0.1)
    assert running.metadata is not None
    assert running.metadata.vm.state is VMState.RUNNING
    assert running.metadata.guest.management is ManagementState.READY
    # The provider machine ID is persisted once it becomes available after
    # boot; the stable environment fingerprint is never replaced.
    assert running.metadata.vm.provider_id == "provider-machine-id-1234"
    assert running.metadata.vm.resource_id == built.metadata.vm.resource_id

    stopped = lifecycle.stop(scenario, scenario_path)
    assert stopped.changed
    assert stopped.metadata is not None
    assert stopped.metadata.vm.state is VMState.STOPPED

    destroyed = lifecycle.destroy(scenario, scenario_path)
    assert destroyed.changed
    assert RuntimeMetadataStore(scenario_path).load() is None
    assert not RuntimeMetadataStore(scenario_path).vagrant_directory.exists()


def test_windows_vagrant_build_rejected_before_backend_calls(
    scenario: Scenario,
    tmp_path: Path,
) -> None:
    content = b"reviewed windows amd64 media"
    manifest = ImageManifest(
        id="windows-11-amd64",
        os=ImageOS(family="windows", distribution="windows", version="11"),
        architecture=Architecture.AMD64,
        runtimes=(RuntimeType.VM,),
        backends=(VMBackend.VAGRANT,),
        source=ImageSource(
            type=ImageSourceType.OFFICIAL,
            vendor="microsoft",
            artifact_format=ArtifactFormat.ISO,
            version="test",
            filename="windows-11-amd64.iso",
            acquisition=ImageAcquisitionMethod.MANUAL,
        ),
        checksum=Checksum(value=hashlib.sha256(content).hexdigest()),
    )
    cache = ImageCache(tmp_path / "images")
    cache.ensure()
    cache.artifact_path(manifest).write_bytes(content)
    manager = ImageManager(ImageRegistry((manifest,)), cache)
    templates = TemplateManager(manager)
    reference = "rf-base-windows-11-amd64"
    vagrant = FakeVagrant({reference})
    templates.prepare(
        manifest.id,
        VMBackend.VAGRANT,
        vagrant,
        reference=reference,
    )

    host = HostInfo(os=HostOS.LINUX, architecture=Architecture.AMD64, apple_silicon=False)
    plan = RuntimePlan(
        scenario_id=scenario.scenario.id,
        host=host,
        runtime=RuntimeResolution(
            runtime=RuntimeType.VM,
            backend=VMBackend.VAGRANT,
            guest_architecture=Architecture.AMD64,
            compatible=True,
            reason="AMD64 VM hosts use Vagrant.",
        ),
        backend_status=BackendStatus(backend=BackendType.VAGRANT, available=True),
        guest=GuestPlan(
            family="windows",
            distribution="windows",
            version="11",
            architecture=Architecture.AMD64,
            image_id=manifest.id,
        ),
        image_status=ImagePlanStatus(
            acquisition="manual", source="ready", template="ready"
        ),
        compatible=True,
        deployable=True,
        next_action="Runtime prerequisites are ready for the scenario lifecycle.",
    )
    windows_scenario = scenario.model_copy(
        update={
            "scenario": scenario.scenario.model_copy(
                update={"platform": "windows", "guest_architecture": "amd64"}
            )
        }
    )
    scenario_path = ScenarioYamlSerializer().dump(
        windows_scenario, tmp_path / "scenarios"
    )
    lifecycle = ScenarioLifecycle(
        template_manager=templates,
        host=host,
        utm=FakeUTM("unused"),  # type: ignore[arg-type]
        vagrant=vagrant,  # type: ignore[arg-type]
        sleeper=lambda _: None,
    )

    with pytest.raises(LifecycleError, match="Windows Vagrant management is unsupported"):
        lifecycle.build(windows_scenario, scenario_path, plan)
    assert vagrant.prepared_boxes == []


def test_ownership_fingerprint_is_deterministic_and_binds_identity(
    scenario: Scenario,
    profile: TrainingProfile,
    registry: PrimitiveRegistry,
    tmp_path: Path,
) -> None:
    lifecycle, plan, scenario_path, _, _ = _environment(
        tmp_path, scenario, profile, registry
    )
    lifecycle.build(scenario, scenario_path, plan)
    store = RuntimeMetadataStore(scenario_path)
    metadata = store.load()
    assert metadata is not None
    assert metadata.metadata_version == 4
    assert metadata.vm.resource_id == "uuid-rf-1337"
    assert metadata.ownership_fingerprint == ownership_fingerprint(metadata)
    assert metadata.ownership_fingerprint == ownership_fingerprint(metadata)
    # A changed backend identity must change the fingerprint.
    different = metadata.model_copy(
        update={
            "vm": metadata.vm.model_copy(update={"resource_id": "other-uuid"})
        }
    )
    assert ownership_fingerprint(different) != ownership_fingerprint(metadata)


def test_runtime_metadata_schema4_round_trips_guest_product_and_version(
    scenario: Scenario,
    profile: TrainingProfile,
    registry: PrimitiveRegistry,
    tmp_path: Path,
) -> None:
    lifecycle, plan, scenario_path, _, _ = _environment(
        tmp_path, scenario, profile, registry
    )
    lifecycle.build(scenario, scenario_path, plan)
    store = RuntimeMetadataStore(scenario_path)
    loaded = store.load()
    assert loaded is not None
    assert loaded.metadata_version == 4
    assert loaded.guest.platform is GuestPlatform.LINUX
    assert loaded.guest.product == "ubuntu"
    assert loaded.guest.version == "24.04"
    assert loaded.vm.resource_id == "uuid-rf-1337"
    assert loaded.ownership_fingerprint == ownership_fingerprint(loaded)


def test_rf_5004_scenario_produces_rf_5004_name(scenario: Scenario) -> None:
    renamed = scenario.model_copy(
        update={"scenario": scenario.scenario.model_copy(update={"id": "5004"})}
    )
    assert scenario_vm_name(renamed) == "rf-5004"


def test_symlinked_runtime_dir_is_rejected_before_mutation(
    scenario: Scenario,
    profile: TrainingProfile,
    registry: PrimitiveRegistry,
    tmp_path: Path,
) -> None:
    _lifecycle, _plan, scenario_path, _, _ = _environment(
        tmp_path, scenario, profile, registry
    )
    store = RuntimeMetadataStore(scenario_path)
    # Replace the runtime dir with a symlink before build saves metadata.
    runtime_dir = store.runtime_dir
    runtime_dir.mkdir(parents=True, exist_ok=True)
    (runtime_dir / "runtime.yaml").write_text("stale", encoding="utf-8")
    shutil.rmtree(runtime_dir)
    real_dir = tmp_path / "real-runtime"
    real_dir.mkdir()
    runtime_dir.symlink_to(real_dir, target_is_directory=True)
    with pytest.raises(RuntimeMetadataError, match="symlink"):
        store.save(
            RuntimeMetadata(
                scenario_id=scenario.scenario.id,
                profile=scenario.scenario.profile,
                runtime=RuntimeType.VM,
                backend=VMBackend.UTM,
                vm=VMIdentity(
                    name="rf-1337",
                    managed_id=scenario_managed_id(scenario),
                    state=VMState.STOPPED,
                    resource_id="uuid-rf-1337",
                ),
                template=RuntimeTemplateReference(
                    image_id="ubuntu-24.04-arm64",
                    template_id="rf-base-ubuntu-24.04-arm64",
                    name="rf-base-ubuntu-24.04-arm64",
                    fingerprint="f" * 64,
                ),
                guest=RuntimeGuestState(architecture=Architecture.ARM64),
                metadata_version=4,
            )
        )


def test_legacy_v3_metadata_remains_valid_for_linux_and_not_windows(
    scenario: Scenario,
    profile: TrainingProfile,
    registry: PrimitiveRegistry,
    tmp_path: Path,
) -> None:
    lifecycle, _plan, scenario_path, _, _ = _environment(
        tmp_path, scenario, profile, registry
    )
    store = RuntimeMetadataStore(scenario_path)
    # Construct legacy (v3) Linux metadata without fingerprint/identity.
    legacy = RuntimeMetadata(
        scenario_id=scenario.scenario.id,
        profile=scenario.scenario.profile,
        runtime=RuntimeType.VM,
        backend=VMBackend.UTM,
        vm=VMIdentity(
            name="rf-1337",
            managed_id=scenario_managed_id(scenario),
            state=VMState.RUNNING,
        ),
        template=RuntimeTemplateReference(
            image_id="ubuntu-24.04-arm64",
            template_id="rf-base-ubuntu-24.04-arm64",
            name="rf-base-ubuntu-24.04-arm64",
            fingerprint="f" * 64,
        ),
        guest=RuntimeGuestState(architecture=Architecture.ARM64),
        metadata_version=3,
    )
    store.save(legacy)
    # Legacy Linux metadata still validates ownership.
    store.validate_ownership(scenario, store.load())  # type: ignore[arg-type]
    # A Windows scenario must never accept the same record: build the legacy
    # record bound to the Windows scenario identity (same id, no platform),
    # which passes ownership but must fail the cross-platform reconciliation.
    windows_scenario = scenario.model_copy(
        update={
            "scenario": scenario.scenario.model_copy(
                update={"platform": "windows", "guest_architecture": "arm64"}
            )
        }
    )
    store.save(
        legacy.model_copy(
            update={
                "vm": legacy.vm.model_copy(
                    update={"managed_id": scenario_managed_id(windows_scenario)}
                )
            }
        )
    )
    with pytest.raises(LifecycleError, match="cannot be reconciled"):
        lifecycle.status(windows_scenario, scenario_path)


def _vagrant_environment(
    scenario: Scenario, tmp_path: Path
) -> tuple[ScenarioLifecycle, RuntimePlan, Path, FakeVagrant, Path]:
    """Linux AMD64 Vagrant environment with a prepared template and plan."""
    content = b"reviewed linux amd64 media"
    manifest = ImageManifest(
        id="ubuntu-24.04-amd64",
        os=ImageOS(family="linux", distribution="ubuntu", version="24.04"),
        architecture=Architecture.AMD64,
        runtimes=(RuntimeType.VM,),
        backends=(VMBackend.VAGRANT,),
        source=ImageSource(
            type=ImageSourceType.OFFICIAL,
            vendor="canonical",
            artifact_format=ArtifactFormat.ISO,
            version="test",
            filename="ubuntu-24.04-amd64.iso",
            acquisition=ImageAcquisitionMethod.MANUAL,
        ),
        checksum=Checksum(value=hashlib.sha256(content).hexdigest()),
    )
    cache = ImageCache(tmp_path / "images")
    cache.ensure()
    cache.artifact_path(manifest).write_bytes(content)
    manager = ImageManager(ImageRegistry((manifest,)), cache)
    templates = TemplateManager(manager)
    reference = "rf-base-ubuntu-24.04-amd64"
    vagrant = FakeVagrant({reference})
    templates.prepare(manifest.id, VMBackend.VAGRANT, vagrant, reference=reference)

    host = HostInfo(os=HostOS.LINUX, architecture=Architecture.AMD64, apple_silicon=False)
    plan = RuntimePlan(
        scenario_id=scenario.scenario.id,
        host=host,
        runtime=RuntimeResolution(
            runtime=RuntimeType.VM,
            backend=VMBackend.VAGRANT,
            guest_architecture=Architecture.AMD64,
            compatible=True,
            reason="AMD64 VM hosts use Vagrant.",
        ),
        backend_status=BackendStatus(backend=BackendType.VAGRANT, available=True),
        guest=GuestPlan(
            family="linux",
            distribution="ubuntu",
            version="24.04",
            architecture=Architecture.AMD64,
            image_id=manifest.id,
        ),
        image_status=ImagePlanStatus(
            acquisition="manual", source="ready", template="ready"
        ),
        compatible=True,
        deployable=True,
        next_action="Runtime prerequisites are ready for the scenario lifecycle.",
    )
    scenario_path = ScenarioYamlSerializer().dump(scenario, tmp_path / "scenarios")
    lifecycle = ScenarioLifecycle(
        template_manager=templates,
        host=host,
        utm=FakeUTM("unused"),  # type: ignore[arg-type]
        vagrant=vagrant,  # type: ignore[arg-type]
        sleeper=lambda _: None,
    )
    return lifecycle, plan, scenario_path, vagrant, manager.cache.artifact_path(manifest)


def test_vagrant_provider_id_persists_after_up_and_fails_closed_on_mismatch(
    scenario: Scenario,
    tmp_path: Path,
) -> None:
    """provider_id is recorded after up; a provider-ID mismatch fails closed."""
    lifecycle, plan, scenario_path, _vagrant, _ = _vagrant_environment(
        scenario, tmp_path
    )
    lifecycle.build(scenario, scenario_path, plan)
    running = lifecycle.up(scenario, scenario_path, plan, timeout=0.1)
    assert running.metadata is not None
    assert running.metadata.vm.provider_id == "provider-machine-id-1234"

    # Replace the provider machine ID in the environment: the persisted
    # identity no longer matches the backend, so every mutation fails closed.
    id_file = (
        RuntimeMetadataStore(scenario_path).vagrant_directory
        / ".vagrant"
        / "machines"
        / "default"
        / "virtualbox"
        / "id"
    )
    id_file.write_text("foreign-machine-id", encoding="utf-8")
    # status is non-destructive: it reports the ownership conflict without
    # raising, and never renders verified ownership.
    conflict_status = lifecycle.status(scenario, scenario_path)
    assert conflict_status.ownership_verified is False
    assert conflict_status.metadata is not None
    assert "provider machine ID does not match" in conflict_status.message
    with pytest.raises(LifecycleError, match="Ownership conflict"):
        lifecycle.destroy(scenario, scenario_path)
    # The VM and metadata survive a failed destroy for retry.
    assert RuntimeMetadataStore(scenario_path).load() is not None
    assert RuntimeMetadataStore(scenario_path).vagrant_directory.is_dir()


def test_vagrant_environment_fingerprint_mismatch_fails_closed(
    scenario: Scenario,
    tmp_path: Path,
) -> None:
    """A replaced Vagrantfile changes the stable environment identity."""
    lifecycle, plan, scenario_path, _vagrant, _ = _vagrant_environment(
        scenario, tmp_path
    )
    lifecycle.build(scenario, scenario_path, plan)
    store = RuntimeMetadataStore(scenario_path)
    metadata = store.load()
    assert metadata is not None
    vagrantfile = store.vagrant_directory / "Vagrantfile"
    vagrantfile.write_text("# foreign replacement environment\n", encoding="utf-8")
    conflict_status = lifecycle.status(scenario, scenario_path)
    assert conflict_status.ownership_verified is False
    assert conflict_status.metadata is not None
    assert "fingerprint does not match" in conflict_status.message
    with pytest.raises(LifecycleError, match="Ownership conflict"):
        lifecycle.destroy(scenario, scenario_path)
    assert store.load() is not None


def test_vagrant_destroy_failure_retains_metadata_for_retry(
    scenario: Scenario,
    tmp_path: Path,
) -> None:
    """Unconfirmed machine deletion keeps metadata so a retry can target it."""
    lifecycle, plan, scenario_path, vagrant, _ = _vagrant_environment(
        scenario, tmp_path
    )
    lifecycle.build(scenario, scenario_path, plan)
    lifecycle.up(scenario, scenario_path, plan, timeout=0.1)
    vagrant.fail_delete = True
    with pytest.raises(
        LifecycleError, match="deletion was not confirmed"
    ):
        lifecycle.destroy(scenario, scenario_path)
    store = RuntimeMetadataStore(scenario_path)
    failed_load = store.load()
    assert failed_load is not None
    # The retry targets the same persisted environment identity.
    assert failed_load.vm.resource_id is not None
    vagrant.fail_delete = False
    retried = lifecycle.destroy(scenario, scenario_path)
    assert retried.changed
    assert store.load() is None
    assert not store.vagrant_directory.exists()


def test_utm_inventory_failure_fails_closed_and_retains_metadata(
    scenario: Scenario,
    profile: TrainingProfile,
    registry: PrimitiveRegistry,
    tmp_path: Path,
) -> None:
    """A transient inventory failure must never read as absence.

    ``utmctl list`` failures propagate as typed backend errors so status,
    stop, and destroy fail closed; metadata and the owned clone survive for
    retry instead of the lifecycle deleting metadata while the VM remains.
    """
    lifecycle, plan, scenario_path, _manager, utm = _environment(
        tmp_path, scenario, profile, registry
    )
    lifecycle.build(scenario, scenario_path, plan)
    lifecycle.up(scenario, scenario_path, plan, timeout=0.1)

    utm.fail_inventory = True
    with pytest.raises(BackendOperationError, match="utmctl list failed"):
        lifecycle.status(scenario, scenario_path)
    with pytest.raises(BackendOperationError, match="utmctl list failed"):
        lifecycle.stop(scenario, scenario_path)
    with pytest.raises(BackendOperationError, match="utmctl list failed"):
        lifecycle.destroy(scenario, scenario_path)
    # No stop or delete request was issued, and metadata was retained.
    assert utm.stopped == []
    assert utm.deleted == []

    utm.fail_inventory = False
    store = RuntimeMetadataStore(scenario_path)
    recovered = store.load()
    assert recovered is not None
    assert recovered.vm.state is VMState.RUNNING
    assert utm.vm_state("rf-1337") is VMState.RUNNING
    # The owned clone is still destroyable once inventory recovers.
    destroyed = lifecycle.destroy(scenario, scenario_path)
    assert destroyed.changed
    assert utm.deleted == ["rf-1337"]
    assert store.load() is None


def test_status_clears_stale_failure_on_healthy_observation(
    scenario: Scenario,
    profile: TrainingProfile,
    registry: PrimitiveRegistry,
    tmp_path: Path,
) -> None:
    """A stale failure record is cleared once status observes healthy state."""
    lifecycle, plan, scenario_path, _, _ = _environment(
        tmp_path, scenario, profile, registry
    )
    lifecycle.build(scenario, scenario_path, plan)
    store = RuntimeMetadataStore(scenario_path)
    metadata = store.load()
    assert metadata is not None
    # Simulate a previously failed stop recorded on cleanly stopped metadata.
    stale = metadata.model_copy(
        update={
            "failure": LifecycleFailure(
                classification="stop_timeout",
                message="Scenario VM did not reach STOPPED before the deadline.",
            )
        }
    )
    store.save(stale)
    refreshed = lifecycle.status(scenario, scenario_path)
    assert refreshed.changed
    assert refreshed.metadata is not None
    assert refreshed.metadata.failure is None
    cleared = store.load()
    assert cleared is not None
    assert cleared.failure is None

    # Unhealthy observations retain the failure record: an unknown backend
    # state is not a healthy state and must not clear the classification.
    utm = lifecycle.utm
    utm.vms["rf-1337"]["state"] = VMState.UNKNOWN  # type: ignore[union-attr]
    retained_before = cleared.model_copy(
        update={
            "failure": LifecycleFailure(
                classification="stop_timeout", message="stale"
            )
        }
    )
    store.save(retained_before)
    retained = lifecycle.status(scenario, scenario_path)
    assert retained.metadata is not None
    assert retained.metadata.failure is not None
    assert retained.metadata.failure.classification == "stop_timeout"


def test_linux_up_without_ip_returns_success_without_failure_record(
    scenario: Scenario,
    profile: TrainingProfile,
    registry: PrimitiveRegistry,
    tmp_path: Path,
) -> None:
    """Linux readiness stays IP-based; RUNNING without an IP is not a failure.

    Established Linux semantics accept a running VM without an address as a
    successful start (management UNAVAILABLE), so no contradictory
    ``management_unavailable`` failure record is persisted and no error is
    raised; only Windows management readiness is a hard lifecycle failure.
    """
    lifecycle, plan, scenario_path, _manager, utm = _environment(
        tmp_path, scenario, profile, registry
    )
    lifecycle.build(scenario, scenario_path, plan)
    # The clone runs but never reports an address before the deadline.
    utm.ip_addresses = lambda name, *, uuid=None: ()  # type: ignore[method-assign]
    result = lifecycle.up(scenario, scenario_path, plan, timeout=0.1)
    assert result.changed
    assert result.metadata is not None
    assert result.metadata.vm.state is VMState.RUNNING
    assert result.metadata.guest.management is ManagementState.UNAVAILABLE
    assert result.metadata.failure is None


def test_legacy_linux_metadata_destroy_by_name_remains_supported(
    scenario: Scenario,
    profile: TrainingProfile,
    registry: PrimitiveRegistry,
    tmp_path: Path,
) -> None:
    """Legacy Linux metadata stays valid for its historical behavior.

    Legacy (v3) records carry no backend-native identity; destructive Linux
    operations resolve the managed resource by exact unique name (duplicates
    fail closed). This pins the documented compatibility boundary: legacy
    metadata is never upgraded into strict backend ownership and can never
    represent Windows.
    """
    lifecycle, _plan, scenario_path, _, utm = _environment(
        tmp_path, scenario, profile, registry
    )
    store = RuntimeMetadataStore(scenario_path)
    utm.vms["rf-1337"] = {"uuid": "legacy-uuid", "state": VMState.STOPPED}
    legacy = RuntimeMetadata(
        scenario_id=scenario.scenario.id,
        profile=scenario.scenario.profile,
        runtime=RuntimeType.VM,
        backend=VMBackend.UTM,
        vm=VMIdentity(
            name="rf-1337",
            managed_id=scenario_managed_id(scenario),
            state=VMState.STOPPED,
        ),
        template=RuntimeTemplateReference(
            image_id="ubuntu-24.04-arm64",
            template_id="rf-base-ubuntu-24.04-arm64",
            name="rf-base-ubuntu-24.04-arm64",
            fingerprint="f" * 64,
        ),
        guest=RuntimeGuestState(architecture=Architecture.ARM64),
        metadata_version=3,
    )
    store.save(legacy)
    destroyed = lifecycle.destroy(scenario, scenario_path)
    assert destroyed.changed
    assert utm.deleted == ["rf-1337"]
    assert store.load() is None
