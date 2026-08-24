from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from rangeforge.host.models import Architecture, HostInfo, HostOS
from rangeforge.images.cache import ImageCache
from rangeforge.images.manager import ImageManager
from rangeforge.images.models import (
    ArtifactFormat,
    Checksum,
    ImageManifest,
    ImageOS,
    ImageSource,
    ImageSourceType,
)
from rangeforge.images.registry import ImageRegistry
from rangeforge.images.resolver import ImageResolver
from rangeforge.images.templates import TemplateManager
from rangeforge.models import Scenario, TrainingProfile
from rangeforge.primitives.registry import PrimitiveRegistry
from rangeforge.runtime.backends.vagrant import VagrantBackend
from rangeforge.runtime.lifecycle import LifecycleError, ScenarioLifecycle
from rangeforge.runtime.metadata import (
    RuntimeMetadataError,
    RuntimeMetadataStore,
    scenario_managed_id,
    scenario_vm_name,
)
from rangeforge.runtime.models import (
    BackendStatus,
    BackendType,
    RuntimePlan,
    RuntimeResolution,
    RuntimeType,
    VMBackend,
    VMState,
)
from rangeforge.runtime.planner import RuntimePlanner
from rangeforge.serialization.yaml import ScenarioYamlSerializer


class FakeUTM:
    def __init__(self, template_name: str) -> None:
        self.vms: dict[str, VMState] = {template_name: VMState.STOPPED}
        self.clones: list[tuple[str, str]] = []
        self.deleted: list[str] = []

    def available(self) -> bool:
        return True

    def template_exists(self, reference: str) -> bool:
        return reference in self.vms

    def vm_exists(self, name: str) -> bool:
        return name in self.vms

    def clone(self, template: str, name: str) -> None:
        assert template in self.vms
        self.vms[name] = VMState.STOPPED
        self.clones.append((template, name))

    def start(self, name: str) -> None:
        self.vms[name] = VMState.RUNNING

    def stop(self, name: str, *, force: bool = False) -> None:
        assert force
        self.vms[name] = VMState.STOPPED

    def delete(self, name: str) -> None:
        self.vms.pop(name)
        self.deleted.append(name)

    def vm_state(self, name: str) -> VMState:
        return self.vms.get(name, VMState.NOT_BUILT)

    def ip_addresses(self, name: str) -> tuple[str, ...]:
        return ("192.168.64.50",) if self.vms.get(name) is VMState.RUNNING else ()


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
    with pytest.raises(LifecycleError, match="does not match host"):
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
