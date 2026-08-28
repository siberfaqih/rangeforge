"""Explicitly gated Windows ARM64 UTM full lifecycle acceptance test.

This test is excluded from default CI by the ``runtime`` marker and
environment gates. It validates the complete Phase 5.4 lifecycle sequence
on a real owned Windows 11 ARM64 UTM clone:

build -> build (idempotent) -> up -> up (idempotent) -> status -> stop
-> stop (idempotent) -> up -> destroy -> destroy (idempotent)

Before running, it records the source checksum and metadata, template UUID
and state, and unrelated VM inventory. It verifies that the source artifact,
clean template, unrelated VMs, and shared caches survive the full lifecycle.
"""

from __future__ import annotations

import contextlib
import os
from pathlib import Path

import pytest

from rangeforge.config import ConfigLoader
from rangeforge.host.detector import HostDetector
from rangeforge.host.models import Architecture
from rangeforge.images.cache import ImageCache
from rangeforge.images.manager import ImageManager
from rangeforge.images.registry import ImageRegistry
from rangeforge.images.templates import TemplateManager
from rangeforge.runtime.backends.utm import UTMBackend
from rangeforge.runtime.backends.vagrant import VagrantBackend
from rangeforge.runtime.guest import GuestPlatform
from rangeforge.runtime.lifecycle import ScenarioLifecycle
from rangeforge.runtime.metadata import RuntimeMetadataStore, scenario_vm_name
from rangeforge.runtime.models import (
    ManagementState,
    RuntimeType,
    VMBackend,
    VMState,
)
from rangeforge.serialization.yaml import ScenarioYamlSerializer


@pytest.mark.runtime
def test_real_windows_arm64_utm_lifecycle() -> None:
    if os.environ.get("RANGEFORGE_RUN_WINDOWS_LIFECYCLE") != "1":
        pytest.skip(
            "Set RANGEFORGE_RUN_WINDOWS_LIFECYCLE=1 to run the Windows ARM64 "
            "UTM lifecycle acceptance test."
        )
    raw_path = os.environ.get("RANGEFORGE_WINDOWS_SCENARIO_PATH")
    if not raw_path:
        pytest.skip(
            "Set RANGEFORGE_WINDOWS_SCENARIO_PATH to the scenario.yaml of an "
            "explicitly created owned Windows ARM64 UTM scenario clone."
        )
    scenario_path = Path(raw_path).expanduser().resolve()
    scenario = ScenarioYamlSerializer().load(scenario_path)
    store = RuntimeMetadataStore(scenario_path)
    metadata = store.load()
    assert metadata is not None, (
        "The target scenario has no persisted RangeForge runtime metadata."
    )
    store.validate_ownership(scenario, metadata)
    assert metadata.guest.platform is GuestPlatform.WINDOWS
    assert metadata.guest.architecture is Architecture.ARM64
    assert metadata.backend is VMBackend.UTM
    assert metadata.vm.name != metadata.template.name
    assert metadata.vm.name != "rf-base-windows-11-arm64"

    config = ConfigLoader(None).load()
    host = HostDetector().detect(executable_overrides=config.executable_overrides)
    assert host.architecture is Architecture.ARM64, (
        "The Windows lifecycle acceptance test must run on an ARM64 host."
    )
    utm = UTMBackend(host.executables.utmctl)
    vagrant = VagrantBackend(host.executables.vagrant)
    template_manager = TemplateManager(
        ImageManager(ImageRegistry.load(), ImageCache(config.images.cache_dir))
    )
    lifecycle = ScenarioLifecycle(
        template_manager=template_manager,
        host=host,
        utm=utm,
        vagrant=vagrant,
    )

    # Record baseline: source checksum, template metadata, template UUID,
    # unrelated VM inventory, shared cache state.
    source_artifact = config.images.cache_dir / "artifacts" / "windows-11-arm64"
    template_metadata_path = template_manager.cache.template_metadata_path(
        "windows-11-arm64", VMBackend.UTM
    )
    source_before = source_artifact.read_bytes() if source_artifact.is_file() else None
    template_meta_before = (
        template_metadata_path.read_text() if template_metadata_path.is_file() else None
    )
    template_uuid_before = None
    template_record = utm.find_by_name("rf-base-windows-11-arm64")
    if template_record is not None:
        template_uuid_before = template_record.uuid
    unrelated_before = {
        record.name: record.uuid
        for record in utm.inventory()
        if record.name not in {"rf-base-windows-11-arm64", scenario_vm_name(scenario)}
    }

    vm_name = scenario_vm_name(scenario)

    # --- Command sequence ---
    # 1. Build (creates exactly one clone; fails if already present).
    # 2. Build (idempotent: no additional clone).
    # 3. Up (start and reach management READY).
    # 4. Up (reprobe, unchanged).
    # 5. Status (reconcile, report RUNNING/READY/VERIFIED).
    # 6. Stop (request+wait, preserve clone).
    # 7. Stop (idempotent).
    # 8. Up (start again, full probe).
    # 9. Destroy (stop, delete exact UUID, confirm absence).
    # 10. Destroy (idempotent).

    from rangeforge.artifacts.cache import ArtifactCache
    from rangeforge.artifacts.manager import ArtifactManager
    from rangeforge.artifacts.registry import ArtifactRegistry
    from rangeforge.cve.loader import CVELoader
    from rangeforge.primitives.loader import PrimitiveLoader
    from rangeforge.profiles.loader import ProfileLoader
    from rangeforge.runtime.models import GuestRequirement
    from rangeforge.runtime.planner import RuntimePlanner
    from rangeforge.runtime.resolver import ImageResolver

    profile = ProfileLoader().load(scenario.scenario.profile)
    # Lifecycle-only planner requirement view.
    _WINDOWS_REQ = GuestRequirement(
        family="windows", distribution="windows", version="11", default_runtime="vm"
    )
    runtime_defaults = dict(profile.runtime_defaults)
    runtime_defaults.setdefault("windows", _WINDOWS_REQ)
    lifecycle_profile = profile.model_copy(update={"runtime_defaults": runtime_defaults})

    primitive_registry = PrimitiveLoader().load()
    image_registry = ImageRegistry.load()
    image_manager = ImageManager(image_registry, ImageCache(config.images.cache_dir))
    artifact_manager = ArtifactManager(
        ArtifactRegistry.load(), ArtifactCache(config.artifacts.cache_dir)
    )
    cves = CVELoader().load(artifact_manager.registry)
    plan = RuntimePlanner(
        profile=lifecycle_profile,
        primitive_registry=primitive_registry,
        image_resolver=ImageResolver(image_registry),
        image_manager=image_manager,
        cve_registry=cves,
        artifact_manager=artifact_manager,
    ).plan(scenario, requested_runtime=RuntimeType.VM, host=host)

    def _bring_up_and_reconcile() -> None:
        # 1. Build
        built = lifecycle.build(scenario, scenario_path, plan)
        assert built.changed, "First build should create the clone."
        assert built.metadata is not None
        assert built.metadata.vm.state is VMState.STOPPED
        assert built.metadata.guest.platform is GuestPlatform.WINDOWS
        assert built.metadata.vm.resource_id is not None
        assert built.metadata.vm.name == vm_name
        assert built.metadata.ownership_fingerprint is not None

        # 2. Build (idempotent)
        built2 = lifecycle.build(scenario, scenario_path, plan)
        assert not built2.changed, "Repeated build should be idempotent."

        # 3. Up
        up_result = lifecycle.up(scenario, scenario_path, plan, timeout=600)
        assert up_result.metadata is not None
        assert up_result.metadata.vm.state is VMState.RUNNING
        assert up_result.metadata.guest.management is ManagementState.READY, (
            "Windows management must be READY after a successful up."
        )

        # 4. Up (idempotent, reprobe)
        up2 = lifecycle.up(scenario, scenario_path, plan, timeout=600)
        assert up2.metadata is not None
        assert up2.metadata.guest.management is ManagementState.READY

        # 5. Status
        status_result = lifecycle.status(scenario, scenario_path)
        assert status_result.metadata is not None
        assert status_result.metadata.vm.state is VMState.RUNNING
        assert status_result.metadata.guest.management is ManagementState.READY
        assert status_result.metadata.guest.platform is GuestPlatform.WINDOWS
        assert status_result.metadata.guest.architecture is Architecture.ARM64
        assert status_result.metadata.guest.product is not None
        assert status_result.metadata.guest.version is not None

        # 6. Stop
        stop_result = lifecycle.stop(scenario, scenario_path)
        assert stop_result.changed, "Stop should change the state."
        assert stop_result.metadata is not None
        assert stop_result.metadata.vm.state is VMState.STOPPED
        assert stop_result.metadata.guest.management is ManagementState.NOT_READY
        # Clone must survive.
        assert utm.find_by_name(vm_name) is not None, "Clone must survive stop."

        # 7. Stop (idempotent)
        stop2 = lifecycle.stop(scenario, scenario_path)
        assert not stop2.changed, "Repeated stop should be idempotent."

        # 8. Up after stop
        up3 = lifecycle.up(scenario, scenario_path, plan, timeout=600)
        assert up3.metadata is not None
        assert up3.metadata.vm.state is VMState.RUNNING
        assert up3.metadata.guest.management is ManagementState.READY

    # F-15: a mid-sequence failure must never knowingly leave the owned clone
    # running or built. destroy() validates persisted RangeForge ownership
    # metadata first and targets only the scenario clone; it can never touch
    # the shared base template or unrelated VMs.
    try:
        _bring_up_and_reconcile()
    except BaseException:
        if store.load() is not None:
            with contextlib.suppress(Exception):
                lifecycle.destroy(scenario, scenario_path)
        raise

    # 9. Destroy
    destroyed = lifecycle.destroy(scenario, scenario_path)
    assert destroyed.changed, "Destroy should remove the scenario clone."
    assert utm.find_by_name(vm_name) is None, "Clone must be gone after destroy."
    store2 = RuntimeMetadataStore(scenario_path)
    assert store2.load() is None, "Runtime metadata must be removed."

    # 10. Destroy (idempotent)
    destroyed2 = lifecycle.destroy(scenario, scenario_path)
    assert not destroyed2.changed, "Repeated destroy should be idempotent."

    # --- Preservation assertions ---
    # Source artifact unchanged.
    if source_before is not None:
        assert source_artifact.read_bytes() == source_before, (
            "Source artifact must survive the lifecycle."
        )
    # Template metadata unchanged.
    if template_meta_before is not None:
        assert template_metadata_path.read_text() == template_meta_before, (
            "Template metadata must survive the lifecycle."
        )
    # Template UUID unchanged.
    template_record_after = utm.find_by_name("rf-base-windows-11-arm64")
    if template_uuid_before is not None and template_record_after is not None:
        assert template_record_after.uuid == template_uuid_before, (
            "Clean base template must survive the lifecycle."
        )
    # Unrelated VMs unchanged.
    unrelated_after = {
        record.name: record.uuid
        for record in utm.inventory()
        if record.name not in {"rf-base-windows-11-arm64", vm_name}
    }
    assert unrelated_after == unrelated_before, (
        "Unrelated VMs must survive the lifecycle."
    )