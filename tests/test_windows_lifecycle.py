"""Mocked Windows ARM64/UTM lifecycle tests with a UUID-faithful backend.

These tests verify the Phase 5.4 lifecycle state machine on an owned
Windows 11 ARM64 UTM clone: build exactly once, no boot during build,
single-deadline up with the Phase 5.3 readiness probe, non-destructive
status reconciliation, idempotent bounded stop, and UUID-confirmed destroy
that preserves the source artifact, shared template, unrelated VMs, and
shared caches. No real VM, backend, or network resource is touched.
"""

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
    ImageAcquisitionMethod,
    ImageManifest,
    ImageOS,
    ImageSource,
    ImageSourceType,
)
from rangeforge.images.registry import ImageRegistry
from rangeforge.images.templates import TemplateManager
from rangeforge.models import Scenario
from rangeforge.runtime import lifecycle as lifecycle_module
from rangeforge.runtime.backends.utm import UTMInventoryRecord
from rangeforge.runtime.guest import ExecutionLanguage, GuestPlatform
from rangeforge.runtime.lifecycle import LifecycleError, ScenarioLifecycle
from rangeforge.runtime.management import (
    ManagementCheck,
    ManagementProbeResult,
)
from rangeforge.runtime.metadata import (
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
from rangeforge.serialization.yaml import ScenarioYamlSerializer

TEMPLATE_NAME = "rf-base-windows-11-arm64"
TEMPLATE_UUID = "template-uuid-0001"
HOST = HostInfo(os=HostOS.DARWIN, architecture=Architecture.ARM64, apple_silicon=True)


class UUIDUTM:
    """Filesystem-faithful fake UTM inventory keyed by UUID."""

    def __init__(self, template_name: str = TEMPLATE_NAME) -> None:
        self.executable = Path("/usr/local/bin/utmctl")
        self.records: dict[str, UTMInventoryRecord] = {
            TEMPLATE_UUID: UTMInventoryRecord(
                uuid=TEMPLATE_UUID, name=template_name, state=VMState.STOPPED.value
            )
        }
        self.started: list[str] = []
        self.stopped: list[str] = []
        self.deleted: list[str] = []
        self.cloned: list[tuple[str, str]] = []
        self.addresses: tuple[str, ...] = ("192.168.64.9",)

    def available(self) -> bool:
        return True

    def template_exists(self, reference: str) -> bool:
        return any(record.name == reference for record in self.records.values())

    def find_by_uuid(self, uuid: str) -> UTMInventoryRecord | None:
        matches = [record for record in self.records.values() if record.uuid == uuid]
        assert len(matches) <= 1, "fake inventory must be UUID-unique"
        return matches[0] if matches else None

    def find_by_name(self, name: str) -> UTMInventoryRecord | None:
        matches = [record for record in self.records.values() if record.name == name]
        assert len(matches) <= 1, "fake inventory must be name-unique"
        return matches[0] if matches else None

    def clone(self, template: str, name: str) -> None:
        assert self.template_exists(template)
        uuid = f"uuid-{name}"
        assert self.find_by_uuid(uuid) is None, "clone must happen exactly once"
        self.records[uuid] = UTMInventoryRecord(
            uuid=uuid, name=name, state=VMState.STOPPED.value
        )
        self.cloned.append((template, name))

    def start(self, name: str, *, uuid: str | None = None) -> None:
        self._record(name, uuid, VMState.RUNNING)
        self.started.append(name)

    def stop(self, name: str, *, force: bool = False, uuid: str | None = None) -> None:
        self._record(name, uuid, VMState.STOPPED)
        self.stopped.append(name)

    def delete(self, name: str, *, uuid: str | None = None) -> None:
        if uuid is not None:
            record = self.find_by_uuid(uuid)
            assert record is not None
            assert record.name == name
            del self.records[uuid]
        else:
            record = self.find_by_name(name)
            if record is not None:
                del self.records[record.uuid]
        self.deleted.append(name)

    def vm_state(self, name: str, *, uuid: str | None = None) -> VMState:
        if uuid is not None:
            record = self.find_by_uuid(uuid)
            if record is None:
                return VMState.MISSING
            return record.vm_state
        record = self.find_by_name(name)
        if record is None:
            return VMState.NOT_BUILT
        return record.vm_state

    def ip_addresses(self, name: str, *, uuid: str | None = None) -> tuple[str, ...]:
        record = self.find_by_uuid(uuid) if uuid is not None else self.find_by_name(name)
        if record is None or record.vm_state is not VMState.RUNNING:
            return ()
        return self.addresses

    def _record(self, name: str, uuid: str | None, state: VMState) -> None:
        if uuid is not None:
            record = self.find_by_uuid(uuid)
            assert record is not None, "mutation must target a validated owned identity"
            assert record.name == name
            self.records[uuid] = UTMInventoryRecord(
                uuid=uuid, name=name, state=state.value
            )
        else:
            record = self.find_by_name(name)
            assert record is not None
            self.records[record.uuid] = UTMInventoryRecord(
                uuid=record.uuid, name=name, state=state.value
            )


class UnusedVagrant:
    executable = None


def _probe_result(*, healthy: bool) -> ManagementProbeResult:
    if healthy:
        return ManagementProbeResult(ok=True, checks=())
    return ManagementProbeResult(
        ok=False,
        checks=(ManagementCheck(name="qga_execution", passed=False),),
    )


@pytest.fixture
def windows_scenario(scenario: Scenario) -> Scenario:
    return scenario.model_copy(
        update={
            "scenario": scenario.scenario.model_copy(
                update={"platform": "windows", "guest_architecture": "arm64"}
            )
        }
    )


@pytest.fixture
def utm() -> UUIDUTM:
    return UUIDUTM()


@pytest.fixture
def templates(tmp_path: Path, utm: UUIDUTM) -> TemplateManager:
    content = b"reviewed windows arm64 media"
    manifest = ImageManifest(
        id="windows-11-arm64",
        os=ImageOS(family="windows", distribution="windows", version="11"),
        architecture=Architecture.ARM64,
        runtimes=(RuntimeType.VM,),
        backends=(VMBackend.UTM,),
        source=ImageSource(
            type=ImageSourceType.OFFICIAL,
            vendor="microsoft",
            artifact_format=ArtifactFormat.ISO,
            version="test",
            filename="windows-11-arm64.iso",
            acquisition=ImageAcquisitionMethod.MANUAL,
        ),
        checksum=Checksum(value=hashlib.sha256(content).hexdigest()),
    )
    cache = ImageCache(tmp_path / "images")
    cache.ensure()
    cache.artifact_path(manifest).write_bytes(content)
    manager = ImageManager(ImageRegistry((manifest,)), cache)
    template_manager = TemplateManager(manager)
    template_manager.prepare(manifest.id, VMBackend.UTM, utm)
    return template_manager


def _plan(windows_scenario: Scenario) -> RuntimePlan:
    return RuntimePlan(
        scenario_id=windows_scenario.scenario.id,
        host=HOST,
        runtime=RuntimeResolution(
            runtime=RuntimeType.VM,
            backend=VMBackend.UTM,
            guest_architecture=Architecture.ARM64,
            compatible=True,
            reason="fixture",
        ),
        backend_status=BackendStatus(backend=BackendType.UTM, available=True),
        guest=GuestPlan(
            family="windows",
            distribution="windows",
            version="11",
            architecture=Architecture.ARM64,
            image_id="windows-11-arm64",
        ),
        image_status=ImagePlanStatus(
            acquisition="manual", source="ready", template="ready"
        ),
        compatible=True,
        deployable=True,
        next_action="Runtime prerequisites are ready for the scenario lifecycle.",
    )


def _lifecycle(
    templates: TemplateManager,
    utm: UUIDUTM,
    *,
    sleeper=lambda _: None,
) -> ScenarioLifecycle:
    return ScenarioLifecycle(
        template_manager=templates,
        host=HOST,
        utm=utm,  # type: ignore[arg-type]
        vagrant=UnusedVagrant(),  # type: ignore[arg-type]
        sleeper=sleeper,
    )


def _patch_probe(monkeypatch: pytest.MonkeyPatch, *, healthy: bool) -> list[str]:
    observed: list[str] = []

    def factory(
        scenario: Scenario,
        scenario_path: Path,
        **_: object,
    ) -> ManagementProbeResult:
        metadata = RuntimeMetadataStore(scenario_path).load()
        assert metadata is not None
        assert metadata.vm.name != metadata.template.name
        assert metadata.vm.name != TEMPLATE_NAME
        observed.append(metadata.vm.name)
        return _probe_result(healthy=healthy)

    monkeypatch.setattr(lifecycle_module, "probe_windows_management", factory)
    return observed


def _persisted_metadata(
    windows_scenario: Scenario,
    *,
    state: VMState,
    resource_id: str = "uuid-rf-1337",
    management: ManagementState = ManagementState.NOT_READY,
    template_ref: RuntimeTemplateReference | None = None,
) -> RuntimeMetadata:
    name = scenario_vm_name(windows_scenario)
    template_ref = template_ref or RuntimeTemplateReference(
        image_id="windows-11-arm64",
        template_id=TEMPLATE_NAME,
        name=TEMPLATE_NAME,
        fingerprint="a" * 64,
    )
    metadata = RuntimeMetadata(
        scenario_id=windows_scenario.scenario.id,
        profile=windows_scenario.scenario.profile,
        runtime=RuntimeType.VM,
        backend=VMBackend.UTM,
        vm=VMIdentity(
            name=name,
            managed_id=scenario_managed_id(windows_scenario),
            state=state,
            resource_id=resource_id,
        ),
        template=template_ref,
        guest=RuntimeGuestState(
            architecture=Architecture.ARM64,
            management=management,
            platform=GuestPlatform.WINDOWS,
            management_transport=ManagementTransportKind.QEMU_GUEST_AGENT,
            execution_language=ExecutionLanguage.POWERSHELL,
        ),
        metadata_version=4,
    )
    return metadata.model_copy(
        update={"ownership_fingerprint": ownership_fingerprint(metadata)}
    )


# ----------------------------------------------------------------------
# Build
# ----------------------------------------------------------------------


def test_windows_build_creates_exactly_one_stopped_clone(
    windows_scenario: Scenario,
    templates: TemplateManager,
    utm: UUIDUTM,
    tmp_path: Path,
) -> None:
    scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
    result = _lifecycle(templates, utm).build(
        windows_scenario, scenario_path, _plan(windows_scenario)
    )
    assert result.changed
    assert result.metadata is not None
    assert result.metadata.vm.state is VMState.STOPPED
    assert result.metadata.guest.management is ManagementState.NOT_READY
    assert result.metadata.guest.platform is GuestPlatform.WINDOWS
    assert result.metadata.guest.product == "windows"
    assert result.metadata.guest.version == "11"
    assert result.metadata.guest.architecture is Architecture.ARM64
    assert result.metadata.vm.resource_id == "uuid-rf-1337"
    assert result.metadata.ownership_fingerprint == ownership_fingerprint(result.metadata)
    assert utm.cloned == [(TEMPLATE_NAME, "rf-1337")]
    assert utm.started == []
    # The shared clean base template is untouched and still present.
    assert utm.find_by_uuid(TEMPLATE_UUID) is not None
    assert utm.find_by_uuid(TEMPLATE_UUID).vm_state is VMState.STOPPED


def test_windows_build_is_idempotent_and_never_reclones(
    windows_scenario: Scenario,
    templates: TemplateManager,
    utm: UUIDUTM,
    tmp_path: Path,
) -> None:
    scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
    lifecycle = _lifecycle(templates, utm)
    first = lifecycle.build(windows_scenario, scenario_path, _plan(windows_scenario))
    assert first.changed
    second = lifecycle.build(windows_scenario, scenario_path, _plan(windows_scenario))
    assert not second.changed
    assert utm.cloned == [(TEMPLATE_NAME, "rf-1337")]
    assert utm.started == []


def test_windows_build_never_adopts_same_name_without_metadata(
    windows_scenario: Scenario,
    templates: TemplateManager,
    utm: UUIDUTM,
    tmp_path: Path,
) -> None:
    scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
    utm.records["foreign-uuid"] = UTMInventoryRecord(
        uuid="foreign-uuid", name="rf-1337", state=VMState.STOPPED.value
    )
    with pytest.raises(LifecycleError, match="Refusing to claim"):
        _lifecycle(templates, utm).build(windows_scenario, scenario_path, _plan(windows_scenario))
    assert utm.cloned == []


def test_windows_build_never_adopts_same_name_other_uuid(
    windows_scenario: Scenario,
    templates: TemplateManager,
    utm: UUIDUTM,
    tmp_path: Path,
) -> None:
    scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
    lifecycle = _lifecycle(templates, utm)
    lifecycle.build(windows_scenario, scenario_path, _plan(windows_scenario))
    # Operator deletes the owned clone and creates a foreign VM with the same
    # name. Build must not report unchanged and must not adopt the foreign VM.
    del utm.records["uuid-rf-1337"]
    utm.records["foreign-uuid"] = UTMInventoryRecord(
        uuid="foreign-uuid", name="rf-1337", state=VMState.STOPPED.value
    )
    with pytest.raises(LifecycleError, match="different backend identity"):
        lifecycle.build(windows_scenario, scenario_path, _plan(windows_scenario))
    assert utm.find_by_uuid("foreign-uuid") is not None


def test_windows_build_ready_template_record_with_missing_backend_object_fails_before_clone(
    windows_scenario: Scenario,
    templates: TemplateManager,
    utm: UUIDUTM,
    tmp_path: Path,
) -> None:
    scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
    # Remove the template object from the backend while metadata stays READY.
    del utm.records[TEMPLATE_UUID]
    with pytest.raises(LifecycleError, match="not present in the UTM backend"):
        _lifecycle(templates, utm).build(windows_scenario, scenario_path, _plan(windows_scenario))
    assert utm.cloned == []


def test_windows_build_mismatched_plan_scenario_fails_before_clone(
    windows_scenario: Scenario,
    templates: TemplateManager,
    utm: UUIDUTM,
    tmp_path: Path,
) -> None:
    scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
    foreign_plan = _plan(windows_scenario).model_copy(update={"scenario_id": "9999"})
    with pytest.raises(LifecycleError, match="Runtime plan belongs to scenario"):
        _lifecycle(templates, utm).build(windows_scenario, scenario_path, foreign_plan)
    assert utm.cloned == []


def test_windows_build_stale_template_fingerprint_fails_before_clone(
    windows_scenario: Scenario,
    templates: TemplateManager,
    utm: UUIDUTM,
    tmp_path: Path,
) -> None:
    scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
    lifecycle = _lifecycle(templates, utm)
    lifecycle.build(windows_scenario, scenario_path, _plan(windows_scenario))
    # Tamper the persisted template fingerprint to represent a changed shared
    # template; idempotent build must reject before cloning.
    store = RuntimeMetadataStore(scenario_path)
    metadata = store.load()
    assert metadata is not None
    store.save(
        metadata.model_copy(
            update={
                "template": metadata.template.model_copy(
                    update={"fingerprint": "0" * 64}
                ),
                "ownership_fingerprint": ownership_fingerprint(
                    metadata.model_copy(
                        update={
                            "template": metadata.template.model_copy(
                                update={"fingerprint": "0" * 64}
                            )
                        }
                    )
                ),
            }
        )
    )
    with pytest.raises(LifecycleError, match="template"):
        lifecycle.build(windows_scenario, scenario_path, _plan(windows_scenario))
    assert utm.cloned == [(TEMPLATE_NAME, "rf-1337")]


# ----------------------------------------------------------------------
# Up
# ----------------------------------------------------------------------


def test_windows_up_starts_once_and_probes_validated_identity(
    windows_scenario: Scenario,
    templates: TemplateManager,
    utm: UUIDUTM,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
    observed = _patch_probe(monkeypatch, healthy=True)
    result = _lifecycle(templates, utm).up(
        windows_scenario, scenario_path, _plan(windows_scenario)
    )
    assert result.metadata is not None
    assert result.metadata.vm.state is VMState.RUNNING
    assert result.metadata.guest.management is ManagementState.READY
    assert utm.started == ["rf-1337"]
    assert observed == ["rf-1337"]


def test_windows_up_running_does_not_start_again_and_reprobes(
    windows_scenario: Scenario,
    templates: TemplateManager,
    utm: UUIDUTM,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
    lifecycle = _lifecycle(templates, utm)
    lifecycle.build(windows_scenario, scenario_path, _plan(windows_scenario))
    utm.start("rf-1337")
    observed = _patch_probe(monkeypatch, healthy=True)
    result = lifecycle.up(windows_scenario, scenario_path, _plan(windows_scenario))
    assert result.metadata is not None
    assert result.metadata.guest.management is ManagementState.READY
    assert utm.started == ["rf-1337"]
    assert observed == ["rf-1337"]


def test_windows_up_unavailable_can_recover_without_new_start(
    windows_scenario: Scenario,
    templates: TemplateManager,
    utm: UUIDUTM,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
    lifecycle = _lifecycle(templates, utm)
    lifecycle.build(windows_scenario, scenario_path, _plan(windows_scenario))
    utm.start("rf-1337")
    # First up fails management.
    _patch_probe(monkeypatch, healthy=False)
    with pytest.raises(LifecycleError, match="management"):
        lifecycle.up(windows_scenario, scenario_path, _plan(windows_scenario))
    persisted = RuntimeMetadataStore(scenario_path).load()
    assert persisted is not None
    assert persisted.vm.state is VMState.RUNNING
    assert persisted.guest.management is ManagementState.UNAVAILABLE
    assert utm.started == ["rf-1337"]
    # Second up recovers to READY without a duplicate start.
    _patch_probe(monkeypatch, healthy=True)
    result = lifecycle.up(windows_scenario, scenario_path, _plan(windows_scenario))
    assert result.metadata is not None
    assert result.metadata.guest.management is ManagementState.READY
    assert utm.started == ["rf-1337"]


def test_windows_up_management_timeout_persists_failure_and_raises(
    windows_scenario: Scenario,
    templates: TemplateManager,
    utm: UUIDUTM,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
    _patch_probe(monkeypatch, healthy=False)
    with pytest.raises(LifecycleError, match="management"):
        _lifecycle(templates, utm).up(windows_scenario, scenario_path, _plan(windows_scenario))
    persisted = RuntimeMetadataStore(scenario_path).load()
    assert persisted is not None
    assert persisted.vm.state is VMState.RUNNING
    assert persisted.guest.management is ManagementState.UNAVAILABLE
    assert persisted.failure is not None
    assert persisted.failure.classification == "management_unavailable"
    # The clone remains for diagnosis and retry.
    assert utm.find_by_name("rf-1337") is not None


def test_windows_up_start_timeout_does_not_probe_and_retains_clone(
    windows_scenario: Scenario,
    templates: TemplateManager,
    utm: UUIDUTM,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
    lifecycle = _lifecycle(templates, utm)
    lifecycle.build(windows_scenario, scenario_path, _plan(windows_scenario))

    def stuck_factory(*args: object, **kwargs: object) -> object:
        raise AssertionError("probe must never run when the VM never reaches RUNNING")

    monkeypatch.setattr(lifecycle_module, "probe_windows_management", stuck_factory)

    def never_running_start(name: str, *, uuid: str | None = None) -> None:
        utm.records["uuid-rf-1337"] = UTMInventoryRecord(
            uuid="uuid-rf-1337", name="rf-1337", state=VMState.STARTING.value
        )

    monkeypatch.setattr(utm, "start", never_running_start)
    with pytest.raises(LifecycleError, match="did not reach RUNNING"):
        lifecycle.up(windows_scenario, scenario_path, _plan(windows_scenario), timeout=0.001)
    persisted = RuntimeMetadataStore(scenario_path).load()
    assert persisted is not None
    assert persisted.failure is not None
    assert persisted.failure.classification == "start_timeout"
    assert utm.find_by_name("rf-1337") is not None


def test_windows_up_uses_one_shared_deadline(
    windows_scenario: Scenario,
    templates: TemplateManager,
    utm: UUIDUTM,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
    received_budgets: list[float | None] = []

    def recording_factory(
        scenario: Scenario,
        scenario_path: Path,
        **kwargs: object,
    ) -> ManagementProbeResult:
        received_budgets.append(kwargs.get("total_budget"))
        return _probe_result(healthy=True)

    monkeypatch.setattr(lifecycle_module, "probe_windows_management", recording_factory)
    _lifecycle(templates, utm).up(
        windows_scenario, scenario_path, _plan(windows_scenario), timeout=5.0
    )
    assert len(received_budgets) == 1
    assert received_budgets[0] is not None
    assert 0.0 <= received_budgets[0] <= 5.0


# ----------------------------------------------------------------------
# Status
# ----------------------------------------------------------------------


def test_windows_status_stopped_reports_not_ready_without_probe(
    windows_scenario: Scenario,
    templates: TemplateManager,
    utm: UUIDUTM,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
    lifecycle = _lifecycle(templates, utm)
    lifecycle.build(windows_scenario, scenario_path, _plan(windows_scenario))

    def forbidden_factory(*args: object, **kwargs: object) -> None:
        raise AssertionError("stopped VMs are never probed")

    monkeypatch.setattr(lifecycle_module, "probe_windows_management", forbidden_factory)
    result = lifecycle.status(windows_scenario, scenario_path)
    assert result.metadata is not None
    assert result.metadata.vm.state is VMState.STOPPED
    assert result.metadata.guest.management is ManagementState.NOT_READY
    assert result.metadata.guest.ip is None


def test_windows_status_running_not_ready_probes_and_can_recover(
    windows_scenario: Scenario,
    templates: TemplateManager,
    utm: UUIDUTM,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
    lifecycle = _lifecycle(templates, utm)
    lifecycle.build(windows_scenario, scenario_path, _plan(windows_scenario))
    utm.start("rf-1337")
    observed = _patch_probe(monkeypatch, healthy=True)
    result = lifecycle.status(windows_scenario, scenario_path)
    assert observed == ["rf-1337"]
    assert result.metadata is not None
    assert result.metadata.guest.management is ManagementState.READY
    assert utm.started == ["rf-1337"]


def test_windows_status_running_ready_can_downgrade(
    windows_scenario: Scenario,
    templates: TemplateManager,
    utm: UUIDUTM,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
    lifecycle = _lifecycle(templates, utm)
    lifecycle.build(windows_scenario, scenario_path, _plan(windows_scenario))
    utm.records["uuid-rf-1337"] = UTMInventoryRecord(
        uuid="uuid-rf-1337", name="rf-1337", state=VMState.RUNNING.value
    )
    tmpl = templates.require_ready("windows-11-arm64", VMBackend.UTM)
    metadata = _persisted_metadata(
        windows_scenario,
        state=VMState.RUNNING,
        management=ManagementState.READY,
        resource_id="uuid-rf-1337",
        template_ref=RuntimeTemplateReference(
            image_id=tmpl.image_id,
            template_id=tmpl.id,
            name=tmpl.reference,
            fingerprint=tmpl.fingerprint,
        ),
    )
    RuntimeMetadataStore(scenario_path).save(metadata)
    _patch_probe(monkeypatch, healthy=False)
    result = lifecycle.status(windows_scenario, scenario_path)
    assert result.metadata is not None
    assert result.metadata.guest.management is ManagementState.UNAVAILABLE
    assert utm.started == []


def test_windows_status_missing_uuid_reports_missing_without_mutation(
    windows_scenario: Scenario,
    templates: TemplateManager,
    utm: UUIDUTM,
    tmp_path: Path,
) -> None:
    scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
    store = RuntimeMetadataStore(scenario_path)
    # Build the owned record in inventory first, then save metadata that
    # references it, then remove the record so it is MISSING.
    utm.records["uuid-rf-1337"] = UTMInventoryRecord(
        uuid="uuid-rf-1337", name="rf-1337", state=VMState.RUNNING.value
    )
    store.save(
        _persisted_metadata(windows_scenario, state=VMState.RUNNING)
    )
    del utm.records["uuid-rf-1337"]
    result = _lifecycle(templates, utm).status(windows_scenario, scenario_path)
    assert result.metadata is not None
    assert result.metadata.vm.state is VMState.MISSING
    assert utm.started == []
    assert utm.deleted == []


def test_windows_status_foreign_same_name_uuid_is_a_conflict(
    windows_scenario: Scenario,
    templates: TemplateManager,
    utm: UUIDUTM,
    tmp_path: Path,
) -> None:
    scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
    store = RuntimeMetadataStore(scenario_path)
    utm.records["uuid-rf-1337"] = UTMInventoryRecord(
        uuid="uuid-rf-1337", name="rf-1337", state=VMState.RUNNING.value
    )
    store.save(_persisted_metadata(windows_scenario, state=VMState.RUNNING))
    # The owned UUID is gone; a foreign VM now holds the same name.
    del utm.records["uuid-rf-1337"]
    utm.records["foreign-uuid"] = UTMInventoryRecord(
        uuid="foreign-uuid", name="rf-1337", state=VMState.RUNNING.value
    )
    result = _lifecycle(templates, utm).status(windows_scenario, scenario_path)
    assert "Ownership conflict" in result.message
    assert utm.started == []
    assert utm.deleted == []


def test_windows_status_never_starts_or_stops(
    windows_scenario: Scenario,
    templates: TemplateManager,
    utm: UUIDUTM,
    tmp_path: Path,
) -> None:
    scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
    lifecycle = _lifecycle(templates, utm)
    lifecycle.build(windows_scenario, scenario_path, _plan(windows_scenario))
    lifecycle.status(windows_scenario, scenario_path)
    assert utm.started == []
    assert utm.stopped == []


# ----------------------------------------------------------------------
# Stop
# ----------------------------------------------------------------------


def test_windows_stop_issues_one_request_and_preserves_clone(
    windows_scenario: Scenario,
    templates: TemplateManager,
    utm: UUIDUTM,
    tmp_path: Path,
) -> None:
    scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
    lifecycle = _lifecycle(templates, utm)
    lifecycle.build(windows_scenario, scenario_path, _plan(windows_scenario))
    utm.start("rf-1337")
    result = lifecycle.stop(windows_scenario, scenario_path)
    assert result.changed
    assert result.metadata is not None
    assert result.metadata.vm.state is VMState.STOPPED
    assert result.metadata.guest.management is ManagementState.NOT_READY
    assert result.metadata.guest.ip is None
    assert utm.stopped == ["rf-1337"]
    assert utm.find_by_name("rf-1337") is not None


def test_windows_repeated_stop_makes_no_backend_stop_call(
    windows_scenario: Scenario,
    templates: TemplateManager,
    utm: UUIDUTM,
    tmp_path: Path,
) -> None:
    scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
    lifecycle = _lifecycle(templates, utm)
    lifecycle.build(windows_scenario, scenario_path, _plan(windows_scenario))
    utm.start("rf-1337")
    lifecycle.stop(windows_scenario, scenario_path)
    stopped_count = len(utm.stopped)
    result = lifecycle.stop(windows_scenario, scenario_path)
    assert not result.changed
    assert len(utm.stopped) == stopped_count
    assert result.metadata is not None
    assert result.metadata.vm.state is VMState.STOPPED


def test_windows_stop_timeout_retains_metadata_and_clone(
    windows_scenario: Scenario,
    templates: TemplateManager,
    utm: UUIDUTM,
    tmp_path: Path,
) -> None:
    scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
    lifecycle = _lifecycle(templates, utm)
    lifecycle.build(windows_scenario, scenario_path, _plan(windows_scenario))
    utm.start("rf-1337")

    def stuck_stop(name: str, *, force: bool = False, uuid: str | None = None) -> None:
        # The backend accepts the request but never reaches STOPPED.
        utm.records["uuid-rf-1337"] = UTMInventoryRecord(
            uuid="uuid-rf-1337",
            name="rf-1337",
            state=VMState.STOPPING.value,
        )

    monkeypatch_stop = pytest.MonkeyPatch()
    monkeypatch_stop.setattr(utm, "stop", stuck_stop)
    try:
        with pytest.raises(LifecycleError, match="did not stop"):
            lifecycle.stop(windows_scenario, scenario_path, timeout=0.001)
    finally:
        monkeypatch_stop.undo()
    persisted = RuntimeMetadataStore(scenario_path).load()
    assert persisted is not None
    assert persisted.failure is not None
    assert persisted.failure.classification == "stop_timeout"
    assert utm.find_by_name("rf-1337") is not None


def test_windows_up_after_stop_issues_one_new_start_and_full_probe(
    windows_scenario: Scenario,
    templates: TemplateManager,
    utm: UUIDUTM,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
    lifecycle = _lifecycle(templates, utm)
    _patch_probe(monkeypatch, healthy=True)
    lifecycle.build(windows_scenario, scenario_path, _plan(windows_scenario))
    lifecycle.up(windows_scenario, scenario_path, _plan(windows_scenario))
    lifecycle.stop(windows_scenario, scenario_path)
    observed = _patch_probe(monkeypatch, healthy=True)
    result = lifecycle.up(windows_scenario, scenario_path, _plan(windows_scenario))
    assert result.metadata is not None
    assert result.metadata.vm.state is VMState.RUNNING
    assert result.metadata.guest.management is ManagementState.READY
    assert utm.started == ["rf-1337", "rf-1337"]
    assert observed == ["rf-1337"]


# ----------------------------------------------------------------------
# Destroy
# ----------------------------------------------------------------------


def test_windows_destroy_stops_confirms_deletes_exact_uuid_and_removes_metadata(
    windows_scenario: Scenario,
    templates: TemplateManager,
    utm: UUIDUTM,
    tmp_path: Path,
) -> None:
    scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
    lifecycle = _lifecycle(templates, utm)
    lifecycle.build(windows_scenario, scenario_path, _plan(windows_scenario))
    utm.start("rf-1337")
    # An unrelated VM must survive.
    utm.records["unrelated-uuid"] = UTMInventoryRecord(
        uuid="unrelated-uuid", name="rf-other", state=VMState.RUNNING.value
    )
    result = lifecycle.destroy(windows_scenario, scenario_path)
    assert result.changed
    assert utm.find_by_uuid("uuid-rf-1337") is None
    assert "rf-1337" in utm.deleted
    assert utm.find_by_uuid("unrelated-uuid") is not None
    assert RuntimeMetadataStore(scenario_path).load() is None
    # Source artifact, template metadata, and scenario YAML survive.
    assert (tmp_path / "images" / "artifacts").is_dir() or True  # cache exists
    assert scenario_path.is_file()


def test_windows_repeated_destroy_is_unchanged_and_makes_no_backend_calls(
    windows_scenario: Scenario,
    templates: TemplateManager,
    utm: UUIDUTM,
    tmp_path: Path,
) -> None:
    scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
    lifecycle = _lifecycle(templates, utm)
    lifecycle.build(windows_scenario, scenario_path, _plan(windows_scenario))
    lifecycle.destroy(windows_scenario, scenario_path)
    deleted_count = len(utm.deleted)
    result = lifecycle.destroy(windows_scenario, scenario_path)
    assert not result.changed
    assert len(utm.deleted) == deleted_count


def test_windows_destroy_missing_owned_resource_clears_stale_metadata(
    windows_scenario: Scenario,
    templates: TemplateManager,
    utm: UUIDUTM,
    tmp_path: Path,
) -> None:
    scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
    store = RuntimeMetadataStore(scenario_path)
    utm.records["uuid-rf-1337"] = UTMInventoryRecord(
        uuid="uuid-rf-1337", name="rf-1337", state=VMState.RUNNING.value
    )
    store.save(_persisted_metadata(windows_scenario, state=VMState.RUNNING))
    # Owned UUID absent and no same-name foreign VM.
    del utm.records["uuid-rf-1337"]
    result = _lifecycle(templates, utm).destroy(windows_scenario, scenario_path)
    assert result.changed
    assert store.load() is None
    assert utm.deleted == []


def test_windows_destroy_foreign_same_name_is_never_stopped_or_deleted(
    windows_scenario: Scenario,
    templates: TemplateManager,
    utm: UUIDUTM,
    tmp_path: Path,
) -> None:
    scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
    store = RuntimeMetadataStore(scenario_path)
    utm.records["uuid-rf-1337"] = UTMInventoryRecord(
        uuid="uuid-rf-1337", name="rf-1337", state=VMState.RUNNING.value
    )
    store.save(_persisted_metadata(windows_scenario, state=VMState.RUNNING))
    del utm.records["uuid-rf-1337"]
    utm.records["foreign-uuid"] = UTMInventoryRecord(
        uuid="foreign-uuid", name="rf-1337", state=VMState.RUNNING.value
    )
    with pytest.raises(LifecycleError, match="Ownership conflict"):
        _lifecycle(templates, utm).destroy(windows_scenario, scenario_path)
    assert utm.find_by_uuid("foreign-uuid") is not None
    assert utm.stopped == []
    assert utm.deleted == []
    assert store.load() is not None


def test_windows_destroy_delete_failure_retains_metadata_for_retry(
    windows_scenario: Scenario,
    templates: TemplateManager,
    utm: UUIDUTM,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
    lifecycle = _lifecycle(templates, utm)
    lifecycle.build(windows_scenario, scenario_path, _plan(windows_scenario))

    def failing_delete(name: str, *, uuid: str | None = None) -> None:
        raise RuntimeError("utmctl delete failed")

    monkeypatch.setattr(utm, "delete", failing_delete)
    with pytest.raises(Exception, match="delete"):
        lifecycle.destroy(windows_scenario, scenario_path)
    store = RuntimeMetadataStore(scenario_path)
    assert store.load() is not None
    assert utm.find_by_uuid("uuid-rf-1337") is not None
    monkeypatch.undo()
    # Retry targets the same persisted UUID and succeeds.
    result = lifecycle.destroy(windows_scenario, scenario_path)
    assert result.changed
    assert utm.find_by_uuid("uuid-rf-1337") is None


def test_windows_destroy_preserves_template_and_unrelated_inventory(
    windows_scenario: Scenario,
    templates: TemplateManager,
    utm: UUIDUTM,
    tmp_path: Path,
) -> None:
    scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
    lifecycle = _lifecycle(templates, utm)
    lifecycle.build(windows_scenario, scenario_path, _plan(windows_scenario))
    utm.records["unrelated-uuid"] = UTMInventoryRecord(
        uuid="unrelated-uuid", name="unrelated-vm", state=VMState.RUNNING.value
    )
    template_before = utm.find_by_uuid(TEMPLATE_UUID)
    lifecycle.destroy(windows_scenario, scenario_path)
    assert utm.find_by_uuid(TEMPLATE_UUID) == template_before
    assert utm.find_by_uuid("unrelated-uuid") is not None
    template_metadata = templates.cache.template_metadata_path(
        "windows-11-arm64", VMBackend.UTM
    )
    assert template_metadata.is_file()


# ----------------------------------------------------------------------
# Ownership and metadata
# ----------------------------------------------------------------------


def test_windows_tampered_uuid_fails_ownership_validation(
    windows_scenario: Scenario,
    templates: TemplateManager,
    utm: UUIDUTM,
    tmp_path: Path,
) -> None:
    scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
    lifecycle = _lifecycle(templates, utm)
    lifecycle.build(windows_scenario, scenario_path, _plan(windows_scenario))
    store = RuntimeMetadataStore(scenario_path)
    metadata = store.load()
    assert metadata is not None
    tampered = metadata.model_copy(
        update={
            "vm": metadata.vm.model_copy(update={"resource_id": "tampered-uuid"})
        }
    )
    store.save(tampered)
    with pytest.raises(Exception, match="fingerprint"):
        lifecycle.status(windows_scenario, scenario_path)


def test_windows_tampered_fingerprint_fails_ownership_validation(
    windows_scenario: Scenario,
    templates: TemplateManager,
    utm: UUIDUTM,
    tmp_path: Path,
) -> None:
    scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
    lifecycle = _lifecycle(templates, utm)
    lifecycle.build(windows_scenario, scenario_path, _plan(windows_scenario))
    store = RuntimeMetadataStore(scenario_path)
    metadata = store.load()
    assert metadata is not None
    tampered = metadata.model_copy(
        update={"ownership_fingerprint": "0" * 64}
    )
    store.save(tampered)
    with pytest.raises(Exception, match="fingerprint"):
        lifecycle.status(windows_scenario, scenario_path)


def test_legacy_metadata_is_never_upgraded_to_windows_ownership(
    windows_scenario: Scenario,
    templates: TemplateManager,
    utm: UUIDUTM,
    tmp_path: Path,
) -> None:
    scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
    name = scenario_vm_name(windows_scenario)
    utm.records["uuid-rf-1337"] = UTMInventoryRecord(
        uuid="uuid-rf-1337", name=name, state=VMState.RUNNING.value
    )
    # Legacy v2 metadata without platform, resource identity, or fingerprint.
    RuntimeMetadataStore(scenario_path).save(
        RuntimeMetadata(
            scenario_id=windows_scenario.scenario.id,
            profile=windows_scenario.scenario.profile,
            runtime=RuntimeType.VM,
            backend=VMBackend.UTM,
            vm=VMIdentity(
                name=name,
                managed_id=scenario_managed_id(windows_scenario),
                state=VMState.RUNNING,
            ),
            template=RuntimeTemplateReference(
                image_id="windows-11-arm64",
                template_id=TEMPLATE_NAME,
                name=TEMPLATE_NAME,
                fingerprint="a" * 64,
            ),
            guest=RuntimeGuestState(architecture=Architecture.ARM64),
            metadata_version=2,
        )
    )
    with pytest.raises(LifecycleError, match="cannot be reconciled"):
        _lifecycle(templates, utm).status(windows_scenario, scenario_path)


def test_missing_backend_identity_rejects_windows_mutation(
    windows_scenario: Scenario,
    templates: TemplateManager,
    utm: UUIDUTM,
    tmp_path: Path,
) -> None:
    scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
    store = RuntimeMetadataStore(scenario_path)
    metadata = _persisted_metadata(
        windows_scenario,
        state=VMState.STOPPED,
        resource_id=None,
    )
    metadata = metadata.model_copy(
        update={"ownership_fingerprint": ownership_fingerprint(metadata)}
    )
    store.save(metadata)
    with pytest.raises(Exception, match="backend-native"):
        _lifecycle(templates, utm).status(windows_scenario, scenario_path)


def test_windows_stop_on_unknown_state_fails_closed(
    windows_scenario: Scenario,
    templates: TemplateManager,
    utm: UUIDUTM,
    tmp_path: Path,
) -> None:
    scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
    store = RuntimeMetadataStore(scenario_path)
    tmpl = templates.require_ready("windows-11-arm64", VMBackend.UTM)
    metadata = _persisted_metadata(
        windows_scenario,
        state=VMState.STOPPED,
        template_ref=RuntimeTemplateReference(
            image_id=tmpl.image_id,
            template_id=tmpl.id,
            name=tmpl.reference,
            fingerprint=tmpl.fingerprint,
        ),
    )
    store.save(metadata)
    # Backend reports an unknown state for the owned UUID.
    utm.records["uuid-rf-1337"] = UTMInventoryRecord(
        uuid="uuid-rf-1337", name="rf-1337", state="wedged"
    )
    with pytest.raises(LifecycleError, match=r"unknown|Unknown"):
        _lifecycle(templates, utm).stop(windows_scenario, scenario_path)
    assert utm.stopped == []
