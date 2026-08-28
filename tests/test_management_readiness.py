"""Lifecycle-level Windows management readiness tests.

Verifies that Windows management is never marked READY from IP discovery
alone, that the fixed internal probe gates readiness on an owned running
UTM clone, and that shared base templates are never probed.
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
from rangeforge.runtime.backends.base import BackendOperationError
from rangeforge.runtime.backends.utm import UTMInventoryRecord
from rangeforge.runtime.guest import ExecutionLanguage, GuestPlatform
from rangeforge.runtime.lifecycle import LifecycleError, ScenarioLifecycle
from rangeforge.runtime.management import (
    ManagementCheck,
    ManagementProbeResult,
    ManagementTransportError,
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
HOST = HostInfo(os=HostOS.DARWIN, architecture=Architecture.ARM64, apple_silicon=True)


class LifecycleUTM:
    def __init__(self, template_name: str) -> None:
        self.executable = Path("/usr/local/bin/utmctl")
        self.vms: dict[str, dict] = {
            template_name: {"uuid": "template-uuid", "state": VMState.STOPPED}
        }
        self.started: list[str] = []
        self.addresses: tuple[str, ...] = ("192.168.64.9",)

    def available(self) -> bool:
        return True

    def template_exists(self, reference: str) -> bool:
        return reference in self.vms

    def vm_exists(self, name: str) -> bool:
        return name in self.vms

    def find_by_name(self, name: str) -> UTMInventoryRecord | None:
        entry = self.vms.get(name)
        if entry is None:
            return None
        return UTMInventoryRecord(
            uuid=entry["uuid"], name=name, state=entry["state"].value
        )

    def find_by_uuid(self, uuid: str) -> UTMInventoryRecord | None:
        for name, entry in self.vms.items():
            if entry["uuid"] == uuid:
                return UTMInventoryRecord(
                    uuid=uuid, name=name, state=entry["state"].value
                )
        return None

    def clone(self, template: str, name: str) -> None:
        assert template in self.vms
        self.vms[name] = {"uuid": f"uuid-{name}", "state": VMState.STOPPED}

    def start(self, name: str, *, uuid: str | None = None) -> None:
        self.vms[name]["state"] = VMState.RUNNING
        self.started.append(name)

    def stop(self, name: str, *, force: bool = False, uuid: str | None = None) -> None:
        self.vms[name]["state"] = VMState.STOPPED

    def delete(self, name: str, *, uuid: str | None = None) -> None:
        self.vms.pop(name)

    def vm_state(self, name: str, *, uuid: str | None = None) -> VMState:
        if uuid is not None:
            record = self.find_by_uuid(uuid)
            if record is None:
                return VMState.MISSING
            if record.name != name:
                raise BackendOperationError(
                    "Ownership conflict: UUID belongs to a different name."
                )
            return record.vm_state
        entry = self.vms.get(name)
        if entry is None:
            return VMState.NOT_BUILT
        return entry["state"]

    def ip_addresses(self, name: str, *, uuid: str | None = None) -> tuple[str, ...]:
        entry = self.vms.get(name)
        if entry is None:
            return ()
        return self.addresses if entry["state"] is VMState.RUNNING else ()


class UnusedVagrant:
    executable = None


def _probe_result(*, healthy: bool) -> ManagementProbeResult:
    """Probe-result stand-in: every check passes when healthy."""
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
def templates(tmp_path: Path, utm: LifecycleUTM) -> TemplateManager:
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
    templates = TemplateManager(manager)
    templates.prepare(manifest.id, VMBackend.UTM, utm)
    return templates


@pytest.fixture
def utm() -> LifecycleUTM:
    return LifecycleUTM(TEMPLATE_NAME)


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
    utm: LifecycleUTM,
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


def _patch_probe(
    monkeypatch: pytest.MonkeyPatch, *, healthy: bool
) -> list[str]:
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


def test_windows_up_requires_probe_and_marks_ready(
    windows_scenario: Scenario,
    templates: TemplateManager,
    utm: LifecycleUTM,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
    observed = _patch_probe(monkeypatch, healthy=True)
    result = _lifecycle(templates, utm).up(windows_scenario, scenario_path, _plan(windows_scenario))
    assert result.metadata is not None
    assert result.metadata.guest.management is ManagementState.READY
    assert result.metadata.guest.platform is windows_scenario_guest_platform()
    assert result.metadata.guest.execution_language is ExecutionLanguage.POWERSHELL
    assert result.metadata.guest.management_transport is (
        ManagementTransportKind.QEMU_GUEST_AGENT
    )
    assert observed == [result.metadata.vm.name]
    assert utm.started == [result.metadata.vm.name]


def test_windows_up_settles_qga_before_management_probe(
    windows_scenario: Scenario,
    templates: TemplateManager,
    utm: LifecycleUTM,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
    observed_sleeps: list[float] = []
    _patch_probe(monkeypatch, healthy=True)

    result = _lifecycle(
        templates, utm, sleeper=observed_sleeps.append
    ).up(windows_scenario, scenario_path, _plan(windows_scenario))

    assert result.metadata is not None
    assert result.metadata.guest.management is ManagementState.READY
    assert 10.0 in observed_sleeps


def windows_scenario_guest_platform():
    from rangeforge.runtime.guest import GuestPlatform

    return GuestPlatform.WINDOWS


def test_windows_up_is_not_ready_from_ip_discovery_alone(
    windows_scenario: Scenario,
    templates: TemplateManager,
    utm: LifecycleUTM,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
    _patch_probe(monkeypatch, healthy=False)
    with pytest.raises(LifecycleError, match="management readiness"):
        _lifecycle(templates, utm).up(windows_scenario, scenario_path, _plan(windows_scenario))
    # The clone has an IP and is running, yet management must stay unavailable.
    persisted = RuntimeMetadataStore(scenario_path).load()
    assert persisted is not None
    assert persisted.guest.ip == "192.168.64.9"
    assert persisted.vm.state is VMState.RUNNING
    assert persisted.guest.management is ManagementState.UNAVAILABLE


def test_windows_status_never_marks_ready_from_ip_alone(
    windows_scenario: Scenario,
    templates: TemplateManager,
    utm: LifecycleUTM,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
    name = scenario_vm_name(windows_scenario)
    tmpl = templates.require_ready("windows-11-arm64", VMBackend.UTM)
    RuntimeMetadataStore(scenario_path).save(
        _owned_metadata(
            windows_scenario,
            state=VMState.RUNNING,
            management=ManagementState.NOT_READY,
            ip="192.168.64.9",
            template=tmpl,
        )
    )
    utm.vms[name] = {"uuid": "scenario-uuid", "state": VMState.RUNNING}
    observed = _patch_probe(monkeypatch, healthy=False)
    result = _lifecycle(templates, utm).status(windows_scenario, scenario_path)
    assert observed == [name]
    assert result.metadata is not None
    assert result.metadata.guest.ip == "192.168.64.9"
    # Status reprobes every running Windows clone; a failed probe must never
    # mark READY from IP discovery alone.
    assert result.metadata.guest.management is ManagementState.UNAVAILABLE


def test_windows_status_downgrades_ready_when_vm_is_not_running(
    windows_scenario: Scenario,
    templates: TemplateManager,
    utm: LifecycleUTM,
    tmp_path: Path,
) -> None:
    """A stopped Windows clone can never retain READY across status refresh."""
    scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
    name = scenario_vm_name(windows_scenario)
    tmpl = templates.require_ready("windows-11-arm64", VMBackend.UTM)
    RuntimeMetadataStore(scenario_path).save(
        _owned_metadata(
            windows_scenario,
            state=VMState.STOPPED,
            management=ManagementState.READY,
            template=tmpl,
        )
    )
    utm.vms[name] = {"uuid": "scenario-uuid", "state": VMState.STOPPED}
    result = _lifecycle(templates, utm).status(windows_scenario, scenario_path)
    assert result.metadata is not None
    assert result.metadata.vm.state is VMState.STOPPED
    assert result.metadata.guest.management is ManagementState.NOT_READY


def test_windows_status_reprobes_ready_and_downgrades_on_failure(
    windows_scenario: Scenario,
    templates: TemplateManager,
    utm: LifecycleUTM,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A wedged channel cannot retain READY merely because its IP is stable."""
    scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
    name = scenario_vm_name(windows_scenario)
    tmpl = templates.require_ready("windows-11-arm64", VMBackend.UTM)
    RuntimeMetadataStore(scenario_path).save(
        _owned_metadata(
            windows_scenario,
            state=VMState.RUNNING,
            management=ManagementState.READY,
            ip="192.168.64.9",
            template=tmpl,
        )
    )
    utm.vms[name] = {"uuid": "scenario-uuid", "state": VMState.RUNNING}
    observed = _patch_probe(monkeypatch, healthy=False)
    result = _lifecycle(templates, utm).status(windows_scenario, scenario_path)
    assert observed == [name]
    assert result.metadata is not None
    assert result.metadata.vm.state is VMState.RUNNING
    assert result.metadata.guest.management is ManagementState.UNAVAILABLE
    assert "qga_execution" in result.message


def test_windows_status_reprobes_ready_and_keeps_on_success(
    windows_scenario: Scenario,
    templates: TemplateManager,
    utm: LifecycleUTM,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
    name = scenario_vm_name(windows_scenario)
    tmpl = templates.require_ready("windows-11-arm64", VMBackend.UTM)
    RuntimeMetadataStore(scenario_path).save(
        _owned_metadata(
            windows_scenario,
            state=VMState.RUNNING,
            management=ManagementState.READY,
            ip="192.168.64.9",
            template=tmpl,
        )
    )
    utm.vms[name] = {"uuid": "scenario-uuid", "state": VMState.RUNNING}
    observed = _patch_probe(monkeypatch, healthy=True)
    result = _lifecycle(templates, utm).status(windows_scenario, scenario_path)
    assert observed == [name]
    assert result.metadata is not None
    assert result.metadata.guest.management is ManagementState.READY


def test_windows_readiness_survives_persisted_metadata_errors(
    windows_scenario: Scenario,
    templates: TemplateManager,
    utm: LifecycleUTM,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Persisted-metadata races leave management unavailable, never escape."""
    from rangeforge.runtime.metadata import RuntimeMetadataError

    scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)

    def racing_factory(*args: object, **kwargs: object) -> object:
        raise RuntimeMetadataError("Runtime metadata changed during validation.")

    monkeypatch.setattr(lifecycle_module, "probe_windows_management", racing_factory)
    with pytest.raises(LifecycleError, match="management"):
        _lifecycle(templates, utm).up(
            windows_scenario, scenario_path, _plan(windows_scenario)
        )
    persisted = RuntimeMetadataStore(scenario_path).load()
    assert persisted is not None
    assert persisted.guest.management is ManagementState.UNAVAILABLE


def test_legacy_metadata_keeps_linux_ip_readiness(
    scenario: Scenario,
    templates: TemplateManager,
    utm: LifecycleUTM,
    tmp_path: Path,
) -> None:
    scenario_path = ScenarioYamlSerializer().dump(scenario, tmp_path)
    name = scenario_vm_name(scenario)
    RuntimeMetadataStore(scenario_path).save(
        RuntimeMetadata(
            scenario_id=scenario.scenario.id,
            profile=scenario.scenario.profile,
            runtime=RuntimeType.VM,
            backend=VMBackend.UTM,
            vm=VMIdentity(
                name=name, managed_id=scenario_managed_id(scenario), state=VMState.RUNNING
            ),
            template=_template_reference(),
            guest=RuntimeGuestState(architecture=Architecture.ARM64),
            metadata_version=2,
        )
    )
    utm.vms[name] = {"uuid": "legacy-uuid", "state": VMState.RUNNING}
    result = _lifecycle(templates, utm).status(scenario, scenario_path)
    assert result.metadata is not None
    assert result.metadata.guest.management is ManagementState.READY


def test_probe_never_targets_base_template(
    windows_scenario: Scenario,
    templates: TemplateManager,
    utm: LifecycleUTM,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
    name = scenario_vm_name(windows_scenario)

    def forbidden_factory(*args: object, **kwargs: object) -> None:
        raise AssertionError("transport construction must never reach the base template")

    monkeypatch.setattr(lifecycle_module, "probe_windows_management", forbidden_factory)
    tmpl = templates.require_ready("windows-11-arm64", VMBackend.UTM)
    tampered = _owned_metadata(
        windows_scenario, state=VMState.RUNNING, template=tmpl
    ).model_copy(
        update={
            "template": RuntimeTemplateReference(
                image_id=tmpl.image_id,
                template_id=tmpl.id,
                name=name,
                fingerprint=tmpl.fingerprint,
            )
        }
    )
    tampered = tampered.model_copy(
        update={"ownership_fingerprint": ownership_fingerprint(tampered)}
    )
    RuntimeMetadataStore(scenario_path).save(tampered)
    with pytest.raises(Exception, match="template"):
        _lifecycle(templates, utm).up(windows_scenario, scenario_path, _plan(windows_scenario))
    assert utm.started == []
    assert utm.vms[TEMPLATE_NAME]["state"] is VMState.STOPPED


def _template_reference():
    from rangeforge.runtime.models import RuntimeTemplateReference

    return RuntimeTemplateReference(
        image_id="windows-11-arm64",
        template_id=TEMPLATE_NAME,
        name=TEMPLATE_NAME,
        fingerprint="a" * 64,
    )


def _owned_metadata(
    scenario: Scenario,
    *,
    state: VMState,
    management: ManagementState = ManagementState.NOT_READY,
    ip: str | None = None,
    resource_id: str | None = "scenario-uuid",
    platform: GuestPlatform = GuestPlatform.WINDOWS,
    metadata_version: int = 4,
    template=None,
) -> RuntimeMetadata:
    """Build schema-4 owned metadata for an owned scenario clone.

    When ``template`` (the prepared ``BaseTemplate``) is provided, the
    persisted template identity and fingerprint match the trusted registry so
    idempotent build reconciliation and management-target validation succeed.
    """
    name = scenario_vm_name(scenario)
    template_ref = (
        RuntimeTemplateReference(
            image_id=template.image_id,
            template_id=template.id,
            name=template.reference,
            fingerprint=template.fingerprint,
        )
        if template is not None
        else _template_reference()
    )
    metadata = RuntimeMetadata(
        scenario_id=scenario.scenario.id,
        profile=scenario.scenario.profile,
        runtime=RuntimeType.VM,
        backend=VMBackend.UTM,
        vm=VMIdentity(
            name=name,
            managed_id=scenario_managed_id(scenario),
            state=state,
            resource_id=resource_id,
        ),
        template=template_ref,
        guest=RuntimeGuestState(
            architecture=Architecture.ARM64,
            ip=ip,
            management=management,
            platform=platform,
            management_transport=ManagementTransportKind.QEMU_GUEST_AGENT,
            execution_language=ExecutionLanguage.POWERSHELL,
        ),
        metadata_version=metadata_version,
    )
    return metadata.model_copy(
        update={"ownership_fingerprint": ownership_fingerprint(metadata)}
    )


def test_transport_error_leaves_management_unavailable(
    windows_scenario: Scenario,
    templates: TemplateManager,
    utm: LifecycleUTM,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)

    def failing_factory(*args: object, **kwargs: object) -> None:
        raise ManagementTransportError("Owned UTM scenario VM is missing.")

    monkeypatch.setattr(lifecycle_module, "probe_windows_management", failing_factory)
    with pytest.raises(LifecycleError, match="management"):
        _lifecycle(templates, utm).up(
            windows_scenario, scenario_path, _plan(windows_scenario)
        )
    persisted = RuntimeMetadataStore(scenario_path).load()
    assert persisted is not None
    assert persisted.guest.management is ManagementState.UNAVAILABLE


def test_legacy_windows_metadata_is_rejected_before_backend_calls(
    windows_scenario: Scenario,
    templates: TemplateManager,
    utm: LifecycleUTM,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pre-platform metadata cannot be trusted for a Windows scenario.

    Metadata written before platform-aware builds carries no platform and is
    only ever treated as Linux; silently treating a Windows scenario's record
    as Linux would bypass the fixed readiness probe and mark the clone READY
    from backend IP discovery alone. The stale record must be cleared
    explicitly before any backend call.
    """
    scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
    name = scenario_vm_name(windows_scenario)
    utm.vms[name] = {"uuid": "legacy-uuid", "state": VMState.RUNNING}
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
            template=_template_reference(),
            guest=RuntimeGuestState(architecture=Architecture.ARM64),
            metadata_version=2,
        )
    )

    def forbidden_factory(*args: object, **kwargs: object) -> None:
        raise AssertionError("transport construction must never reach legacy metadata")

    monkeypatch.setattr(lifecycle_module, "probe_windows_management", forbidden_factory)
    with pytest.raises(lifecycle_module.LifecycleError, match="cannot be reconciled"):
        _lifecycle(templates, utm).up(
            windows_scenario, scenario_path, _plan(windows_scenario)
        )
    with pytest.raises(lifecycle_module.LifecycleError, match="cannot be reconciled"):
        _lifecycle(templates, utm).status(windows_scenario, scenario_path)
    assert utm.started == []


def test_legacy_linux_metadata_still_uses_ip_readiness(
    scenario: Scenario,
    templates: TemplateManager,
    utm: LifecycleUTM,
    tmp_path: Path,
) -> None:
    """Legacy Linux metadata keeps the historical Linux behavior."""
    scenario_path = ScenarioYamlSerializer().dump(scenario, tmp_path)
    name = scenario_vm_name(scenario)
    utm.vms[name] = {"uuid": "legacy-uuid", "state": VMState.RUNNING}
    RuntimeMetadataStore(scenario_path).save(
        RuntimeMetadata(
            scenario_id=scenario.scenario.id,
            profile=scenario.scenario.profile,
            runtime=RuntimeType.VM,
            backend=VMBackend.UTM,
            vm=VMIdentity(
                name=name,
                managed_id=scenario_managed_id(scenario),
                state=VMState.RUNNING,
            ),
            template=_template_reference(),
            guest=RuntimeGuestState(architecture=Architecture.ARM64),
            metadata_version=2,
        )
    )
    result = _lifecycle(templates, utm).status(scenario, scenario_path)
    assert result.metadata is not None
    assert result.metadata.guest.management is ManagementState.READY


def test_windows_up_reprobes_stale_ready_and_downgrades(
    windows_scenario: Scenario,
    templates: TemplateManager,
    utm: LifecycleUTM,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A previously READY Windows channel must be re-verified on up()."""
    scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
    name = scenario_vm_name(windows_scenario)
    tmpl = templates.require_ready("windows-11-arm64", VMBackend.UTM)
    utm.vms[name] = {"uuid": "scenario-uuid", "state": VMState.RUNNING}
    RuntimeMetadataStore(scenario_path).save(
        _owned_metadata(
            windows_scenario,
            state=VMState.RUNNING,
            management=ManagementState.READY,
            ip="192.168.64.9",
            template=tmpl,
        )
    )
    observed = _patch_probe(monkeypatch, healthy=False)
    with pytest.raises(LifecycleError, match="management"):
        _lifecycle(templates, utm).up(
            windows_scenario, scenario_path, _plan(windows_scenario)
        )
    assert observed == [name]
    assert utm.started == []
    persisted = RuntimeMetadataStore(scenario_path).load()
    assert persisted is not None
    assert persisted.vm.state is VMState.RUNNING
    assert persisted.guest.management is ManagementState.UNAVAILABLE


def test_windows_up_keeps_ready_after_healthy_reprobe(
    windows_scenario: Scenario,
    templates: TemplateManager,
    utm: LifecycleUTM,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
    name = scenario_vm_name(windows_scenario)
    tmpl = templates.require_ready("windows-11-arm64", VMBackend.UTM)
    utm.vms[name] = {"uuid": "scenario-uuid", "state": VMState.RUNNING}
    RuntimeMetadataStore(scenario_path).save(
        _owned_metadata(
            windows_scenario,
            state=VMState.RUNNING,
            management=ManagementState.READY,
            ip="192.168.64.9",
            template=tmpl,
        )
    )
    observed = _patch_probe(monkeypatch, healthy=True)
    result = _lifecycle(templates, utm).up(
        windows_scenario, scenario_path, _plan(windows_scenario)
    )
    assert observed == [name]
    assert utm.started == []
    assert result.metadata is not None
    assert result.metadata.guest.management is ManagementState.READY
    assert result.message == "Scenario VM is already running and management is ready."
