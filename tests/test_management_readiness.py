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
from rangeforge.runtime.guest import ExecutionLanguage
from rangeforge.runtime.lifecycle import ScenarioLifecycle
from rangeforge.runtime.management import (
    ManagementCheck,
    ManagementProbeResult,
    ManagementTransportError,
)
from rangeforge.runtime.metadata import (
    RuntimeMetadataStore,
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
        self.vms: dict[str, VMState] = {template_name: VMState.STOPPED}
        self.started: list[str] = []

    def available(self) -> bool:
        return True

    def template_exists(self, reference: str) -> bool:
        return reference in self.vms

    def vm_exists(self, name: str) -> bool:
        return name in self.vms

    def clone(self, template: str, name: str) -> None:
        assert template in self.vms
        self.vms[name] = VMState.STOPPED

    def start(self, name: str) -> None:
        self.vms[name] = VMState.RUNNING
        self.started.append(name)

    def stop(self, name: str, *, force: bool = False) -> None:
        self.vms[name] = VMState.STOPPED

    def delete(self, name: str) -> None:
        self.vms.pop(name)

    def vm_state(self, name: str) -> VMState:
        return self.vms.get(name, VMState.NOT_BUILT)

    def ip_addresses(self, name: str) -> tuple[str, ...]:
        return ("192.168.64.9",) if self.vms.get(name) is VMState.RUNNING else ()


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
    result = _lifecycle(templates, utm).up(windows_scenario, scenario_path, _plan(windows_scenario))
    assert result.metadata is not None
    # The clone has an IP and is running, yet management must stay unavailable.
    assert result.metadata.guest.ip == "192.168.64.9"
    assert result.metadata.vm.state is VMState.RUNNING
    assert result.metadata.guest.management is ManagementState.UNAVAILABLE
    assert "qga_execution" in result.message


def test_windows_status_never_marks_ready_from_ip_alone(
    windows_scenario: Scenario,
    templates: TemplateManager,
    utm: LifecycleUTM,
    tmp_path: Path,
) -> None:
    scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
    name = scenario_vm_name(windows_scenario)
    RuntimeMetadataStore(scenario_path).save(
        RuntimeMetadata(
            scenario_id=windows_scenario.scenario.id,
            profile=windows_scenario.scenario.profile,
            runtime=RuntimeType.VM,
            backend=VMBackend.UTM,
            vm=VMIdentity(
                name=name, managed_id=scenario_managed_id(windows_scenario), state=VMState.RUNNING
            ),
            template=_template_reference(),
            guest=RuntimeGuestState(
                architecture=Architecture.ARM64,
                management=ManagementState.NOT_READY,
                platform=windows_scenario_guest_platform(),
                management_transport=ManagementTransportKind.QEMU_GUEST_AGENT,
                execution_language=ExecutionLanguage.POWERSHELL,
            ),
        )
    )
    utm.vms[name] = VMState.RUNNING
    result = _lifecycle(templates, utm).status(windows_scenario, scenario_path)
    assert result.metadata is not None
    assert result.metadata.guest.ip == "192.168.64.9"
    assert result.metadata.guest.management is ManagementState.NOT_READY


def test_windows_status_downgrades_ready_when_vm_is_not_running(
    windows_scenario: Scenario,
    templates: TemplateManager,
    utm: LifecycleUTM,
    tmp_path: Path,
) -> None:
    """A stopped Windows clone can never retain READY across status refresh."""
    scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
    name = scenario_vm_name(windows_scenario)
    RuntimeMetadataStore(scenario_path).save(
        RuntimeMetadata(
            scenario_id=windows_scenario.scenario.id,
            profile=windows_scenario.scenario.profile,
            runtime=RuntimeType.VM,
            backend=VMBackend.UTM,
            vm=VMIdentity(
                name=name, managed_id=scenario_managed_id(windows_scenario), state=VMState.STOPPED
            ),
            template=_template_reference(),
            guest=RuntimeGuestState(
                architecture=Architecture.ARM64,
                management=ManagementState.READY,
                platform=windows_scenario_guest_platform(),
                management_transport=ManagementTransportKind.QEMU_GUEST_AGENT,
                execution_language=ExecutionLanguage.POWERSHELL,
            ),
        )
    )
    utm.vms[name] = VMState.STOPPED
    result = _lifecycle(templates, utm).status(windows_scenario, scenario_path)
    assert result.metadata is not None
    assert result.metadata.vm.state is VMState.STOPPED
    assert result.metadata.guest.management is ManagementState.NOT_READY


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
    result = _lifecycle(templates, utm).up(
        windows_scenario, scenario_path, _plan(windows_scenario)
    )
    assert result.metadata is not None
    assert result.metadata.guest.management is ManagementState.UNAVAILABLE


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
        )
    )
    utm.vms[name] = VMState.RUNNING
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
    tampered = RuntimeMetadata(
        scenario_id=windows_scenario.scenario.id,
        profile=windows_scenario.scenario.profile,
        runtime=RuntimeType.VM,
        backend=VMBackend.UTM,
        vm=VMIdentity(
            name=name, managed_id=scenario_managed_id(windows_scenario), state=VMState.RUNNING
        ),
        template=_template_reference().model_copy(update={"name": name}),
        guest=RuntimeGuestState(
            architecture=Architecture.ARM64,
            platform=windows_scenario_guest_platform(),
            management_transport=ManagementTransportKind.QEMU_GUEST_AGENT,
            execution_language=ExecutionLanguage.POWERSHELL,
        ),
    )
    RuntimeMetadataStore(scenario_path).save(tampered)
    with pytest.raises(Exception, match="template"):
        _lifecycle(templates, utm).up(windows_scenario, scenario_path, _plan(windows_scenario))
    assert utm.started == []
    assert utm.vms[TEMPLATE_NAME] is VMState.STOPPED


def _template_reference():
    from rangeforge.runtime.models import RuntimeTemplateReference

    return RuntimeTemplateReference(
        image_id="windows-11-arm64",
        template_id=TEMPLATE_NAME,
        name=TEMPLATE_NAME,
        fingerprint="a" * 64,
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
    result = _lifecycle(templates, utm).up(windows_scenario, scenario_path, _plan(windows_scenario))
    assert result.metadata is not None
    assert result.metadata.guest.management is ManagementState.UNAVAILABLE
