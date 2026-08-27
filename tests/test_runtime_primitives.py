from __future__ import annotations

import re
from pathlib import Path

import pytest

from rangeforge.host.models import Architecture, HostInfo, HostOS
from rangeforge.models import (
    AttackGraphSpec,
    Scenario,
    SelectedPrimitive,
    TrainingProfile,
)
from rangeforge.primitives.registry import PrimitiveRegistry
from rangeforge.runtime.backends.base import CommandResult
from rangeforge.runtime.metadata import (
    RuntimeMetadataStore,
    scenario_managed_id,
    scenario_vm_name,
)
from rangeforge.runtime.models import (
    ExecutionLanguage,
    GuestPlan,
    ManagementState,
    ProvisioningState,
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
from rangeforge.runtime_primitives.artifacts import RuntimeArtifactStore
from rangeforge.runtime_primitives.derivation import ScenarioSecretDeriver
from rangeforge.runtime_primitives.engine import ProvisioningError, RuntimePrimitiveEngine
from rangeforge.runtime_primitives.loader import RuntimePrimitiveLoader
from rangeforge.runtime_primitives.models import RuntimeValidationResult
from rangeforge.runtime_primitives.registry import RuntimeImplementationError
from rangeforge.runtime_primitives.transport import (
    UTMGuestTransport,
    VagrantGuestTransport,
)
from rangeforge.serialization.yaml import ScenarioYamlSerializer
from rangeforge.validation.scenario import ScenarioValidator

RUNTIME_PATH = (
    "service_enumeration",
    "simple_web_foothold",
    "credential_discovery_config",
    "linux_sudo_misconfiguration",
)


class SuccessfulGuest:
    language = ExecutionLanguage.SHELL

    def __init__(self) -> None:
        self.scripts: list[str] = []

    def execute(self, script: str, *, timeout: float = 120) -> CommandResult:
        self.scripts.append(script)
        checks = re.findall(r"RF_CHECK ([a-z_]+) [01]", script)
        if checks:
            return CommandResult(
                returncode=0,
                stdout="\n".join(f"RF_CHECK {name} 1" for name in dict.fromkeys(checks)),
            )
        return CommandResult(returncode=0)


class FailingGuest(SuccessfulGuest):
    def __init__(self, fail_at: int) -> None:
        super().__init__()
        self.fail_at = fail_at
        self.provision_calls = 0

    def execute(self, script: str, *, timeout: float = 120) -> CommandResult:
        if "RF_CHECK" not in script:
            self.provision_calls += 1
            if self.provision_calls == self.fail_at:
                return CommandResult(returncode=1, stderr="intentional fixture failure")
        return super().execute(script, timeout=timeout)


def _runtime_scenario(
    scenario: Scenario,
    profile: TrainingProfile,
    registry: PrimitiveRegistry,
) -> Scenario:
    primitives = tuple(registry.require(identifier) for identifier in RUNTIME_PATH)
    graph = AttackGraphSpec(
        start=scenario.attack_graph.start,
        objective=scenario.attack_graph.objective,
        path=RUNTIME_PATH,
        selected_primitives=tuple(SelectedPrimitive.from_primitive(item) for item in primitives),
    )
    draft = scenario.model_copy(update={"attack_graph": graph})
    validation = ScenarioValidator(profile, registry).validate(draft)
    assert validation.valid
    return draft.model_copy(update={"validation": validation})


def _plan(scenario: Scenario, architecture: Architecture = Architecture.ARM64) -> RuntimePlan:
    host = HostInfo(
        os=HostOS.DARWIN,
        architecture=architecture,
        apple_silicon=architecture is Architecture.ARM64,
    )
    return RuntimePlan(
        scenario_id=scenario.scenario.id,
        host=host,
        runtime=RuntimeResolution(
            runtime=RuntimeType.VM,
            backend=VMBackend.UTM,
            guest_architecture=architecture,
            compatible=True,
            reason="fixture",
        ),
        guest=GuestPlan(
            family="linux",
            distribution="ubuntu",
            version="24.04",
            architecture=architecture,
            image_id="ubuntu-24.04-arm64",
        ),
        compatible=True,
        deployable=True,
        next_action="ready",
    )


def _deployed(scenario: Scenario, scenario_path: Path) -> None:
    RuntimeMetadataStore(scenario_path).save(
        RuntimeMetadata(
            scenario_id=scenario.scenario.id,
            profile=scenario.scenario.profile,
            runtime=RuntimeType.VM,
            backend=VMBackend.UTM,
            vm=VMIdentity(
                name=scenario_vm_name(scenario),
                managed_id=scenario_managed_id(scenario),
                state=VMState.RUNNING,
            ),
            template=RuntimeTemplateReference(
                image_id="ubuntu-24.04-arm64",
                template_id="rf-base-ubuntu-24.04-arm64",
                name="rf-base-ubuntu-24.04-arm64",
                fingerprint="f" * 64,
            ),
            guest=RuntimeGuestState(
                architecture=Architecture.ARM64,
                ip="192.168.64.50",
                management=ManagementState.READY,
            ),
        )
    )


def test_runtime_manifest_parsing_and_resolution(
    scenario: Scenario,
    profile: TrainingProfile,
    registry: PrimitiveRegistry,
) -> None:
    runtime_scenario = _runtime_scenario(scenario, profile, registry)
    runtime_registry = RuntimePrimitiveLoader().load(registry)
    resolved = runtime_registry.resolve(
        runtime_scenario,
        runtime=RuntimeType.VM,
        backend=VMBackend.UTM,
        architecture=Architecture.ARM64,
    )
    assert tuple(item.primitive.id for item in resolved) == RUNTIME_PATH
    assert all(item.knowledge.concepts for item in resolved)


def test_unsupported_primitive_and_architecture_are_rejected(
    scenario: Scenario,
    profile: TrainingProfile,
    registry: PrimitiveRegistry,
) -> None:
    engine = RuntimePrimitiveEngine(RuntimePrimitiveLoader().load(registry))
    with pytest.raises(RuntimeImplementationError, match="cannot be provisioned"):
        engine.compile_plan(scenario, _plan(scenario))
    runtime_scenario = _runtime_scenario(scenario, profile, registry)
    with pytest.raises(RuntimeImplementationError, match="architecture"):
        engine.compile_plan(runtime_scenario, _plan(runtime_scenario, Architecture.UNSUPPORTED))


def test_plan_order_and_deterministic_secret_derivation(
    scenario: Scenario,
    profile: TrainingProfile,
    registry: PrimitiveRegistry,
) -> None:
    runtime_scenario = _runtime_scenario(scenario, profile, registry)
    engine = RuntimePrimitiveEngine(RuntimePrimitiveLoader().load(registry))
    first = engine.compile_plan(runtime_scenario, _plan(runtime_scenario))
    second = engine.compile_plan(runtime_scenario, _plan(runtime_scenario))
    assert first == second
    assert tuple(step.primitive for step in first.steps) == RUNTIME_PATH
    assert tuple(step.order for step in first.steps) == (1, 2, 3, 4)

    deriver = ScenarioSecretDeriver()
    config = deriver.derive(runtime_scenario)
    assert config == deriver.derive(runtime_scenario)
    assert config.scenario_user not in {
        "root",
        config.management_account,
        config.service_account,
        config.audit_user,
    }
    changed = runtime_scenario.model_copy(
        update={
            "scenario": runtime_scenario.scenario.model_copy(
                update={"seed": runtime_scenario.scenario.seed + 1, "id": "1338"}
            )
        }
    )
    changed_config = deriver.derive(changed)
    assert changed_config.scenario_credential != config.scenario_credential
    assert changed_config.local_flag != config.local_flag
    assert changed_config.proof_flag != config.proof_flag


def test_rendered_credential_and_sudo_configuration_is_narrow(
    scenario: Scenario,
    profile: TrainingProfile,
    registry: PrimitiveRegistry,
) -> None:
    runtime_scenario = _runtime_scenario(scenario, profile, registry)
    runtime_registry = RuntimePrimitiveLoader().load(registry)
    engine = RuntimePrimitiveEngine(runtime_registry)
    configuration = ScenarioSecretDeriver().derive(runtime_scenario)
    credential = runtime_registry.get("credential_discovery_config")
    sudo = runtime_registry.get("linux_sudo_misconfiguration")
    assert credential is not None and sudo is not None
    credential_script = engine._script(credential, "provision", configuration)
    sudo_script = engine._script(sudo, "provision", configuration)
    assert configuration.scenario_credential in credential_script
    assert "chmod 0640" in credential_script
    assert "NOPASSWD: /usr/bin/find" in sudo_script
    assert "NOPASSWD: ALL" not in sudo_script


def test_provision_validate_redaction_and_reprovision_idempotence(
    scenario: Scenario,
    profile: TrainingProfile,
    registry: PrimitiveRegistry,
    tmp_path: Path,
) -> None:
    runtime_scenario = _runtime_scenario(scenario, profile, registry)
    scenario_path = ScenarioYamlSerializer().dump(runtime_scenario, tmp_path)
    _deployed(runtime_scenario, scenario_path)
    engine = RuntimePrimitiveEngine(RuntimePrimitiveLoader().load(registry))
    guest = SuccessfulGuest()
    first = engine.provision(runtime_scenario, scenario_path, _plan(runtime_scenario), guest)
    second = engine.provision(runtime_scenario, scenario_path, _plan(runtime_scenario), guest)
    assert first.valid and second.valid
    metadata = RuntimeMetadataStore(scenario_path).load()
    assert metadata is not None
    assert metadata.provisioning.state is ProvisioningState.COMPLETE
    assert metadata.provisioning.completed_primitives == RUNTIME_PATH

    artifacts = RuntimeArtifactStore(scenario_path)
    config = artifacts.load_configuration()
    assert config is not None
    student = artifacts.student_text()
    assert "192.168.64.50" in student
    assert config.scenario_credential not in student
    assert config.scenario_user not in student
    assert config.local_flag not in student
    assert config.proof_flag not in student
    assert not any(identifier in student for identifier in RUNTIME_PATH)
    parsed = RuntimeValidationResult.model_validate_json(
        artifacts.validation_path.read_text(encoding="utf-8")
    )
    assert parsed == second
    assert not any(item.triggered for item in parsed.negative_checks)


def test_partial_failure_state_and_clean_template_protection(
    scenario: Scenario,
    profile: TrainingProfile,
    registry: PrimitiveRegistry,
    tmp_path: Path,
) -> None:
    runtime_scenario = _runtime_scenario(scenario, profile, registry)
    scenario_path = ScenarioYamlSerializer().dump(runtime_scenario, tmp_path)
    _deployed(runtime_scenario, scenario_path)
    engine = RuntimePrimitiveEngine(RuntimePrimitiveLoader().load(registry))
    with pytest.raises(ProvisioningError, match="credential_discovery_config"):
        engine.provision(
            runtime_scenario,
            scenario_path,
            _plan(runtime_scenario),
            FailingGuest(fail_at=3),
        )
    metadata = RuntimeMetadataStore(scenario_path).load()
    assert metadata is not None
    assert metadata.provisioning.state is ProvisioningState.FAILED
    assert metadata.provisioning.completed_primitives == RUNTIME_PATH[:2]

    tampered = metadata.model_copy(
        update={"vm": metadata.vm.model_copy(update={"name": metadata.template.name})}
    )
    RuntimeMetadataStore(scenario_path).save(tampered)
    guest = SuccessfulGuest()
    with pytest.raises(Exception, match=r"identity|template"):
        engine.provision(runtime_scenario, scenario_path, _plan(runtime_scenario), guest)
    assert not guest.scripts


def test_utm_and_vagrant_guest_transport_commands_are_scenario_scoped(
    tmp_path: Path,
) -> None:
    commands: list[tuple[str, ...]] = []
    uploaded: dict[str, str] = {}

    def utm_runner(command: tuple[str, ...], script: str, timeout: float) -> CommandResult:
        commands.append(command)
        if command[1:3] == ("file", "push"):
            uploaded[command[-1]] = script
            return CommandResult(returncode=0)
        if command[1:3] == ("file", "pull") and command[-1].endswith(".sh"):
            return CommandResult(returncode=0, stdout=uploaded[command[-1]].strip())
        if command[1:3] == ("file", "pull"):
            return CommandResult(
                returncode=0,
                stdout="RF_CHECK fixture 1\nRF_TRANSPORT_COMPLETE:0",
            )
        return CommandResult(returncode=0)

    utm_result = UTMGuestTransport(
        Path("/usr/local/bin/utmctl"),
        "rf-81",
        runner=utm_runner,
        sleeper=lambda _: None,
    ).execute("echo fixture")
    assert utm_result.returncode == 0
    assert all("rf-base" not in item for command in commands for item in command)
    assert any(command[1:3] == ("file", "push") for command in commands)
    assert any(command[1] == "exec" and "rf-81" in command for command in commands)
    framed_script = next(iter(uploaded.values()))
    assert "(\necho fixture\n)" in framed_script
    assert "RF_TRANSPORT_COMPLETE:%s" in framed_script

    vagrant_commands: list[tuple[str, ...]] = []

    def vagrant_runner(
        command: tuple[str, ...], script: str, timeout: float
    ) -> CommandResult:
        vagrant_commands.append(command)
        return CommandResult(returncode=0, stdout=script)

    directory = tmp_path / "runtime" / "vagrant"
    result = VagrantGuestTransport(
        Path("/usr/local/bin/vagrant"),
        directory,
        runner=vagrant_runner,
    ).execute("echo fixture")
    assert result.returncode == 0
    assert vagrant_commands == [
        (
            "/usr/local/bin/vagrant",
            "--chdir",
            str(directory),
            "ssh",
            "-c",
            "sudo -n /bin/bash -s",
        )
    ]


def test_utm_guest_transport_preserves_guest_exit_status() -> None:
    uploaded: dict[str, str] = {}

    def runner(command: tuple[str, ...], script: str, timeout: float) -> CommandResult:
        if command[1:3] == ("file", "push"):
            uploaded[command[-1]] = script
            return CommandResult(returncode=0)
        if command[1:3] == ("file", "pull") and command[-1].endswith(".sh"):
            return CommandResult(returncode=0, stdout=uploaded[command[-1]].strip())
        if command[1:3] == ("file", "pull"):
            return CommandResult(
                returncode=0,
                stdout="provisioner failed\nRF_TRANSPORT_COMPLETE:23",
            )
        return CommandResult(returncode=0)

    result = UTMGuestTransport(
        Path("/usr/local/bin/utmctl"),
        "rf-81",
        runner=runner,
        sleeper=lambda _: None,
    ).execute("exit 23")

    assert result.returncode == 23
    assert "provisioner failed" in result.stdout


class UndeclaredTransport:
    """A guest transport that does not declare its execution language."""

    def execute(self, script: str, *, timeout: float = 120) -> CommandResult:
        return CommandResult(returncode=0)

    def push(self, source: Path, destination: str, *, timeout: float = 300) -> CommandResult:
        return CommandResult(returncode=0)


def test_provision_rejects_undeclared_transport_language(
    scenario: Scenario,
    profile: TrainingProfile,
    registry: PrimitiveRegistry,
    tmp_path: Path,
) -> None:
    """A transport that does not declare its language is rejected (default-deny)."""
    runtime_scenario = _runtime_scenario(scenario, profile, registry)
    scenario_path = ScenarioYamlSerializer().dump(runtime_scenario, tmp_path)
    _deployed(runtime_scenario, scenario_path)
    engine = RuntimePrimitiveEngine(RuntimePrimitiveLoader().load(registry))
    with pytest.raises(ProvisioningError, match="no declared execution language"):
        engine.provision(
            runtime_scenario,
            scenario_path,
            _plan(runtime_scenario),
            UndeclaredTransport(),  # type: ignore[arg-type]
        )


def test_provision_rejects_non_shell_transport_language(
    scenario: Scenario,
    profile: TrainingProfile,
    registry: PrimitiveRegistry,
    tmp_path: Path,
) -> None:
    """A PowerShell transport must never execute shell primitive manifests."""
    runtime_scenario = _runtime_scenario(scenario, profile, registry)
    scenario_path = ScenarioYamlSerializer().dump(runtime_scenario, tmp_path)
    _deployed(runtime_scenario, scenario_path)
    engine = RuntimePrimitiveEngine(RuntimePrimitiveLoader().load(registry))

    class PowerShellTransport(UndeclaredTransport):
        language = ExecutionLanguage.POWERSHELL

    with pytest.raises(ProvisioningError, match="Linux shell management transport"):
        engine.provision(
            runtime_scenario,
            scenario_path,
            _plan(runtime_scenario),
            PowerShellTransport(),  # type: ignore[arg-type]
        )
