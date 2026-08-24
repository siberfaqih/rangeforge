"""Compile, apply, and validate scenario-ordered runtime primitives."""

from __future__ import annotations

import hashlib
import json
import shlex
from pathlib import Path

from rangeforge.artifacts.manager import ArtifactManager
from rangeforge.host.models import Architecture
from rangeforge.models import Scenario
from rangeforge.runtime.metadata import RuntimeMetadataStore, scenario_vm_name
from rangeforge.runtime.models import (
    ManagementState,
    ProvisioningState,
    ProvisioningStatus,
    RuntimeMetadata,
    RuntimePlan,
    RuntimeValidationState,
    RuntimeValidationStatus,
    VMState,
)
from rangeforge.runtime_primitives.artifacts import RuntimeArtifactStore
from rangeforge.runtime_primitives.derivation import ScenarioSecretDeriver
from rangeforge.runtime_primitives.models import (
    CVERuntimeBinding,
    FlagValidation,
    LockedBaseImage,
    LockedPrimitive,
    NegativeValidation,
    PrimitiveValidation,
    ProvisioningPlan,
    ProvisioningStep,
    RuntimeArtifactReference,
    RuntimeCheck,
    RuntimePrimitive,
    RuntimeValidationResult,
    ScenarioRuntimeConfiguration,
    ScenarioRuntimeLock,
)
from rangeforge.runtime_primitives.registry import RuntimePrimitiveRegistry
from rangeforge.runtime_primitives.transport import GuestTransport


class ProvisioningError(RuntimeError):
    """Raised when a scenario-owned provisioning step cannot converge."""


class RuntimeValidationError(RuntimeError):
    """Raised when runtime validation cannot be executed safely."""


_EXPECTED_CHECKS: dict[str, tuple[str, ...]] = {
    "service_enumeration": (
        "service_metadata",
        "service_running",
        "port_listening",
    ),
    "simple_web_foothold": (
        "vulnerable_condition",
        "service_identity",
        "service_nonroot",
        "local_exists",
        "local_owner",
        "local_mode",
        "local_readable_service",
    ),
    "credential_discovery_config": (
        "artifact_exists",
        "artifact_mode",
        "service_can_read",
        "audit_cannot_read",
        "credential_authenticates",
        "scenario_user_nonroot",
    ),
    "linux_sudo_misconfiguration": (
        "target_exists",
        "sudo_rule",
        "root_reachable",
        "service_no_rule",
        "audit_no_rule",
        "not_sudo_all",
        "proof_exists",
        "proof_owner",
        "proof_mode",
        "scenario_cannot_read_proof",
        "service_cannot_read_proof",
    ),
}


class RuntimePrimitiveEngine:
    def __init__(
        self,
        registry: RuntimePrimitiveRegistry,
        deriver: ScenarioSecretDeriver | None = None,
        artifact_manager: ArtifactManager | None = None,
    ) -> None:
        self.registry = registry
        self.deriver = deriver or ScenarioSecretDeriver()
        self.artifact_manager = artifact_manager

    def compile_plan(self, scenario: Scenario, runtime_plan: RuntimePlan) -> ProvisioningPlan:
        if runtime_plan.runtime.backend is None or runtime_plan.guest is None:
            raise ProvisioningError(
                "Runtime primitive provisioning requires a resolved VM backend."
            )
        resolved = self.registry.resolve(
            scenario,
            runtime=runtime_plan.runtime.runtime,
            backend=runtime_plan.runtime.backend,
            architecture=runtime_plan.guest.architecture,
        )
        configuration = self.deriver.derive(scenario)
        artifacts = self._required_artifacts(resolved, runtime_plan.guest.architecture)
        configuration_fingerprint = self._fingerprint(configuration.model_dump(mode="json"))
        steps = tuple(
            ProvisioningStep(
                primitive=item.primitive.id,
                order=index,
                provisioner=item.manifest.provisioner,
                validator=item.manifest.validator,
            )
            for index, item in enumerate(resolved, start=1)
        )
        content = {
            "scenario_id": scenario.scenario.id,
            "runtime": runtime_plan.runtime.runtime.value,
            "backend": runtime_plan.runtime.backend.value,
            "architecture": runtime_plan.guest.architecture.value,
            "machine_name": scenario_vm_name(scenario),
            "steps": [step.model_dump(mode="json") for step in steps],
            "flags": ["local", "proof"],
            "artifacts": [item.model_dump(mode="json") for item in artifacts],
            "cve_registry_version": scenario.scenario.cve_registry_version,
            "configuration_fingerprint": configuration_fingerprint,
        }
        return ProvisioningPlan(
            scenario_id=scenario.scenario.id,
            runtime=runtime_plan.runtime.runtime,
            backend=runtime_plan.runtime.backend,
            architecture=runtime_plan.guest.architecture,
            machine_name=scenario_vm_name(scenario),
            steps=steps,
            flags=("local", "proof"),
            artifacts=artifacts,
            cve_registry_version=scenario.scenario.cve_registry_version,
            configuration_fingerprint=configuration_fingerprint,
            plan_fingerprint=self._fingerprint(content),
        )

    def provision(
        self,
        scenario: Scenario,
        scenario_path: Path,
        runtime_plan: RuntimePlan,
        transport: GuestTransport,
    ) -> RuntimeValidationResult:
        plan = self.compile_plan(scenario, runtime_plan)
        configuration = self.deriver.derive(scenario)
        metadata_store = RuntimeMetadataStore(scenario_path)
        metadata = self._require_owned_running_target(scenario, metadata_store, plan)
        resolved = self.registry.resolve(
            scenario,
            runtime=plan.runtime,
            backend=plan.backend,
            architecture=plan.architecture,
        )
        artifacts = RuntimeArtifactStore(scenario_path)
        artifacts.save_plan(plan)
        artifacts.save_configuration(configuration)
        artifacts.save_lock(self._lock(scenario, metadata, plan, resolved))
        self._stage_artifacts(plan, transport)
        current = metadata.model_copy(
            update={
                "provisioning": ProvisioningStatus(
                    state=ProvisioningState.PROVISIONING,
                    plan_fingerprint=plan.plan_fingerprint,
                ),
                "validation": RuntimeValidationStatus(state=RuntimeValidationState.NOT_RUN),
            }
        )
        metadata_store.save(current)
        completed: list[str] = []
        primary_cve = self._primary_cve(resolved)
        for runtime_primitive in resolved:
            primitive_id = runtime_primitive.primitive.id
            current = current.model_copy(
                update={
                    "provisioning": current.provisioning.model_copy(
                        update={"active_primitive": primitive_id}
                    )
                }
            )
            metadata_store.save(current)
            script = self._script(
                runtime_primitive,
                "provision",
                configuration,
                architecture=plan.architecture,
                primary_cve=primary_cve,
            )
            result = transport.execute(script)
            if result.returncode != 0:
                error = result.stderr or result.stdout or "guest provisioner returned failure"
                failed = current.model_copy(
                    update={
                        "provisioning": ProvisioningStatus(
                            state=ProvisioningState.FAILED,
                            completed_primitives=tuple(completed),
                            active_primitive=primitive_id,
                            plan_fingerprint=plan.plan_fingerprint,
                            error=error,
                        ),
                        "validation": RuntimeValidationStatus(state=RuntimeValidationState.INVALID),
                    }
                )
                metadata_store.save(failed)
                raise ProvisioningError(
                    f"Provisioning failed at primitive '{primitive_id}'. Completed: "
                    f"{', '.join(completed) if completed else 'none'}. {error}"
                )
            completed.append(primitive_id)
            current = current.model_copy(
                update={
                    "provisioning": ProvisioningStatus(
                        state=ProvisioningState.PROVISIONING,
                        completed_primitives=tuple(completed),
                        plan_fingerprint=plan.plan_fingerprint,
                    )
                }
            )
            metadata_store.save(current)
        complete = current.model_copy(
            update={
                "provisioning": ProvisioningStatus(
                    state=ProvisioningState.COMPLETE,
                    completed_primitives=tuple(completed),
                    plan_fingerprint=plan.plan_fingerprint,
                )
            }
        )
        metadata_store.save(complete)
        assert complete.guest.ip is not None
        artifacts.write_student_artifacts(scenario, complete.guest.ip)
        return self.validate(scenario, scenario_path, transport)

    def validate(
        self,
        scenario: Scenario,
        scenario_path: Path,
        transport: GuestTransport,
    ) -> RuntimeValidationResult:
        metadata_store = RuntimeMetadataStore(scenario_path)
        metadata = metadata_store.load()
        if metadata is None:
            raise RuntimeValidationError("Scenario VM is not built.")
        metadata_store.validate_ownership(scenario, metadata)
        if metadata.provisioning.state is not ProvisioningState.COMPLETE:
            raise RuntimeValidationError(
                "Scenario provisioning is not COMPLETE; runtime cannot be valid."
            )
        artifacts = RuntimeArtifactStore(scenario_path)
        plan = artifacts.load_plan()
        configuration = artifacts.load_configuration()
        if plan is None or configuration is None:
            raise RuntimeValidationError(
                "Provisioning plan or instructor configuration is missing."
            )
        self._require_owned_running_target(scenario, metadata_store, plan)
        resolved = self.registry.resolve(
            scenario,
            runtime=plan.runtime,
            backend=plan.backend,
            architecture=plan.architecture,
        )
        primary_cve = self._primary_cve(resolved)
        primitive_results: list[PrimitiveValidation] = []
        all_checks: dict[str, bool] = {}
        validator_script = "\n".join(
            "(\n"
            + self._script(
                item,
                "validate",
                configuration,
                architecture=plan.architecture,
                primary_cve=primary_cve,
            )
            + "\n)"
            for item in resolved
        )
        execution = transport.execute(validator_script)
        parsed = self._parse_checks(execution.stdout)
        for runtime_primitive in resolved:
            expected = (
                runtime_primitive.cve.expected_checks
                if runtime_primitive.cve is not None
                else _EXPECTED_CHECKS.get(runtime_primitive.primitive.id, ())
            )
            checks = tuple(
                RuntimeCheck(
                    name=name,
                    passed=parsed.get(name, False),
                    detail=("verified" if parsed.get(name, False) else "missing or failed"),
                )
                for name in expected
            )
            if execution.returncode != 0:
                checks += (
                    RuntimeCheck(
                        name="validator_execution",
                        passed=False,
                        detail=execution.stderr or "validator returned failure",
                    ),
                )
            all_checks.update({check.name: check.passed for check in checks})
            primitive_results.append(
                PrimitiveValidation(
                    primitive=runtime_primitive.primitive.id,
                    valid=bool(checks) and all(check.passed for check in checks),
                    checks=checks,
                )
            )
        flags = self._flag_results(all_checks)
        negative = self._negative_results(all_checks, artifacts, configuration, scenario)
        valid = (
            all(item.valid for item in primitive_results)
            and all(item.valid for item in flags)
            and not any(item.triggered for item in negative)
        )
        validation = RuntimeValidationResult(
            scenario_id=scenario.scenario.id,
            backend=plan.backend,
            primitives=tuple(primitive_results),
            flags=flags,
            negative_checks=negative,
            status="valid" if valid else "invalid",
        )
        artifacts.save_validation(validation)
        updated = metadata.model_copy(
            update={
                "validation": RuntimeValidationStatus(
                    state=(
                        RuntimeValidationState.VALID if valid else RuntimeValidationState.INVALID
                    ),
                    result_path=str(
                        artifacts.validation_path.relative_to(
                            scenario_path.expanduser().resolve().parent
                        )
                    ),
                )
            }
        )
        metadata_store.save(updated)
        return validation

    def _require_owned_running_target(
        self,
        scenario: Scenario,
        store: RuntimeMetadataStore,
        plan: ProvisioningPlan,
    ) -> RuntimeMetadata:
        metadata = store.load()
        if metadata is None:
            raise ProvisioningError("Scenario VM is not built.")
        store.validate_ownership(scenario, metadata)
        if metadata.vm.name != plan.machine_name or metadata.vm.name == metadata.template.name:
            raise ProvisioningError(
                "Provisioning target is not the owned scenario clone; "
                "shared templates are protected."
            )
        if (
            metadata.backend is not plan.backend
            or metadata.guest.architecture is not plan.architecture
        ):
            raise ProvisioningError("Provisioning plan does not match runtime ownership metadata.")
        if metadata.vm.state is not VMState.RUNNING:
            raise ProvisioningError("Scenario VM must be RUNNING before provisioning.")
        if metadata.guest.management is not ManagementState.READY or not metadata.guest.ip:
            raise ProvisioningError("Trusted guest management is not READY.")
        return metadata

    def _script(
        self,
        runtime_primitive: RuntimePrimitive,
        phase: str,
        configuration: ScenarioRuntimeConfiguration,
        *,
        architecture: Architecture | None = None,
        primary_cve: CVERuntimeBinding | None = None,
    ) -> str:
        implementation = (
            runtime_primitive.manifest.provisioner
            if phase == "provision"
            else runtime_primitive.manifest.validator
        )
        path = self.registry.script_path(runtime_primitive, implementation)
        raw = path.read_text(encoding="utf-8")
        values = {
            "SCENARIO_ID": configuration.scenario_id,
            "SERVICE_USER": configuration.service_account,
            "SCENARIO_USER": configuration.scenario_user,
            "AUDIT_USER": configuration.audit_user,
            "MANAGEMENT_USER": configuration.management_account,
            "CREDENTIAL": configuration.scenario_credential,
            "LOCAL_FLAG": configuration.local_flag,
            "PROOF_FLAG": configuration.proof_flag,
            "PORT": str(configuration.service_port),
            "PRIMARY_SERVICE_NAME": (
                primary_cve.service_name if primary_cve else "rf-web-foothold"
            ),
            "PRIMARY_SERVICE_PORT": str(
                primary_cve.service_port if primary_cve else configuration.service_port
            ),
        }
        if runtime_primitive.cve is not None:
            selected_architecture = architecture or Architecture.ARM64
            for artifact in runtime_primitive.cve.artifacts_for(selected_architecture):
                token = self._artifact_token(artifact.id)
                values[token] = f"/var/lib/rangeforge/artifacts/{artifact.filename}"
                if artifact.id.startswith("temurin-jre-"):
                    values["ARCH_ARTIFACT_TEMURIN_JRE"] = values[token]
        for key, value in values.items():
            raw = raw.replace(f"@@{key}@@", shlex.quote(value))
        if "@@" in raw:
            raise ProvisioningError(f"Unresolved template token in {path.name}.")
        return raw

    def _required_artifacts(
        self,
        resolved: tuple[RuntimePrimitive, ...],
        architecture: Architecture,
    ) -> tuple[RuntimeArtifactReference, ...]:
        required = {
            artifact.id: artifact
            for item in resolved
            if item.cve is not None
            for artifact in item.cve.artifacts_for(architecture)
        }
        if not required:
            return ()
        if self.artifact_manager is None:
            raise ProvisioningError("CVE artifact manager is unavailable.")
        for artifact_id, reference in required.items():
            verification = self.artifact_manager.verify(artifact_id)
            if not verification.valid:
                raise ProvisioningError(
                    "Scenario cannot be provisioned. "
                    f"Artifact '{artifact_id}' is {verification.status.value}. "
                    f"Run: rangeforge artifacts pull {artifact_id}"
                )
            if verification.actual_sha256 != reference.sha256.lower():
                raise ProvisioningError(f"Artifact lock mismatch for '{artifact_id}'.")
        return tuple(required[key] for key in sorted(required))

    def _stage_artifacts(self, plan: ProvisioningPlan, transport: GuestTransport) -> None:
        if not plan.artifacts:
            return
        if self.artifact_manager is None:
            raise ProvisioningError("CVE artifact manager is unavailable.")
        for artifact in plan.artifacts:
            source = self.artifact_manager.verify(artifact.id).path
            destination = f"/var/lib/rangeforge/artifacts/{artifact.filename}"
            check = transport.execute(
                "if printf '%s  %s\\n' "
                f"{shlex.quote(artifact.sha256.lower())} {shlex.quote(destination)} "
                "| sha256sum -c - >/dev/null 2>&1; then "
                "printf 'RF_ARTIFACT_READY\\n'; fi"
            )
            if check.returncode == 0 and "RF_ARTIFACT_READY" in check.stdout:
                continue
            result = transport.push(source, destination)
            if result.returncode != 0:
                raise ProvisioningError(
                    f"Could not stage artifact '{artifact.id}' in the owned scenario VM: "
                    f"{result.stderr or result.stdout}"
                )

    @staticmethod
    def _primary_cve(resolved: tuple[RuntimePrimitive, ...]) -> CVERuntimeBinding | None:
        return next((item.cve for item in resolved if item.cve is not None), None)

    @staticmethod
    def _artifact_token(artifact_id: str) -> str:
        return "ARTIFACT_" + "".join(
            character.upper() if character.isalnum() else "_"
            for character in artifact_id
        )

    @staticmethod
    def _lock(
        scenario: Scenario,
        metadata: RuntimeMetadata,
        plan: ProvisioningPlan,
        resolved: tuple[RuntimePrimitive, ...],
    ) -> ScenarioRuntimeLock:
        return ScenarioRuntimeLock(
            scenario_id=scenario.scenario.id,
            seed=scenario.scenario.seed,
            profile=scenario.scenario.profile,
            runtime=plan.runtime,
            backend=plan.backend,
            architecture=plan.architecture,
            cve_registry_version=plan.cve_registry_version,
            base_image=LockedBaseImage(
                id=metadata.template.image_id,
                fingerprint=metadata.template.fingerprint,
            ),
            primitives=tuple(
                LockedPrimitive(
                    id=item.primitive.id,
                    version=item.cve.definition_version if item.cve else 1,
                    cve_id=item.cve.cve_id if item.cve else None,
                    service_version=item.cve.expected_version if item.cve else None,
                    artifacts=(
                        item.cve.artifacts_for(plan.architecture) if item.cve else ()
                    ),
                )
                for item in resolved
            ),
        )

    @staticmethod
    def _parse_checks(output: str) -> dict[str, bool]:
        checks: dict[str, bool] = {}
        for line in output.splitlines():
            parts = line.split()
            if len(parts) == 3 and parts[0] == "RF_CHECK":
                checks[parts[1]] = parts[2] == "1"
        return checks

    @staticmethod
    def _flag_results(checks: dict[str, bool]) -> tuple[FlagValidation, ...]:
        local_names = ("local_exists", "local_owner", "local_mode", "local_readable_service")
        proof_names = (
            "proof_exists",
            "proof_owner",
            "proof_mode",
            "scenario_cannot_read_proof",
            "service_cannot_read_proof",
        )
        return (
            FlagValidation(
                flag="local.txt",
                valid=all(checks.get(name, False) for name in local_names),
                checks=tuple(
                    RuntimeCheck(name=name, passed=checks.get(name, False)) for name in local_names
                ),
            ),
            FlagValidation(
                flag="proof.txt",
                valid=all(checks.get(name, False) for name in proof_names),
                checks=tuple(
                    RuntimeCheck(name=name, passed=checks.get(name, False)) for name in proof_names
                ),
            ),
        )

    @staticmethod
    def _negative_results(
        checks: dict[str, bool],
        artifacts: RuntimeArtifactStore,
        configuration: ScenarioRuntimeConfiguration,
        scenario: Scenario,
    ) -> tuple[NegativeValidation, ...]:
        student = artifacts.student_text()
        forbidden = (
            configuration.scenario_credential,
            configuration.local_flag,
            configuration.proof_flag,
            configuration.scenario_user,
            *scenario.attack_graph.path,
        )
        student_leaks_solution = any(item and item in student for item in forbidden)
        return (
            NegativeValidation(
                name="service_user_is_root",
                triggered=not checks.get("service_nonroot", False),
            ),
            NegativeValidation(
                name="scenario_user_is_root",
                triggered=not checks.get("scenario_user_nonroot", False),
            ),
            NegativeValidation(
                name="proof_world_readable",
                triggered=not checks.get("proof_mode", False),
            ),
            NegativeValidation(
                name="management_secret_exposed",
                triggered=student_leaks_solution,
                detail="student artifact solution scan",
            ),
            NegativeValidation(
                name="unexpected_sudo_access",
                triggered=not all(
                    checks.get(name, False)
                    for name in ("service_no_rule", "audit_no_rule", "not_sudo_all")
                ),
            ),
        )

    @staticmethod
    def _fingerprint(payload: object) -> str:
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()
