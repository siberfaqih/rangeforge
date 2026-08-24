"""Scenario-local runtime, instructor, and deliberately redacted student artifacts."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import TypeVar

import yaml
from pydantic import BaseModel, ValidationError

from rangeforge.models import Scenario
from rangeforge.runtime_primitives.models import (
    ProvisioningPlan,
    RuntimeValidationResult,
    ScenarioRuntimeConfiguration,
    ScenarioRuntimeLock,
)


class RuntimeArtifactError(ValueError):
    """Raised when Phase 3 artifacts cannot be safely read or written."""


ArtifactModel = TypeVar("ArtifactModel", bound=BaseModel)


class RuntimeArtifactStore:
    def __init__(self, scenario_path: Path) -> None:
        self.scenario_path = scenario_path.expanduser().resolve()
        self.scenario_dir = self.scenario_path.parent
        self.runtime_dir = self.scenario_dir / "runtime"
        self.student_dir = self.scenario_dir / "student"
        self.plan_path = self.runtime_dir / "provisioning-plan.json"
        self.instructor_path = self.runtime_dir / "instructor.json"
        self.validation_path = self.runtime_dir / "validation.json"
        self.lock_path = self.runtime_dir / "lock.yaml"

    def save_plan(self, plan: ProvisioningPlan) -> Path:
        self._write_json(self.plan_path, plan.model_dump(mode="json"), mode=0o600)
        return self.plan_path

    def load_plan(self) -> ProvisioningPlan | None:
        return self._load(self.plan_path, ProvisioningPlan)

    def save_configuration(self, configuration: ScenarioRuntimeConfiguration) -> Path:
        self._write_json(
            self.instructor_path,
            configuration.model_dump(mode="json"),
            mode=0o600,
        )
        return self.instructor_path

    def load_configuration(self) -> ScenarioRuntimeConfiguration | None:
        return self._load(self.instructor_path, ScenarioRuntimeConfiguration)

    def save_validation(self, result: RuntimeValidationResult) -> Path:
        self._write_json(self.validation_path, result.model_dump(mode="json"), mode=0o600)
        return self.validation_path

    def load_validation(self) -> RuntimeValidationResult | None:
        return self._load(self.validation_path, RuntimeValidationResult)

    def save_lock(self, lock: ScenarioRuntimeLock) -> Path:
        if self.runtime_dir.is_symlink():
            raise RuntimeArtifactError("Refusing to write runtime lock through a symlink.")
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        temporary = self.lock_path.with_suffix(".yaml.partial")
        temporary.write_text(
            yaml.safe_dump(lock.model_dump(mode="json"), sort_keys=False),
            encoding="utf-8",
        )
        os.chmod(temporary, 0o600)
        temporary.replace(self.lock_path)
        return self.lock_path

    def load_lock(self) -> ScenarioRuntimeLock | None:
        if not self.lock_path.is_file():
            return None
        try:
            return ScenarioRuntimeLock.model_validate(
                yaml.safe_load(self.lock_path.read_text(encoding="utf-8"))
            )
        except (OSError, yaml.YAMLError, ValidationError) as exc:
            raise RuntimeArtifactError(f"Runtime lock is invalid: {exc}") from exc

    def write_student_artifacts(self, scenario: Scenario, target_ip: str) -> tuple[Path, Path]:
        if self.student_dir.is_symlink():
            raise RuntimeArtifactError("Refusing to write student artifacts through a symlink.")
        self.student_dir.mkdir(parents=True, exist_ok=True)
        readme = self.student_dir / "README.md"
        targets = self.student_dir / "targets.txt"
        readme.write_text(
            "# RangeForge Training Scenario\n\n"
            f"Scenario: {scenario.scenario.id}\n\n"
            f"Target: {target_ip}\n\n"
            "Objective: obtain `local.txt` and `proof.txt`.\n\n"
            "This intentionally vulnerable target is for authorized, isolated "
            "local training only.\n",
            encoding="utf-8",
        )
        targets.write_text(f"{target_ip}\n", encoding="utf-8")
        os.chmod(readme, 0o644)
        os.chmod(targets, 0o644)
        return readme, targets

    def student_text(self) -> str:
        if not self.student_dir.is_dir():
            return ""
        return "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted(self.student_dir.iterdir())
            if path.is_file()
        )

    def remove_runtime_artifacts(self) -> None:
        for path in (self.plan_path, self.instructor_path, self.validation_path):
            if path.is_file():
                path.unlink()

    def _write_json(self, path: Path, payload: object, *, mode: int) -> None:
        if self.runtime_dir.is_symlink():
            raise RuntimeArtifactError("Refusing to write runtime artifacts through a symlink.")
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(f"{path.suffix}.partial")
        temporary.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.chmod(temporary, mode)
        temporary.replace(path)

    @staticmethod
    def _load(path: Path, model: type[ArtifactModel]) -> ArtifactModel | None:
        if not path.is_file():
            return None
        try:
            return model.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValidationError) as exc:
            raise RuntimeArtifactError(f"Runtime artifact '{path.name}' is invalid: {exc}") from exc
