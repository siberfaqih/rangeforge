"""Scenario-scoped runtime identity and metadata persistence."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import yaml
from pydantic import ValidationError

from rangeforge.models import Scenario
from rangeforge.runtime.models import RuntimeMetadata


class RuntimeMetadataError(ValueError):
    """Raised when scenario runtime ownership metadata is invalid."""


def scenario_vm_name(scenario: Scenario) -> str:
    raw = scenario.scenario.id.lower()
    slug = re.sub(r"[^a-z0-9-]+", "-", raw).strip("-")
    if slug and slug == raw and len(slug) <= 48:
        return f"rf-{slug}"
    digest = hashlib.sha256(
        f"{scenario.scenario.profile}:{scenario.scenario.id}".encode()
    ).hexdigest()[:10]
    prefix = slug[:36].rstrip("-") or "scenario"
    return f"rf-{prefix}-{digest}"


def scenario_managed_id(scenario: Scenario) -> str:
    payload = f"rangeforge:{scenario.model_dump_json()}"
    return hashlib.sha256(payload.encode()).hexdigest()


class RuntimeMetadataStore:
    def __init__(self, scenario_path: Path) -> None:
        self.scenario_path = scenario_path.expanduser().resolve()
        self.runtime_dir = self.scenario_path.parent / "runtime"
        self.path = self.runtime_dir / "runtime.yaml"

    @property
    def vagrant_directory(self) -> Path:
        return self.runtime_dir / "vagrant"

    def load(self) -> RuntimeMetadata | None:
        if not self.path.is_file():
            return None
        try:
            return RuntimeMetadata.model_validate(
                yaml.safe_load(self.path.read_text(encoding="utf-8"))
            )
        except (OSError, yaml.YAMLError, ValidationError) as exc:
            raise RuntimeMetadataError(f"Runtime metadata is invalid: {exc}") from exc

    def save(self, metadata: RuntimeMetadata) -> Path:
        if self.runtime_dir.is_symlink():
            raise RuntimeMetadataError("Refusing to write runtime metadata through a symlink.")
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".yaml.partial")
        temporary.write_text(
            yaml.safe_dump(metadata.model_dump(mode="json"), sort_keys=False),
            encoding="utf-8",
        )
        temporary.replace(self.path)
        return self.path

    def remove(self) -> None:
        if self.path.is_file():
            self.path.unlink()
        for name in ("provisioning-plan.json", "instructor.json", "validation.json"):
            artifact = self.runtime_dir / name
            if artifact.is_file():
                artifact.unlink()
        if self.runtime_dir.is_dir() and not any(self.runtime_dir.iterdir()):
            self.runtime_dir.rmdir()
        student_dir = self.scenario_path.parent / "student"
        if student_dir.is_dir() and not student_dir.is_symlink():
            for name in ("README.md", "targets.txt"):
                artifact = student_dir / name
                if artifact.is_file():
                    artifact.unlink()
            if not any(student_dir.iterdir()):
                student_dir.rmdir()

    def validate_ownership(self, scenario: Scenario, metadata: RuntimeMetadata) -> None:
        expected_name = scenario_vm_name(scenario)
        expected_id = scenario_managed_id(scenario)
        if metadata.scenario_id != scenario.scenario.id:
            raise RuntimeMetadataError("Runtime metadata belongs to a different scenario.")
        if metadata.profile != scenario.scenario.profile:
            raise RuntimeMetadataError("Runtime metadata profile does not match the scenario.")
        if metadata.vm.name != expected_name or metadata.vm.managed_id != expected_id:
            raise RuntimeMetadataError(
                "Runtime VM identity does not match the specified RangeForge scenario."
            )
        if metadata.vm.name == metadata.template.name:
            raise RuntimeMetadataError("Scenario VM identity cannot equal the shared template.")
