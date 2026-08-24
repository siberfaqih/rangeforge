"""Strongly typed domain models used by the RangeForge core."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    """Base model that rejects misspelled or unsupported fields."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class AccessState(StrEnum):
    NO_ACCESS = "no_access"
    SERVICE_DISCOVERED = "service_discovered"
    LOW_PRIV_SHELL = "low_priv_shell"
    USER_SHELL = "user_shell"
    ROOT = "root"


class DifficultyLevel(StrEnum):
    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"


class DifficultyMetadata(StrictModel):
    enumeration: int = Field(ge=1, le=3)
    exploitation: int = Field(ge=1, le=3)
    dependency: int = Field(default=1, ge=1, le=3)

    @property
    def score(self) -> float:
        return (self.enumeration + self.exploitation + self.dependency) / 3


class StateRequirement(StrictModel):
    states: tuple[AccessState, ...] = Field(min_length=1)


class StateProvision(StrictModel):
    state: AccessState


class Primitive(StrictModel):
    id: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    name: str
    categories: tuple[str, ...] = Field(min_length=1)
    platforms: tuple[str, ...] = Field(min_length=1)
    requires: StateRequirement
    provides: StateProvision
    profiles: tuple[str, ...] = Field(min_length=1)
    difficulty: DifficultyMetadata
    description: str
    runtime_support: tuple[Literal["docker", "vm"], ...] = ("docker", "vm")
    architectures: tuple[Literal["arm64", "amd64"], ...] = ("arm64", "amd64")


class ProfileMode(StrictModel):
    start_state: AccessState
    objective: AccessState
    minimum_steps: int = Field(ge=1)
    maximum_steps: int = Field(ge=1)

    @model_validator(mode="after")
    def length_range_is_valid(self) -> ProfileMode:
        if self.minimum_steps > self.maximum_steps:
            raise ValueError("minimum_steps cannot exceed maximum_steps")
        return self


class GuestRequirement(StrictModel):
    family: str
    distribution: str
    version: str
    default_runtime: Literal["docker", "vm"] = "vm"


class TrainingProfile(StrictModel):
    id: str
    name: str
    allowed_platforms: tuple[str, ...] = Field(min_length=1)
    allowed_categories: tuple[str, ...] = Field(min_length=1)
    forbidden_categories: tuple[str, ...] = ()
    allowed_techniques: tuple[str, ...] = Field(min_length=1)
    modes: dict[str, ProfileMode]
    runtime_defaults: dict[str, GuestRequirement] = Field(default_factory=dict)


class ScenarioMetadata(StrictModel):
    id: str
    seed: int
    profile: str
    profile_name: str
    mode: str
    platform: str
    difficulty: DifficultyLevel
    difficulty_score: float
    generator_version: str
    target_runtime: Literal["docker", "vm"] = "vm"
    guest_architecture: Literal["arm64", "amd64"] = "arm64"
    cve_registry_version: int = Field(default=1, ge=1)


class MachineMetadata(StrictModel):
    hostname: str
    ip: str


class SelectedPrimitive(StrictModel):
    id: str
    name: str
    categories: tuple[str, ...]
    requires: tuple[AccessState, ...]
    provides: AccessState
    difficulty: DifficultyMetadata

    @classmethod
    def from_primitive(cls, primitive: Primitive) -> SelectedPrimitive:
        return cls(
            id=primitive.id,
            name=primitive.name,
            categories=primitive.categories,
            requires=primitive.requires.states,
            provides=primitive.provides.state,
            difficulty=primitive.difficulty,
        )


class AttackGraphSpec(StrictModel):
    start: AccessState
    objective: AccessState
    path: tuple[str, ...]
    selected_primitives: tuple[SelectedPrimitive, ...]


class ValidationResult(StrictModel):
    solvable: bool
    profile_violations: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    vm_deployed: bool = False

    @property
    def valid(self) -> bool:
        return self.solvable and not self.profile_violations and not self.errors


class Scenario(StrictModel):
    scenario: ScenarioMetadata
    machine: MachineMetadata
    attack_graph: AttackGraphSpec
    validation: ValidationResult
