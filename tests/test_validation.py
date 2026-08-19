from __future__ import annotations

from rangeforge.models import (
    AccessState,
    DifficultyMetadata,
    Primitive,
    Scenario,
    SelectedPrimitive,
    StateProvision,
    StateRequirement,
    TrainingProfile,
)
from rangeforge.primitives.registry import PrimitiveRegistry
from rangeforge.validation.scenario import ScenarioValidator


def test_unknown_primitive_is_rejected(
    scenario: Scenario, profile: TrainingProfile, registry: PrimitiveRegistry
) -> None:
    graph = scenario.attack_graph.model_copy(
        update={"path": ("primitive_that_does_not_exist", *scenario.attack_graph.path[1:])}
    )
    altered = scenario.model_copy(update={"attack_graph": graph})
    result = ScenarioValidator(profile, registry).validate(altered)
    assert not result.solvable
    assert "Unknown primitive: primitive_that_does_not_exist" in result.errors


def test_forbidden_primitive_is_rejected(
    scenario: Scenario, profile: TrainingProfile, registry: PrimitiveRegistry
) -> None:
    forbidden = Primitive(
        id="forbidden_evasion",
        name="Forbidden Evasion",
        categories=("advanced_evasion",),
        platforms=("linux",),
        requires=StateRequirement(states=(AccessState.NO_ACCESS,)),
        provides=StateProvision(state=AccessState.SERVICE_DISCOVERED),
        profiles=("oscp",),
        difficulty=DifficultyMetadata(enumeration=1, exploitation=1, dependency=1),
        description="Test-only forbidden primitive",
    )
    expanded_registry = PrimitiveRegistry((*registry.all(), forbidden))
    selected = SelectedPrimitive.from_primitive(forbidden)
    graph = scenario.attack_graph.model_copy(
        update={
            "path": (forbidden.id, *scenario.attack_graph.path[1:]),
            "selected_primitives": (selected, *scenario.attack_graph.selected_primitives[1:]),
        }
    )
    altered = scenario.model_copy(update={"attack_graph": graph})
    result = ScenarioValidator(profile, expanded_registry).validate(altered)
    assert result.profile_violations
    assert any("forbidden categories" in error for error in result.profile_violations)


def test_graph_length_constraint(
    scenario: Scenario, profile: TrainingProfile, registry: PrimitiveRegistry
) -> None:
    standalone = profile.modes["standalone"].model_copy(
        update={"minimum_steps": len(scenario.attack_graph.path) + 1}
    )
    stricter = profile.model_copy(update={"modes": {"standalone": standalone}})
    result = ScenarioValidator(stricter, registry).validate(scenario)
    assert any("steps; profile requires" in error for error in result.errors)


def test_generated_scenario_validates(scenario: Scenario) -> None:
    assert scenario.validation.valid
    assert scenario.validation.profile_violations == ()
    assert scenario.validation.errors == ()
    assert scenario.validation.vm_deployed is False

