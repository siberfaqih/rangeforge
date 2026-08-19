from __future__ import annotations

import pytest

from rangeforge.generator.scenario import GenerationError, ScenarioGenerator, calculate_difficulty
from rangeforge.graph.solver import GraphSolver
from rangeforge.models import (
    AccessState,
    DifficultyLevel,
    DifficultyMetadata,
    Primitive,
    StateProvision,
    StateRequirement,
    TrainingProfile,
)
from rangeforge.primitives.registry import PrimitiveRegistry


def test_same_seed_produces_same_scenario(
    profile: TrainingProfile, registry: PrimitiveRegistry
) -> None:
    generator = ScenarioGenerator(profile, registry)
    first = generator.generate(
        mode="standalone", platform="linux", difficulty=DifficultyLevel.MEDIUM, seed=1337
    )
    second = generator.generate(
        mode="standalone", platform="linux", difficulty=DifficultyLevel.MEDIUM, seed=1337
    )
    assert first == second


def test_different_seeds_can_produce_different_scenarios(
    profile: TrainingProfile, registry: PrimitiveRegistry
) -> None:
    generator = ScenarioGenerator(profile, registry)
    scenarios = {
        generator.generate(
            mode="standalone", platform="linux", difficulty=DifficultyLevel.MEDIUM, seed=seed
        ).model_dump_json()
        for seed in range(1, 6)
    }
    assert len(scenarios) > 1


def test_graph_reaches_root(
    profile: TrainingProfile, registry: PrimitiveRegistry
) -> None:
    scenario = ScenarioGenerator(profile, registry).generate(
        mode="standalone", platform="linux", difficulty=DifficultyLevel.HARD, seed=42
    )
    assert scenario.validation.solvable
    assert scenario.attack_graph.selected_primitives[-1].provides is AccessState.ROOT


def test_invalid_transition_is_rejected(registry: PrimitiveRegistry) -> None:
    sudo = registry.require("linux_sudo_misconfiguration")
    result = GraphSolver().solve(AccessState.NO_ACCESS, AccessState.ROOT, (sudo,))
    assert not result.solvable
    assert "Requires: user_shell" in result.errors[0]
    assert "Current state: no_access" in result.errors[0]


def test_profile_platform_restriction(
    profile: TrainingProfile, registry: PrimitiveRegistry
) -> None:
    with pytest.raises(GenerationError, match="not allowed"):
        ScenarioGenerator(profile, registry).generate(
            mode="standalone",
            platform="windows",
            difficulty=DifficultyLevel.MEDIUM,
            seed=1,
        )


def _primitive_with_score(identifier: str, score: int) -> Primitive:
    return Primitive(
        id=identifier,
        name=identifier,
        categories=("enumeration",),
        platforms=("linux",),
        requires=StateRequirement(states=(AccessState.NO_ACCESS,)),
        provides=StateProvision(state=AccessState.ROOT),
        profiles=("oscp",),
        difficulty=DifficultyMetadata(
            enumeration=score, exploitation=score, dependency=score
        ),
        description="Test primitive",
    )


def test_difficulty_calculation() -> None:
    easy = calculate_difficulty((_primitive_with_score("easy_path", 1),))
    assert easy.level is DifficultyLevel.EASY
    assert (
        calculate_difficulty((_primitive_with_score("medium_path", 2),)).level
        is DifficultyLevel.MEDIUM
    )
    hard = calculate_difficulty((_primitive_with_score("hard_path", 3),))
    assert hard.level is DifficultyLevel.HARD
