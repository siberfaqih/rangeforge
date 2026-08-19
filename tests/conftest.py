from __future__ import annotations

import pytest

from rangeforge.generator.scenario import ScenarioGenerator
from rangeforge.models import DifficultyLevel, Scenario, TrainingProfile
from rangeforge.primitives.loader import PrimitiveLoader
from rangeforge.primitives.registry import PrimitiveRegistry
from rangeforge.profiles.loader import ProfileLoader


@pytest.fixture
def profile() -> TrainingProfile:
    return ProfileLoader().load("oscp")


@pytest.fixture
def registry() -> PrimitiveRegistry:
    return PrimitiveLoader().load()


@pytest.fixture
def scenario(profile: TrainingProfile, registry: PrimitiveRegistry) -> Scenario:
    return ScenarioGenerator(profile, registry).generate(
        mode="standalone",
        platform="linux",
        difficulty=DifficultyLevel.MEDIUM,
        seed=1337,
    )

