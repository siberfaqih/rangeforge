"""Profile-driven, seeded scenario generator."""

from dataclasses import dataclass

from rangeforge import __version__
from rangeforge.generator.randomizer import ScenarioRandomizer
from rangeforge.graph.engine import AttackGraphEngine
from rangeforge.models import (
    AttackGraphSpec,
    DifficultyLevel,
    MachineMetadata,
    Primitive,
    Scenario,
    ScenarioMetadata,
    SelectedPrimitive,
    TrainingProfile,
    ValidationResult,
)
from rangeforge.primitives.registry import PrimitiveRegistry
from rangeforge.validation.scenario import ScenarioValidator


class GenerationError(ValueError):
    """Raised when profile constraints yield no valid candidate."""


@dataclass(frozen=True)
class DifficultyAssessment:
    level: DifficultyLevel
    score: float


def calculate_difficulty(path: tuple[Primitive, ...]) -> DifficultyAssessment:
    """Average primitive reasoning complexity, with three documented score bands.

    Each primitive's enumeration, exploitation, and dependency values (1..3) are
    averaged. The scenario score is the mean of those primitive scores. A score at
    or below 1.50 is easy, at or below 2.35 is medium, and anything higher is hard.
    """
    if not path:
        raise ValueError("A scenario path must contain at least one primitive")
    score = round(sum(item.difficulty.score for item in path) / len(path), 2)
    if score <= 1.5:
        level = DifficultyLevel.EASY
    elif score <= 2.35:
        level = DifficultyLevel.MEDIUM
    else:
        level = DifficultyLevel.HARD
    return DifficultyAssessment(level, score)


class ScenarioGenerator:
    def __init__(self, profile: TrainingProfile, registry: PrimitiveRegistry) -> None:
        self.profile = profile
        self.registry = registry

    def generate(
        self,
        *,
        mode: str,
        platform: str,
        difficulty: DifficultyLevel,
        seed: int,
    ) -> Scenario:
        if platform not in self.profile.allowed_platforms:
            raise GenerationError(
                f"Platform '{platform}' is not allowed by profile '{self.profile.id}'."
            )
        mode_config = self.profile.modes.get(mode)
        if mode_config is None:
            raise GenerationError(f"Mode '{mode}' is not defined by profile '{self.profile.id}'.")

        allowed = self.registry.allowed_for(self.profile, platform)
        engine = AttackGraphEngine(allowed)
        all_candidates = engine.candidate_paths(
            mode_config.start_state,
            mode_config.objective,
            mode_config.minimum_steps,
            mode_config.maximum_steps,
        )
        candidates = tuple(
            path for path in all_candidates if calculate_difficulty(path).level == difficulty
        )
        if not candidates:
            raise GenerationError(
                f"No {difficulty.value} path satisfies profile '{self.profile.id}' "
                f"mode '{mode}'."
            )

        randomizer = ScenarioRandomizer(seed)
        path = randomizer.choice(candidates)
        assessment = calculate_difficulty(path)
        hostname = self._hostname(randomizer)
        machine_ip = f"192.168.56.{randomizer.randint(10, 240)}"
        scenario_id = str(seed)
        draft = Scenario(
            scenario=ScenarioMetadata(
                id=scenario_id,
                seed=seed,
                profile=self.profile.id,
                profile_name=self.profile.name,
                mode=mode,
                platform=platform,
                difficulty=assessment.level,
                difficulty_score=assessment.score,
                generator_version=__version__,
            ),
            machine=MachineMetadata(hostname=hostname, ip=machine_ip),
            attack_graph=AttackGraphSpec(
                start=mode_config.start_state,
                objective=mode_config.objective,
                path=tuple(item.id for item in path),
                selected_primitives=tuple(SelectedPrimitive.from_primitive(item) for item in path),
            ),
            validation=ValidationResult(solvable=False),
        )
        validation = ScenarioValidator(self.profile, self.registry).validate(draft)
        scenario = draft.model_copy(update={"validation": validation})
        if not validation.valid:
            details = "\n".join((*validation.profile_violations, *validation.errors))
            raise GenerationError(f"Generated scenario failed validation:\n{details}")
        return scenario

    @staticmethod
    def _hostname(randomizer: ScenarioRandomizer) -> str:
        roles = ("app", "data", "files", "ops", "web")
        return f"{randomizer.choice(roles)}{randomizer.randint(1, 99):02d}"

