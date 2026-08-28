"""Independent static checks for generated or loaded scenarios.

This module provides two validation paths:

1. ``ScenarioValidator.validate()`` — full profile-gated curriculum, primitive,
   and graph-solvability validation. Used by ``generate``, ``provision``,
   ``validate``, and all commands that modify or inspect training content.

2. ``validate_lifecycle_structure()`` — structural validation for standalone
   runtime lifecycle commands (``runtime plan``, ``build``, ``up``, ``status``,
   ``stop``, ``destroy``). This path validates scenario identity and
   runtime-relevant structure without checking curriculum eligibility, technique
   policy, or graph solvability. It is selected by command scope and never
   enables generation, provisioning, primitive selection, or runtime validity.
"""

from rangeforge.graph.solver import GraphSolver
from rangeforge.models import Primitive, Scenario, TrainingProfile, ValidationResult
from rangeforge.primitives.registry import PrimitiveRegistry


class ScenarioValidator:
    def __init__(self, profile: TrainingProfile, registry: PrimitiveRegistry) -> None:
        self.profile = profile
        self.registry = registry

    def validate(self, scenario: Scenario) -> ValidationResult:
        errors: list[str] = []
        violations: list[str] = []
        metadata = scenario.scenario
        graph = scenario.attack_graph

        if metadata.profile != self.profile.id:
            errors.append(
                f"Scenario profile '{metadata.profile}' does not match loaded profile "
                f"'{self.profile.id}'."
            )
        if metadata.platform not in self.profile.allowed_platforms:
            violations.append(
                f"Platform '{metadata.platform}' is not allowed by profile '{self.profile.id}'."
            )
        mode = self.profile.modes.get(metadata.mode)
        if mode is None:
            errors.append(
                f"Mode '{metadata.mode}' is not defined by profile '{self.profile.id}'."
            )
        else:
            if graph.start != mode.start_state:
                errors.append(
                    f"Attack graph starts at '{graph.start.value}', but profile mode requires "
                    f"'{mode.start_state.value}'."
                )
            if graph.objective != mode.objective:
                errors.append(
                    f"Attack graph objective is '{graph.objective.value}', but profile mode "
                    "requires "
                    f"'{mode.objective.value}'."
                )
            if not mode.minimum_steps <= len(graph.path) <= mode.maximum_steps:
                errors.append(
                    f"Attack graph has {len(graph.path)} steps; profile requires "
                    f"{mode.minimum_steps}..{mode.maximum_steps}."
                )

        if tuple(item.id for item in graph.selected_primitives) != graph.path:
            errors.append("Selected primitive details do not match the declared attack path.")

        resolved: list[Primitive] = []
        allowed_categories = set(self.profile.allowed_categories)
        forbidden_categories = set(self.profile.forbidden_categories)
        allowed_techniques = set(self.profile.allowed_techniques)
        for primitive_id in graph.path:
            primitive = self.registry.get(primitive_id)
            if primitive is None:
                errors.append(f"Unknown primitive: {primitive_id}")
                continue
            resolved.append(primitive)
            if metadata.platform not in primitive.platforms:
                violations.append(
                    f"Primitive '{primitive.id}' does not support platform '{metadata.platform}'."
                )
            if self.profile.id not in primitive.profiles:
                violations.append(
                    f"Primitive '{primitive.id}' does not support profile '{self.profile.id}'."
                )
            if primitive.id not in allowed_techniques:
                violations.append(
                    f"Primitive '{primitive.id}' is not explicitly allowed by profile "
                    f"'{self.profile.id}'."
                )
            primitive_categories = set(primitive.categories)
            disallowed = primitive_categories - allowed_categories
            if disallowed:
                violations.append(
                    f"Primitive '{primitive.id}' uses categories not allowed by profile: "
                    f"{', '.join(sorted(disallowed))}."
                )
            forbidden = primitive_categories.intersection(forbidden_categories)
            if forbidden:
                violations.append(
                    f"Primitive '{primitive.id}' uses forbidden categories: "
                    f"{', '.join(sorted(forbidden))}."
                )

        solvable = False
        if len(resolved) == len(graph.path) and mode is not None:
            solve_result = GraphSolver().solve(graph.start, graph.objective, tuple(resolved))
            solvable = solve_result.solvable
            errors.extend(solve_result.errors)

        return ValidationResult(
            solvable=solvable,
            profile_violations=tuple(dict.fromkeys(violations)),
            errors=tuple(dict.fromkeys(errors)),
            vm_deployed=False,
        )


def validate_lifecycle_structure(scenario: Scenario, profile: TrainingProfile) -> list[str]:
    """Structural validation for standalone runtime lifecycle commands.

    This is a narrower validation path than ``ScenarioValidator.validate()``.
    It checks:
    - The scenario has a valid profile reference.
    - The scenario has a well-formed platform, architecture, and mode.
    - The profile declares the required mode.

    It does not check:
    - Whether the platform is allowed by the profile.
    - Whether the selected primitives are allowed techniques.
    - Whether the attack graph is solvable.
    - Curriculum eligibility or training-policy violations.

    This validation is selected by command scope (runtime plan, build, up,
    status, stop, destroy) and must never enable generation, provisioning,
    primitive selection, or runtime validity for an otherwise-ineligible
    scenario.
    """
    issues: list[str] = []
    if scenario.scenario.profile != profile.id:
        issues.append(
            f"Scenario profile '{scenario.scenario.profile}' does not match loaded profile "
            f"'{profile.id}'."
        )
    if not scenario.scenario.platform:
        issues.append("Scenario has no declared platform.")
    if not scenario.scenario.guest_architecture:
        issues.append("Scenario has no declared guest architecture.")
    mode = profile.modes.get(scenario.scenario.mode)
    if mode is None:
        issues.append(
            f"Mode '{scenario.scenario.mode}' is not defined by profile '{profile.id}'."
        )
    return issues
