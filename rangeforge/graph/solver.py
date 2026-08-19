"""Validate declared primitive paths and objective reachability."""

from dataclasses import dataclass

from rangeforge.models import AccessState, Primitive


@dataclass(frozen=True)
class SolveResult:
    solvable: bool
    final_state: AccessState
    errors: tuple[str, ...] = ()


class GraphSolver:
    def solve(
        self,
        start: AccessState,
        objective: AccessState,
        path: tuple[Primitive, ...],
    ) -> SolveResult:
        current = start
        errors: list[str] = []
        for primitive in path:
            if current not in primitive.requires.states:
                required = ", ".join(state.value for state in primitive.requires.states)
                errors.append(
                    "Invalid state transition.\n"
                    f"Primitive: {primitive.id}\n"
                    f"Requires: {required}\n"
                    f"Current state: {current.value}"
                )
                return SolveResult(False, current, tuple(errors))
            current = primitive.provides.state
        if current != objective:
            errors.append(
                f"Objective not reached. Expected '{objective.value}', reached '{current.value}'."
            )
        return SolveResult(not errors, current, tuple(errors))

