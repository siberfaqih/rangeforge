"""Primitive registry and profile guardrails."""

from collections.abc import Iterable

from rangeforge.models import Primitive, TrainingProfile


class PrimitiveRegistry:
    def __init__(self, primitives: Iterable[Primitive]) -> None:
        self._primitives: dict[str, Primitive] = {}
        for primitive in primitives:
            if primitive.id in self._primitives:
                raise ValueError(f"Duplicate primitive id: {primitive.id}")
            self._primitives[primitive.id] = primitive

    def get(self, primitive_id: str) -> Primitive | None:
        return self._primitives.get(primitive_id)

    def require(self, primitive_id: str) -> Primitive:
        primitive = self.get(primitive_id)
        if primitive is None:
            raise KeyError(f"Unknown primitive: {primitive_id}")
        return primitive

    def all(self) -> tuple[Primitive, ...]:
        return tuple(self._primitives[key] for key in sorted(self._primitives))

    def allowed_for(self, profile: TrainingProfile, platform: str) -> tuple[Primitive, ...]:
        """Apply a deterministic default-deny curriculum filter."""
        allowed_categories = set(profile.allowed_categories)
        forbidden_categories = set(profile.forbidden_categories)
        allowed_techniques = set(profile.allowed_techniques)
        return tuple(
            primitive
            for primitive in self.all()
            if primitive.id in allowed_techniques
            and profile.id in primitive.profiles
            and platform in primitive.platforms
            and set(primitive.categories).issubset(allowed_categories)
            and not set(primitive.categories).intersection(forbidden_categories)
        )

