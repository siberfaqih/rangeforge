"""Runtime implementation resolution kept separate from logical primitive policy."""

from __future__ import annotations

from pathlib import Path

from rangeforge.host.models import Architecture
from rangeforge.models import Scenario
from rangeforge.runtime.models import RuntimeType, VMBackend
from rangeforge.runtime_primitives.models import RuntimePrimitive


class RuntimeImplementationError(ValueError):
    """Raised when a logical primitive has no exact compatible runtime implementation."""


class RuntimePrimitiveRegistry:
    def __init__(self, primitives: tuple[RuntimePrimitive, ...], root: Path) -> None:
        self.root = root
        self._primitives: dict[str, RuntimePrimitive] = {}
        for primitive in primitives:
            identifier = primitive.primitive.id
            if identifier in self._primitives:
                raise RuntimeImplementationError(f"Duplicate runtime primitive: {identifier}")
            self._primitives[identifier] = primitive

    def get(self, primitive_id: str) -> RuntimePrimitive | None:
        return self._primitives.get(primitive_id)

    def resolve(
        self,
        scenario: Scenario,
        *,
        runtime: RuntimeType,
        backend: VMBackend,
        architecture: Architecture,
    ) -> tuple[RuntimePrimitive, ...]:
        resolved: list[RuntimePrimitive] = []
        for primitive_id in scenario.attack_graph.path:
            runtime_primitive = self.get(primitive_id)
            if runtime_primitive is None:
                raise RuntimeImplementationError(
                    "Scenario cannot be provisioned. "
                    f"Primitive '{primitive_id}' has no Linux VM runtime implementation."
                )
            manifest = runtime_primitive.manifest
            supports_runtime = any(
                item.runtime is runtime and backend in item.backends
                for item in manifest.runtime_support
            )
            if scenario.scenario.platform not in manifest.platforms:
                raise RuntimeImplementationError(
                    f"Primitive '{primitive_id}' has no "
                    f"{scenario.scenario.platform} runtime implementation."
                )
            if architecture not in manifest.architectures:
                raise RuntimeImplementationError(
                    f"Primitive '{primitive_id}' does not support architecture "
                    f"'{architecture.value}'."
                )
            if not supports_runtime:
                raise RuntimeImplementationError(
                    f"Primitive '{primitive_id}' does not support {runtime.value}/{backend.value}."
                )
            resolved.append(runtime_primitive)
        return tuple(resolved)

    def script_path(self, primitive: RuntimePrimitive, implementation: str) -> Path:
        root = primitive.definition_path or (self.root / primitive.primitive.id)
        return root / f"{implementation}.sh"
