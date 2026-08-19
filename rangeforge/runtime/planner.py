"""Deterministic, side-effect-free runtime planning for a generated scenario."""

from __future__ import annotations

from collections.abc import Callable

from rangeforge.host.models import HostInfo
from rangeforge.images.manager import ImageManager
from rangeforge.images.models import ArtifactState, TemplateState
from rangeforge.images.resolver import ImageResolutionError, ImageResolver
from rangeforge.models import Primitive, Scenario, TrainingProfile
from rangeforge.primitives.registry import PrimitiveRegistry
from rangeforge.runtime.backends.docker import DockerBackend
from rangeforge.runtime.backends.utm import UTMBackend
from rangeforge.runtime.backends.vagrant import VagrantBackend
from rangeforge.runtime.models import (
    BackendStatus,
    GuestPlan,
    ImagePlanStatus,
    RuntimePlan,
    RuntimeResolution,
    RuntimeType,
    VMBackend,
)
from rangeforge.runtime.resolver import RuntimeResolver

BackendStatusProvider = Callable[[RuntimeResolution, HostInfo], BackendStatus | None]


class RuntimePlanner:
    def __init__(
        self,
        *,
        profile: TrainingProfile,
        primitive_registry: PrimitiveRegistry,
        image_resolver: ImageResolver,
        image_manager: ImageManager,
        backend_status_provider: BackendStatusProvider | None = None,
    ) -> None:
        self.profile = profile
        self.primitive_registry = primitive_registry
        self.image_resolver = image_resolver
        self.image_manager = image_manager
        self.backend_status_provider = backend_status_provider or self._backend_status

    def plan(
        self,
        scenario: Scenario,
        *,
        requested_runtime: RuntimeType,
        host: HostInfo,
    ) -> RuntimePlan:
        issues: list[str] = []
        primitives = self._scenario_primitives(scenario, issues)
        resolution = RuntimeResolver().resolve(requested_runtime, host, primitives)
        issues.extend(resolution.errors)
        backend_status = self.backend_status_provider(resolution, host)

        requirement = self.profile.runtime_defaults.get(scenario.scenario.platform)
        if requirement is None:
            issues.append(
                f"Profile '{self.profile.id}' has no guest requirement for platform "
                f"'{scenario.scenario.platform}'."
            )
            return self._incomplete_plan(
                scenario, host, resolution, backend_status, issues
            )

        guest = GuestPlan(
            family=requirement.family,
            distribution=requirement.distribution,
            version=requirement.version,
            architecture=resolution.guest_architecture,
        )
        image_status: ImagePlanStatus | None = None
        if resolution.compatible:
            try:
                manifest = self.image_resolver.resolve(
                    family=guest.family,
                    distribution=guest.distribution,
                    version=guest.version,
                    architecture=guest.architecture,
                    runtime=resolution.runtime,
                    backend=resolution.backend,
                )
                guest = guest.model_copy(update={"image_id": manifest.id})
                inspection = self.image_manager.inspect(manifest.id)
                template = self._template_state(inspection.template_states, resolution)
                image_status = ImagePlanStatus(
                    source=inspection.artifact_state.value,
                    template=template.value if template else "not_required",
                )
            except ImageResolutionError as exc:
                issues.append(str(exc))

        compatible = resolution.compatible and not issues
        backend_ready = backend_status is not None and backend_status.available
        source_ready = image_status is not None and image_status.source == ArtifactState.READY
        template_ready = (
            resolution.runtime is RuntimeType.DOCKER
            or (
                image_status is not None
                and image_status.template == TemplateState.READY
            )
        )
        deployable = compatible and backend_ready and source_ready and template_ready
        return RuntimePlan(
            scenario_id=scenario.scenario.id,
            host=host,
            runtime=resolution,
            backend_status=backend_status,
            guest=guest,
            image_status=image_status,
            compatible=compatible,
            deployable=deployable,
            issues=tuple(dict.fromkeys(issues)),
            next_action=self._next_action(
                resolution,
                backend_status,
                image_status,
                issues,
            ),
        )

    def _scenario_primitives(
        self, scenario: Scenario, issues: list[str]
    ) -> tuple[Primitive, ...]:
        primitives: list[Primitive] = []
        for primitive_id in scenario.attack_graph.path:
            primitive = self.primitive_registry.get(primitive_id)
            if primitive is None:
                issues.append(f"Unknown primitive in scenario: {primitive_id}")
            else:
                primitives.append(primitive)
        return tuple(primitives)

    @staticmethod
    def _template_state(
        states: dict[VMBackend, TemplateState],
        resolution: RuntimeResolution,
    ) -> TemplateState | None:
        if resolution.runtime is RuntimeType.DOCKER or resolution.backend is None:
            return None
        return states.get(resolution.backend, TemplateState.MISSING)

    @staticmethod
    def _backend_status(
        resolution: RuntimeResolution, host: HostInfo
    ) -> BackendStatus | None:
        if resolution.runtime is RuntimeType.DOCKER:
            return DockerBackend(host.executables.docker).status()
        if resolution.backend is VMBackend.UTM:
            return UTMBackend(host.executables.utmctl).status()
        if resolution.backend is VMBackend.VAGRANT:
            return VagrantBackend(host.executables.vagrant).status()
        return None

    @staticmethod
    def _next_action(
        resolution: RuntimeResolution,
        backend_status: BackendStatus | None,
        image_status: ImagePlanStatus | None,
        issues: list[str],
    ) -> str:
        if issues:
            return "Resolve compatibility errors before deployment."
        if backend_status is None or not backend_status.available:
            backend = resolution.backend.value if resolution.backend else resolution.runtime.value
            return f"Install or start the required {backend} backend."
        if image_status is None or image_status.source == ArtifactState.MISSING:
            return "Import a trusted, checksum-verifiable source image."
        if image_status.source != ArtifactState.READY:
            return "Verify the source image before preparing a backend template."
        if (
            resolution.runtime is RuntimeType.VM
            and image_status.template != TemplateState.READY
        ):
            backend = resolution.backend.value.upper() if resolution.backend else "VM"
            return f"Prepare the reusable {backend} base template."
        return "Runtime prerequisites are ready; deployment remains disabled in Phase 2A."

    @staticmethod
    def _incomplete_plan(
        scenario: Scenario,
        host: HostInfo,
        resolution: RuntimeResolution,
        backend_status: BackendStatus | None,
        issues: list[str],
    ) -> RuntimePlan:
        return RuntimePlan(
            scenario_id=scenario.scenario.id,
            host=host,
            runtime=resolution,
            backend_status=backend_status,
            compatible=False,
            deployable=False,
            issues=tuple(dict.fromkeys(issues)),
            next_action="Add a profile guest requirement before deployment planning.",
        )

