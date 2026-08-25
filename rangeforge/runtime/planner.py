"""Deterministic, side-effect-free runtime planning for a generated scenario."""

from __future__ import annotations

from collections.abc import Callable
from typing import Literal

from rangeforge.artifacts.manager import ArtifactManager
from rangeforge.cve.registry import CVERegistry
from rangeforge.host.models import Architecture, HostInfo
from rangeforge.images.manager import ImageManager
from rangeforge.images.models import (
    ArtifactState,
    ImageAcquisitionMethod,
    ImageManifest,
    TemplateState,
)
from rangeforge.images.resolver import ImageResolutionError, ImageResolver
from rangeforge.models import Primitive, Scenario, TrainingProfile
from rangeforge.primitives.registry import PrimitiveRegistry
from rangeforge.runtime.backends.docker import DockerBackend
from rangeforge.runtime.backends.utm import UTMBackend
from rangeforge.runtime.backends.vagrant import VagrantBackend
from rangeforge.runtime.guest import check_guest_compatibility
from rangeforge.runtime.models import (
    BackendStatus,
    CVEArtifactPlanStatus,
    CVEPlanStatus,
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
        cve_registry: CVERegistry | None = None,
        artifact_manager: ArtifactManager | None = None,
        backend_status_provider: BackendStatusProvider | None = None,
    ) -> None:
        self.profile = profile
        self.primitive_registry = primitive_registry
        self.image_resolver = image_resolver
        self.image_manager = image_manager
        self.cve_registry = cve_registry
        self.artifact_manager = artifact_manager
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
        guest_architecture = Architecture(scenario.scenario.guest_architecture)
        resolution = RuntimeResolver().resolve(
            requested_runtime,
            host,
            primitives,
            guest_architecture=guest_architecture,
        )
        issues.extend(resolution.errors)
        if resolution.runtime.value != scenario.scenario.target_runtime:
            issues.append(
                "Requested runtime does not match the scenario generation target."
            )
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

        guest_compatibility = check_guest_compatibility(
            platform=scenario.scenario.platform,
            family=requirement.family,
            runtime=resolution.runtime,
            backend=resolution.backend,
            architecture=guest_architecture,
            host=host,
        )
        issues.extend(guest_compatibility.errors)

        guest = GuestPlan(
            family=requirement.family,
            distribution=requirement.distribution,
            version=requirement.version,
            architecture=guest_architecture,
        )
        image_status: ImagePlanStatus | None = None
        resolved_manifest: ImageManifest | None = None
        if resolution.compatible and guest_compatibility.compatible:
            try:
                manifest = self.image_resolver.resolve(
                    family=guest.family,
                    distribution=guest.distribution,
                    version=guest.version,
                    architecture=guest.architecture,
                    runtime=resolution.runtime,
                    backend=resolution.backend,
                )
                resolved_manifest = manifest
                guest = guest.model_copy(update={"image_id": manifest.id})
                inspection = self.image_manager.inspect(manifest.id)
                template = self._template_state(inspection.template_states, resolution)
                image_status = ImagePlanStatus(
                    acquisition=manifest.acquisition_method.value,
                    source=inspection.artifact_state.value,
                    template=template.value if template else "not_required",
                )
            except ImageResolutionError as exc:
                issues.append(str(exc))

        cve_status = self._cve_status(
            scenario,
            resolution,
            guest,
            issues,
        )

        compatible = (
            resolution.compatible
            and guest_compatibility.compatible
            and not issues
        )
        backend_ready = backend_status is not None and backend_status.available
        source_ready = image_status is not None and image_status.source == ArtifactState.READY
        template_ready = (
            resolution.runtime is RuntimeType.DOCKER
            or (
                image_status is not None
                and image_status.template == TemplateState.READY
            )
        )
        cve_artifacts_ready = all(
            artifact.status == "ready"
            for cve in cve_status
            for artifact in cve.artifacts
        )
        deployable = (
            compatible
            and backend_ready
            and source_ready
            and template_ready
            and cve_artifacts_ready
        )
        return RuntimePlan(
            scenario_id=scenario.scenario.id,
            host=host,
            runtime=resolution,
            backend_status=backend_status,
            guest=guest,
            image_status=image_status,
            cve_status=cve_status,
            compatible=compatible,
            deployable=deployable,
            issues=tuple(dict.fromkeys(issues)),
            next_action=self._next_action(
                resolution,
                backend_status,
                image_status,
                issues,
                cve_status,
                manifest=resolved_manifest,
            ),
        )

    def _cve_status(
        self,
        scenario: Scenario,
        resolution: RuntimeResolution,
        guest: GuestPlan,
        issues: list[str],
    ) -> tuple[CVEPlanStatus, ...]:
        selected = []
        if self.cve_registry is None:
            return ()
        if scenario.scenario.cve_registry_version != self.cve_registry.version:
            issues.append(
                "Scenario CVE registry version does not match the installed registry."
            )
        for primitive_id in scenario.attack_graph.path:
            item = self.cve_registry.get_by_primitive(primitive_id)
            if item is None:
                continue
            manifest = item.manifest
            if not manifest.supports(
                profile=scenario.scenario.profile,
                platform=scenario.scenario.platform,
                architecture=guest.architecture,
                runtime=resolution.runtime,
                backend=resolution.backend,
                family=guest.family,
                distribution=guest.distribution,
                version=guest.version,
            ):
                issues.append(
                    f"CVE primitive '{primitive_id}' is incompatible with "
                    f"{resolution.runtime.value}/{guest.architecture.value}."
                )
            if self.artifact_manager is None:
                issues.append("CVE artifact manager is unavailable.")
                continue
            artifacts = []
            for artifact_id in manifest.artifact_ids_for(guest.architecture):
                inspection = self.artifact_manager.inspect(artifact_id)
                artifact_status: Literal["missing", "ready", "invalid"] = (
                    "ready"
                    if inspection.state is ArtifactState.READY
                    else (
                        "missing"
                        if inspection.state is ArtifactState.MISSING
                        else "invalid"
                    )
                )
                artifacts.append(
                    CVEArtifactPlanStatus(
                        id=artifact_id,
                        version=inspection.manifest.version,
                        sha256=inspection.manifest.checksum.value.lower(),
                        status=artifact_status,
                    )
                )
            selected.append(
                CVEPlanStatus(
                    primitive=primitive_id,
                    cve_id=manifest.cve.id,
                    product=manifest.cve.product,
                    expected_version=manifest.service.expected_version,
                    artifacts=tuple(artifacts),
                )
            )
        return tuple(selected)

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
        cve_status: tuple[CVEPlanStatus, ...],
        manifest: ImageManifest | None = None,
    ) -> str:
        if issues:
            return "Resolve compatibility errors before deployment."
        if backend_status is None or not backend_status.available:
            backend = resolution.backend.value if resolution.backend else resolution.runtime.value
            return f"Install or start the required {backend} backend."
        # Acquisition-aware guidance: manual media must be imported by the
        # operator, backend-managed sources are prepared through their VM
        # backend, and checksum-pending images can never become ready until
        # a reviewed SHA-256 is configured in the registry.
        acquisition = manifest.source.acquisition if manifest else None
        checksum_pending = manifest is not None and manifest.checksum.value is None
        if image_status is None or image_status.source == ArtifactState.MISSING:
            if checksum_pending:
                return (
                    "This image has no reviewed SHA-256; configure a reviewed "
                    "checksum before its source media can become ready."
                )
            if acquisition is ImageAcquisitionMethod.MANUAL:
                return "Import the trusted, checksum-verifiable source image."
            if acquisition is ImageAcquisitionMethod.BACKEND_MANAGED:
                backend = (
                    resolution.backend.value if resolution.backend else "declared"
                )
                return f"Prepare the source image through the {backend} backend."
            return "Pull or import the trusted, checksum-verifiable source image."
        if image_status.source != ArtifactState.READY:
            if checksum_pending:
                return (
                    "This image has no reviewed SHA-256; configure a reviewed "
                    "checksum before its source media can become ready."
                )
            if acquisition is ImageAcquisitionMethod.MANUAL:
                return "Import the trusted, checksum-verifiable source image."
            return "Verify the source image before preparing a backend template."
        if (
            resolution.runtime is RuntimeType.VM
            and image_status.template != TemplateState.READY
        ):
            backend = resolution.backend.value.upper() if resolution.backend else "VM"
            return f"Prepare or register the reusable {backend} base template."
        for cve in cve_status:
            for artifact in cve.artifacts:
                if artifact.status != "ready":
                    return f"Run: rangeforge artifacts pull {artifact.id}"
        return "Runtime prerequisites are ready for the scenario lifecycle."

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
