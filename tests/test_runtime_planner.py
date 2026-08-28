from __future__ import annotations

import hashlib
from pathlib import Path

from rangeforge.host.models import Architecture, HostInfo, HostOS, RuntimeExecutables
from rangeforge.images.cache import ImageCache
from rangeforge.images.manager import ImageManager
from rangeforge.images.models import (
    ArtifactFormat,
    Checksum,
    ImageAcquisitionMethod,
    ImageManifest,
    ImageOS,
    ImageSource,
    ImageSourceType,
    VagrantBox,
)
from rangeforge.images.registry import ImageRegistry
from rangeforge.images.resolver import ImageResolver
from rangeforge.models import (
    AccessState,
    AttackGraphSpec,
    DifficultyLevel,
    GuestRequirement,
    MachineMetadata,
    Scenario,
    ScenarioMetadata,
    TrainingProfile,
    ValidationResult,
)
from rangeforge.primitives.registry import PrimitiveRegistry
from rangeforge.runtime.models import (
    BackendStatus,
    BackendType,
    RuntimeResolution,
    RuntimeType,
    VMBackend,
)
from rangeforge.runtime.planner import RuntimePlanner


def _host() -> HostInfo:
    return HostInfo(
        os=HostOS.DARWIN,
        architecture=Architecture.ARM64,
        apple_silicon=True,
        executables=RuntimeExecutables(),
    )


def _amd64_host(os: HostOS = HostOS.WINDOWS) -> HostInfo:
    return HostInfo(
        os=os,
        architecture=Architecture.AMD64,
        apple_silicon=False,
        executables=RuntimeExecutables(),
    )


def _utm_ready(_: RuntimeResolution, __: HostInfo) -> BackendStatus:
    return BackendStatus(backend=BackendType.UTM, available=True)


def _vagrant_ready(_: RuntimeResolution, __: HostInfo) -> BackendStatus:
    return BackendStatus(backend=BackendType.VAGRANT, available=True)


def _utm_unavailable(_: RuntimeResolution, __: HostInfo) -> BackendStatus:
    return BackendStatus(backend=BackendType.UTM, available=False)


def _windows_profile(profile: TrainingProfile) -> TrainingProfile:
    """Isolated in-memory profile that allows Windows 11 VM guests."""
    return profile.model_copy(
        update={
            "allowed_platforms": ("linux", "windows"),
            "runtime_defaults": {
                "linux": profile.runtime_defaults["linux"],
                "windows": GuestRequirement(
                    family="windows",
                    distribution="windows",
                    version="11",
                    default_runtime="vm",
                ),
            },
        }
    )


def _windows_scenario(*, architecture: str, scenario_id: str = "windows-plan") -> Scenario:
    return Scenario(
        scenario=ScenarioMetadata(
            id=scenario_id,
            seed=1337,
            profile="oscp",
            profile_name="OSCP-style",
            mode="standalone",
            platform="windows",
            difficulty=DifficultyLevel.MEDIUM,
            difficulty_score=2.0,
            generator_version="test",
            target_runtime="vm",
            guest_architecture=architecture,
        ),
        machine=MachineMetadata(hostname="victim", ip="10.10.10.10"),
        attack_graph=AttackGraphSpec(
            start=AccessState.NO_ACCESS,
            objective=AccessState.ROOT,
            path=(),
            selected_primitives=(),
        ),
        validation=ValidationResult(solvable=True),
    )


def _registry_with_windows_amd64_fixture() -> ImageRegistry:
    """Return the shipped checksum-pending AMD64/Vagrant identity."""
    return ImageRegistry.load()


def _registry_with_reviewed_manual_windows_arm64() -> ImageRegistry:
    """Standalone registry with a manual ARM64 identity whose media identity
    carries a (fixture) reviewed SHA-256, so import guidance applies."""
    return ImageRegistry(
        (
            ImageManifest(
                id="windows-11-arm64",
                os=ImageOS(family="windows", distribution="windows", version="11"),
                architecture=Architecture.ARM64,
                runtimes=(RuntimeType.VM,),
                backends=(VMBackend.UTM,),
                source=ImageSource(
                    type=ImageSourceType.OFFICIAL,
                    vendor="microsoft",
                    artifact_format=ArtifactFormat.ISO,
                    version="11",
                    filename="windows-11-arm64-reviewed.iso",
                    acquisition=ImageAcquisitionMethod.MANUAL,
                ),
                checksum=Checksum(value="d" * 64),
            ),
        )
    )


def _registry_with_backend_managed_windows_amd64() -> ImageRegistry:
    """Standalone registry with a backend-managed AMD64/Vagrant identity."""
    return ImageRegistry(
        (
            ImageManifest(
                id="windows-11-amd64",
                os=ImageOS(family="windows", distribution="windows", version="11"),
                architecture=Architecture.AMD64,
                runtimes=(RuntimeType.VM,),
                backends=(VMBackend.VAGRANT,),
                source=ImageSource(
                    type=ImageSourceType.OFFICIAL,
                    vendor="microsoft",
                    artifact_format=ArtifactFormat.ISO,
                    version="11",
                    filename="windows-11-amd64-box.iso",
                    acquisition=ImageAcquisitionMethod.BACKEND_MANAGED,
                ),
                checksum=Checksum(value="e" * 64),
                vagrant_box=VagrantBox(name="rangeforge-fixtures/windows-11"),
            ),
        )
    )


def _planner(
    profile: TrainingProfile,
    registry: PrimitiveRegistry,
    tmp_path: Path,
    *,
    image_registry: ImageRegistry | None = None,
    backend_status_provider: object = None,
) -> RuntimePlanner:
    resolved_image_registry = image_registry or ImageRegistry.load()
    provider = backend_status_provider or _utm_ready
    return RuntimePlanner(
        profile=profile,
        primitive_registry=registry,
        image_resolver=ImageResolver(resolved_image_registry),
        image_manager=ImageManager(
            resolved_image_registry, ImageCache(tmp_path / "images")
        ),
        backend_status_provider=provider,  # type: ignore[arg-type]
    )


def test_runtime_plan_generation(
    scenario: Scenario,
    profile: TrainingProfile,
    registry: PrimitiveRegistry,
    tmp_path: Path,
) -> None:
    plan = _planner(profile, registry, tmp_path).plan(
        scenario, requested_runtime=RuntimeType.VM, host=_host()
    )
    assert plan.compatible
    assert not plan.deployable
    assert plan.runtime.backend is VMBackend.UTM
    assert plan.guest is not None
    assert plan.guest.image_id == "ubuntu-24.04-arm64"
    assert plan.image_status is not None
    assert plan.image_status.source == "missing"
    assert plan.image_status.template == "missing"


def test_same_scenario_produces_same_runtime_plan(
    scenario: Scenario,
    profile: TrainingProfile,
    registry: PrimitiveRegistry,
    tmp_path: Path,
) -> None:
    planner = _planner(profile, registry, tmp_path)
    first = planner.plan(scenario, requested_runtime=RuntimeType.VM, host=_host())
    second = planner.plan(scenario, requested_runtime=RuntimeType.VM, host=_host())
    assert first == second
    first_hash = hashlib.sha256(first.model_dump_json().encode()).hexdigest()
    second_hash = hashlib.sha256(second.model_dump_json().encode()).hexdigest()
    assert first_hash == second_hash


def test_runtime_plan_windows_guest_with_unresolvable_image_fails_closed(
    profile: TrainingProfile,
    registry: PrimitiveRegistry,
    tmp_path: Path,
) -> None:
    """A native Windows VM guest passes capability checks in Phase 5.2; this
    request fails closed only because its guest requirement still points at
    an Ubuntu distribution for which no Windows image exists."""
    windows_profile = profile.model_copy(
        update={
            "allowed_platforms": ("linux", "windows"),
            "runtime_defaults": {
                "linux": profile.runtime_defaults["linux"],
                "windows": profile.runtime_defaults["linux"].model_copy(
                    update={"family": "windows"}
                ),
            },
        }
    )

    windows_host = HostInfo(
        os=HostOS.WINDOWS,
        architecture=Architecture.AMD64,
        apple_silicon=False,
        executables=RuntimeExecutables(),
    )

    def _vagrant_ready(_: RuntimeResolution, __: HostInfo) -> BackendStatus:
        return BackendStatus(backend=BackendType.VAGRANT, available=True)

    image_registry = ImageRegistry.load()
    planner = RuntimePlanner(
        profile=windows_profile,
        primitive_registry=registry,
        image_resolver=ImageResolver(image_registry),
        image_manager=ImageManager(image_registry, ImageCache(tmp_path / "images")),
        backend_status_provider=_vagrant_ready,
    )

    scenario = Scenario(
        scenario=ScenarioMetadata(
            id="windows-test",
            seed=1337,
            profile="oscp",
            profile_name="OSCP-style",
            mode="standalone",
            platform="windows",
            difficulty=DifficultyLevel.MEDIUM,
            difficulty_score=2.0,
            generator_version="test",
            target_runtime="vm",
            guest_architecture="amd64",
        ),
        machine=MachineMetadata(hostname="victim", ip="10.10.10.10"),
        attack_graph=AttackGraphSpec(
            start=AccessState.NO_ACCESS,
            objective=AccessState.ROOT,
            path=(),
            selected_primitives=(),
        ),
        validation=ValidationResult(solvable=True),
    )

    plan = planner.plan(scenario, requested_runtime=RuntimeType.VM, host=windows_host)
    assert not plan.compatible
    assert not plan.deployable
    assert not any("does not support runtime" in issue for issue in plan.issues)
    # Planning-time denial: Windows VM plans are UTM/QGA-only, so the
    # Vagrant-host request is rejected before image resolution runs.
    assert any(
        "Windows Vagrant management is unsupported" in issue
        for issue in plan.issues
    )
    assert plan.guest is not None
    assert plan.guest.family == "windows"
    assert plan.image_status is None


def test_runtime_plan_rejects_windows_platform_with_linux_family(
    scenario: Scenario,
    profile: TrainingProfile,
    registry: PrimitiveRegistry,
    tmp_path: Path,
) -> None:
    """A Windows scenario must fail closed even when the profile maps the
    platform to a Linux guest family (platform/family mismatch)."""
    mismatch_profile = profile.model_copy(
        update={
            "allowed_platforms": ("linux", "windows"),
            "runtime_defaults": {
                "linux": profile.runtime_defaults["linux"],
                "windows": profile.runtime_defaults["linux"],
            },
        }
    )
    assert mismatch_profile.runtime_defaults["windows"].family == "linux"

    windows_scenario = scenario.model_copy(
        update={
            "scenario": scenario.scenario.model_copy(
                update={"platform": "windows", "guest_architecture": "arm64"}
            )
        }
    )

    plan = _planner(mismatch_profile, registry, tmp_path).plan(
        windows_scenario, requested_runtime=RuntimeType.VM, host=_host()
    )
    assert not plan.compatible
    assert not plan.deployable
    assert any(
        "Guest family 'linux' does not match scenario platform 'windows'" in issue
        for issue in plan.issues
    )
    assert plan.guest is not None
    assert plan.guest.family == "linux"
    assert plan.image_status is None


def test_runtime_plan_rejects_linux_platform_with_windows_family(
    scenario: Scenario,
    profile: TrainingProfile,
    registry: PrimitiveRegistry,
    tmp_path: Path,
) -> None:
    """A Linux scenario must fail closed when the profile guest requirement
    declares a Windows family (platform/family mismatch, reverse direction)."""
    mismatch_profile = profile.model_copy(
        update={
            "runtime_defaults": {
                "linux": profile.runtime_defaults["linux"].model_copy(
                    update={"family": "windows"}
                ),
            },
        }
    )
    assert mismatch_profile.runtime_defaults["linux"].family == "windows"

    plan = _planner(mismatch_profile, registry, tmp_path).plan(
        scenario, requested_runtime=RuntimeType.VM, host=_host()
    )
    assert not plan.compatible
    assert not plan.deployable
    assert any(
        "Guest family 'windows' does not match scenario platform 'linux'" in issue
        for issue in plan.issues
    )
    assert plan.guest is not None
    assert plan.guest.family == "windows"
    assert plan.image_status is None


def test_runtime_plan_rejects_linux_platform_with_unknown_family(
    scenario: Scenario,
    profile: TrainingProfile,
    registry: PrimitiveRegistry,
    tmp_path: Path,
) -> None:
    """A Linux scenario must fail closed when the profile guest requirement
    declares an unknown guest family (e.g. typo), before image resolution."""
    typo_profile = profile.model_copy(
        update={
            "runtime_defaults": {
                "linux": profile.runtime_defaults["linux"].model_copy(
                    update={"family": "linnux"}
                ),
            },
        }
    )

    plan = _planner(typo_profile, registry, tmp_path).plan(
        scenario, requested_runtime=RuntimeType.VM, host=_host()
    )
    assert not plan.compatible
    assert not plan.deployable
    assert any(
        "Unknown guest family: 'linnux'." in issue for issue in plan.issues
    )
    assert plan.guest is not None
    assert plan.guest.family == "linnux"
    assert plan.image_status is None


def test_runtime_plan_rejects_cross_architecture_guest(
    scenario: Scenario,
    profile: TrainingProfile,
    registry: PrimitiveRegistry,
    tmp_path: Path,
) -> None:
    """AMD64 scenario guests on an ARM64 host must fail closed without emulation."""
    arm_host = _host()
    assert arm_host.architecture is Architecture.ARM64

    amd_scenario = scenario.model_copy(
        update={
            "scenario": scenario.scenario.model_copy(
                update={"guest_architecture": "amd64"}
            )
        }
    )
    plan = _planner(profile, registry, tmp_path).plan(
        amd_scenario, requested_runtime=RuntimeType.VM, host=arm_host
    )
    assert not plan.compatible
    assert not plan.deployable
    assert any(
        "silent cross-architecture emulation" in issue for issue in plan.issues
    )


def test_runtime_plan_rejects_windows_scenario_on_linux_profile(
    scenario: Scenario,
    profile: TrainingProfile,
    registry: PrimitiveRegistry,
    tmp_path: Path,
) -> None:
    """A Windows scenario with the stock Linux-only profile must fail closed
    regardless of family mapping, via the missing-requirement path."""
    windows_scenario = scenario.model_copy(
        update={
            "scenario": scenario.scenario.model_copy(
                update={"platform": "windows", "guest_architecture": "amd64"}
            )
        }
    )
    plan = _planner(profile, registry, tmp_path).plan(
        windows_scenario, requested_runtime=RuntimeType.VM, host=_host()
    )
    assert not plan.compatible
    assert not plan.deployable
    assert any(
        "has no guest requirement for platform 'windows'" in issue
        for issue in plan.issues
    )


def test_runtime_plan_preserves_linux_compatibility(
    scenario: Scenario,
    profile: TrainingProfile,
    registry: PrimitiveRegistry,
    tmp_path: Path,
) -> None:
    """Existing Linux behavior must remain unchanged by guest capability checks."""
    plan = _planner(profile, registry, tmp_path).plan(
        scenario, requested_runtime=RuntimeType.VM, host=_host()
    )
    assert plan.compatible
    assert plan.guest is not None
    assert plan.guest.family == "linux"
    assert plan.guest.image_id == "ubuntu-24.04-arm64"
    assert not any("guest platform" in issue.lower() for issue in plan.issues)


def test_runtime_plan_windows_arm64_on_macos_utm_is_compatible_not_deployable(
    profile: TrainingProfile,
    registry: PrimitiveRegistry,
    tmp_path: Path,
) -> None:
    """macOS ARM64 + Windows 11 ARM64 resolves VM/UTM/windows-11-arm64.

    Missing manual media keeps the plan compatible but never deployable,
    and the next action directs the operator to import reviewed media.
    """
    plan = _planner(_windows_profile(profile), registry, tmp_path).plan(
        _windows_scenario(architecture="arm64"),
        requested_runtime=RuntimeType.VM,
        host=_host(),
    )
    assert plan.compatible
    assert not plan.deployable
    assert plan.runtime.backend is VMBackend.UTM
    assert plan.runtime.guest_architecture is Architecture.ARM64
    assert plan.guest is not None
    assert plan.guest.family == "windows"
    assert plan.guest.distribution == "windows"
    assert plan.guest.version == "11"
    assert plan.guest.image_id == "windows-11-arm64"
    assert plan.image_status is not None
    assert plan.image_status.acquisition == "manual"
    assert plan.image_status.source == "missing"
    assert plan.image_status.template == "missing"
    assert plan.next_action == "Import the trusted, checksum-verifiable source image."


def test_runtime_plan_windows_amd64_request_on_arm64_host_is_incompatible(
    profile: TrainingProfile,
    registry: PrimitiveRegistry,
    tmp_path: Path,
) -> None:
    """macOS ARM64 requesting Windows 11 AMD64 fails closed with no
    architecture substitution and no image resolution."""
    plan = _planner(_windows_profile(profile), registry, tmp_path).plan(
        _windows_scenario(architecture="amd64"),
        requested_runtime=RuntimeType.VM,
        host=_host(),
    )
    assert not plan.compatible
    assert not plan.deployable
    # Backend selection follows host policy; the requested guest
    # architecture is preserved verbatim and never substituted.
    assert plan.runtime.backend is VMBackend.UTM
    assert plan.runtime.guest_architecture is Architecture.AMD64
    assert any(
        "silent cross-architecture emulation" in issue for issue in plan.issues
    )
    assert plan.guest is not None
    assert plan.guest.architecture is Architecture.AMD64
    assert plan.image_status is None


def test_runtime_plan_windows_amd64_on_vagrant_host_with_shipped_identity(
    profile: TrainingProfile,
    registry: PrimitiveRegistry,
    tmp_path: Path,
) -> None:
    """AMD64 hosts resolve Vagrant/windows-11-amd64 from the shipped identity,
    but planning-time policy denies Windows-on-Vagrant management outright.

    The plan records the deterministic denial and never resolves image
    readiness for a combination that cannot be managed.
    """
    plan = _planner(
        _windows_profile(profile),
        registry,
        tmp_path,
        image_registry=_registry_with_windows_amd64_fixture(),
        backend_status_provider=_vagrant_ready,
    ).plan(
        _windows_scenario(architecture="amd64"),
        requested_runtime=RuntimeType.VM,
        host=_amd64_host(HostOS.LINUX),
    )
    assert not plan.compatible
    assert not plan.deployable
    assert any(
        "Windows Vagrant management is unsupported" in issue
        for issue in plan.issues
    )
    assert plan.runtime.backend is VMBackend.VAGRANT
    assert plan.runtime.guest_architecture is Architecture.AMD64
    assert plan.guest is not None
    assert plan.guest.family == "windows"
    assert plan.image_status is None

def test_runtime_plan_manual_image_with_reviewed_checksum_directs_import(
    profile: TrainingProfile,
    registry: PrimitiveRegistry,
    tmp_path: Path,
) -> None:
    """A manual image with a configured (reviewed) checksum directs the
    operator to import media; it stays non-deployable until they do."""
    plan = _planner(
        _windows_profile(profile),
        registry,
        tmp_path,
        image_registry=_registry_with_reviewed_manual_windows_arm64(),
        backend_status_provider=_utm_ready,
    ).plan(
        _windows_scenario(architecture="arm64", scenario_id="reviewed-import"),
        requested_runtime=RuntimeType.VM,
        host=_host(),
    )
    assert plan.compatible
    assert not plan.deployable
    assert plan.guest is not None
    assert plan.guest.image_id == "windows-11-arm64"
    assert plan.image_status is not None
    assert plan.image_status.source == "missing"
    assert plan.next_action == "Import the trusted, checksum-verifiable source image."


def test_runtime_plan_backend_managed_image_directs_backend_preparation(
    profile: TrainingProfile,
    registry: PrimitiveRegistry,
    tmp_path: Path,
) -> None:
    """Backend-managed sources direct operators to their VM backend — but a
    Windows-on-Vagrant plan is denied at planning time before any image or
    backend guidance is produced."""
    plan = _planner(
        _windows_profile(profile),
        registry,
        tmp_path,
        image_registry=_registry_with_backend_managed_windows_amd64(),
        backend_status_provider=_vagrant_ready,
    ).plan(
        _windows_scenario(architecture="amd64", scenario_id="backend-managed"),
        requested_runtime=RuntimeType.VM,
        host=_amd64_host(HostOS.LINUX),
    )
    assert not plan.compatible
    assert not plan.deployable
    assert any(
        "Windows Vagrant management is unsupported" in issue
        for issue in plan.issues
    )
    assert plan.next_action == "Resolve compatibility errors before deployment."


def test_same_windows_scenario_produces_same_runtime_plan(
    profile: TrainingProfile,
    registry: PrimitiveRegistry,
    tmp_path: Path,
) -> None:
    """Windows runtime planning must be deterministic for identical inputs."""
    planner = _planner(_windows_profile(profile), registry, tmp_path)
    windows_scenario = _windows_scenario(architecture="arm64")
    first = planner.plan(windows_scenario, requested_runtime=RuntimeType.VM, host=_host())
    second = planner.plan(windows_scenario, requested_runtime=RuntimeType.VM, host=_host())
    assert first == second
    first_hash = hashlib.sha256(first.model_dump_json().encode()).hexdigest()
    second_hash = hashlib.sha256(second.model_dump_json().encode()).hexdigest()
    assert first_hash == second_hash


def test_runtime_plan_missing_backend_keeps_compatibility_and_image(
    profile: TrainingProfile,
    registry: PrimitiveRegistry,
    tmp_path: Path,
) -> None:
    """Backend absence makes the plan non-deployable without changing the
    selected backend or the resolved image."""
    plan = _planner(
        _windows_profile(profile),
        registry,
        tmp_path,
        backend_status_provider=_utm_unavailable,
    ).plan(
        _windows_scenario(architecture="arm64"),
        requested_runtime=RuntimeType.VM,
        host=_host(),
    )
    assert plan.compatible
    assert not plan.deployable
    assert plan.backend_status is not None
    assert not plan.backend_status.available
    assert plan.runtime.backend is VMBackend.UTM
    assert plan.guest is not None
    assert plan.guest.image_id == "windows-11-arm64"
    assert plan.next_action == "Install or start the required utm backend."


def test_lifecycle_only_profile_view_preserves_planner_determinism(
    profile: TrainingProfile,
    registry: PrimitiveRegistry,
    tmp_path: Path,
) -> None:
    """The lifecycle-only Windows requirement view leaves the planner
    deterministic and does not widen profile policy."""
    lifecycle_view = profile.model_copy(
        update={
            "runtime_defaults": {
                **profile.runtime_defaults,
                "windows": GuestRequirement(
                    family="windows",
                    distribution="windows",
                    version="11",
                    default_runtime="vm",
                ),
            }
        }
    )
    # allowed_platforms and techniques remain unchanged (Windows stays denied
    # for curriculum eligibility; only planning can see the requirement).
    assert lifecycle_view.allowed_platforms == profile.allowed_platforms
    assert lifecycle_view.allowed_techniques == profile.allowed_techniques
    planner = _planner(lifecycle_view, registry, tmp_path)
    windows_scenario = _windows_scenario(architecture="arm64")
    first = planner.plan(windows_scenario, requested_runtime=RuntimeType.VM, host=_host())
    second = planner.plan(windows_scenario, requested_runtime=RuntimeType.VM, host=_host())
    assert first == second
    assert first.compatible
    assert first.runtime.backend is VMBackend.UTM
    assert first.guest is not None
    assert first.guest.image_id == "windows-11-arm64"
    assert hashlib.sha256(first.model_dump_json().encode()).hexdigest() == hashlib.sha256(
        second.model_dump_json().encode()
    ).hexdigest()
