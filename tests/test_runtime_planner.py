from __future__ import annotations

import hashlib
from pathlib import Path

from rangeforge.host.models import Architecture, HostInfo, HostOS, RuntimeExecutables
from rangeforge.images.cache import ImageCache
from rangeforge.images.manager import ImageManager
from rangeforge.images.registry import ImageRegistry
from rangeforge.images.resolver import ImageResolver
from rangeforge.models import (
    AccessState,
    AttackGraphSpec,
    DifficultyLevel,
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


def _utm_ready(_: RuntimeResolution, __: HostInfo) -> BackendStatus:
    return BackendStatus(backend=BackendType.UTM, available=True)


def _planner(
    profile: TrainingProfile,
    registry: PrimitiveRegistry,
    tmp_path: Path,
) -> RuntimePlanner:
    image_registry = ImageRegistry.load()
    return RuntimePlanner(
        profile=profile,
        primitive_registry=registry,
        image_resolver=ImageResolver(image_registry),
        image_manager=ImageManager(image_registry, ImageCache(tmp_path / "images")),
        backend_status_provider=_utm_ready,
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


def test_runtime_plan_rejects_windows_guest(
    profile: TrainingProfile,
    registry: PrimitiveRegistry,
    tmp_path: Path,
) -> None:
    """Windows guests must be rejected even if a profile declared a requirement."""
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
    assert any("does not support runtime" in issue for issue in plan.issues)
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
