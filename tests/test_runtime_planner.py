from __future__ import annotations

import hashlib
from pathlib import Path

from rangeforge.host.models import Architecture, HostInfo, HostOS, RuntimeExecutables
from rangeforge.images.cache import ImageCache
from rangeforge.images.manager import ImageManager
from rangeforge.images.registry import ImageRegistry
from rangeforge.images.resolver import ImageResolver
from rangeforge.models import Scenario, TrainingProfile
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

