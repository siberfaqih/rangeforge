"""Explicitly gated Windows ARM64 UTM/QGA management smoke test.

This test is disabled by default twice over: it carries the ``runtime``
marker (deselected by the default pytest configuration) and it requires both

* ``RANGEFORGE_RUN_WINDOWS_MANAGEMENT=1`` and
* ``RANGEFORGE_WINDOWS_SCENARIO_PATH`` pointing at the ``scenario.yaml`` of
  an explicitly created, owned Windows ARM64 UTM scenario clone.

It never targets ``rf-base-windows-11-arm64`` or any other shared base
template: transport construction validates persisted RangeForge ownership
metadata first and refuses anything that is not the owned scenario clone.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from rangeforge.host.detector import HostDetector
from rangeforge.images.cache import ImageCache
from rangeforge.images.manager import ImageManager
from rangeforge.images.registry import ImageRegistry
from rangeforge.images.templates import TemplateManager
from rangeforge.runtime.backends.utm import UTMBackend
from rangeforge.runtime.backends.vagrant import VagrantBackend
from rangeforge.runtime.guest import GuestPlatform
from rangeforge.runtime.management import probe_windows_management
from rangeforge.runtime.metadata import RuntimeMetadataStore
from rangeforge.runtime.models import Architecture, ManagementState, VMBackend, VMState
from rangeforge.serialization.yaml import ScenarioYamlSerializer


@pytest.mark.runtime
def test_real_windows_arm64_utm_qga_management_smoke() -> None:
    if os.environ.get("RANGEFORGE_RUN_WINDOWS_MANAGEMENT") != "1":
        pytest.skip(
            "Set RANGEFORGE_RUN_WINDOWS_MANAGEMENT=1 to run the Windows "
            "ARM64 UTM/QGA management smoke test."
        )
    raw_path = os.environ.get("RANGEFORGE_WINDOWS_SCENARIO_PATH")
    if not raw_path:
        pytest.skip(
            "Set RANGEFORGE_WINDOWS_SCENARIO_PATH to the scenario.yaml of an "
            "explicitly created owned Windows ARM64 UTM scenario clone."
        )
    scenario_path = Path(raw_path).expanduser().resolve()
    scenario = ScenarioYamlSerializer().load(scenario_path)
    store = RuntimeMetadataStore(scenario_path)
    metadata = store.load()
    assert metadata is not None, (
        "The target scenario has no persisted RangeForge runtime metadata."
    )
    store.validate_ownership(scenario, metadata)

    # Only an explicitly created owned Windows ARM64 UTM scenario clone may
    # be probed; shared base templates are refused before any runner call.
    assert metadata.guest.platform is GuestPlatform.WINDOWS
    assert metadata.guest.architecture is Architecture.ARM64
    assert metadata.backend is VMBackend.UTM
    assert metadata.vm.state is VMState.RUNNING
    assert metadata.vm.name != metadata.template.name
    assert metadata.vm.name != "rf-base-windows-11-arm64"
    assert metadata.guest.management is not ManagementState.UNAVAILABLE

    from rangeforge.config import ConfigLoader

    config = ConfigLoader(None).load()
    host = HostDetector().detect(executable_overrides=config.executable_overrides)
    assert host.architecture is Architecture.ARM64, (
        "The Windows QGA management smoke test must run on an ARM64 host."
    )
    utm = UTMBackend(host.executables.utmctl)
    vagrant = VagrantBackend(host.executables.vagrant)
    template_manager = TemplateManager(
        ImageManager(ImageRegistry.load(), ImageCache(config.images.cache_dir))
    )

    probe = probe_windows_management(
        scenario,
        scenario_path,
        host=host,
        utm=utm,
        vagrant=vagrant,
        template_manager=template_manager,
        expected_architecture=Architecture.ARM64,
    )
    failed = tuple(check.name for check in probe.checks if not check.passed)
    assert probe.ok, f"Windows management probe failed checks: {', '.join(failed)}"
