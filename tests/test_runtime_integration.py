from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from rangeforge.cli import app


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.runtime
def test_real_utm_phase3_rebuild(tmp_path: Path) -> None:
    if os.environ.get("RANGEFORGE_RUN_RUNTIME") != "1":
        pytest.skip("Set RANGEFORGE_RUN_RUNTIME=1 for the destructive scenario-clone test.")
    runner = CliRunner()
    generated = runner.invoke(
        app,
        [
            "generate",
            "--profile",
            "oscp",
            "--mode",
            "standalone",
            "--platform",
            "linux",
            "--difficulty",
            "easy",
            "--seed",
            "81",
            "--output",
            str(tmp_path),
        ],
    )
    assert generated.exit_code == 0, generated.output
    scenario_path = tmp_path / "scenario-81" / "scenario.yaml"
    try:
        for _ in range(2):
            for command in ("build", "up", "provision", "validate"):
                result = runner.invoke(app, [command, str(scenario_path)])
                assert result.exit_code == 0, result.output
            destroyed = runner.invoke(app, ["destroy", str(scenario_path)])
            assert destroyed.exit_code == 0, destroyed.output
    finally:
        runner.invoke(app, ["destroy", str(scenario_path)])


@pytest.mark.runtime
@pytest.mark.cve_runtime
def test_real_utm_phase4_cve_rebuild(tmp_path: Path) -> None:
    if os.environ.get("RANGEFORGE_RUN_CVE_RUNTIME") != "1":
        pytest.skip("Set RANGEFORGE_RUN_CVE_RUNTIME=1 for the owned CVE scenario-clone test.")
    runner = CliRunner()
    generated = runner.invoke(
        app,
        [
            "generate",
            "--profile",
            "oscp",
            "--mode",
            "standalone",
            "--platform",
            "linux",
            "--difficulty",
            "easy",
            "--seed",
            "85",
            "--runtime",
            "vm",
            "--architecture",
            "arm64",
            "--output",
            str(tmp_path),
        ],
    )
    assert generated.exit_code == 0, generated.output
    scenario_path = tmp_path / "scenario-85" / "scenario.yaml"
    expected_path = (
        "service_enumeration",
        "cve_2023_46604_activemq_rce",
        "credential_discovery_config",
        "linux_sudo_misconfiguration",
    )
    from rangeforge.serialization.yaml import ScenarioYamlSerializer

    assert ScenarioYamlSerializer().load(scenario_path).attack_graph.path == expected_path
    first_hashes: tuple[str, ...] | None = None
    try:
        for _ in range(2):
            plan = runner.invoke(app, ["runtime", "plan", str(scenario_path)])
            assert plan.exit_code == 0, plan.output
            assert "Deployable" in plan.output and "YES" in plan.output
            for command in ("build", "up", "provision", "validate", "status"):
                result = runner.invoke(app, [command, str(scenario_path)])
                assert result.exit_code == 0, result.output
            runtime_dir = scenario_path.parent / "runtime"
            hashes = tuple(
                _sha256(runtime_dir / filename)
                for filename in (
                    "provisioning-plan.json",
                    "instructor.json",
                    "lock.yaml",
                )
            )
            if first_hashes is None:
                first_hashes = hashes
            else:
                assert hashes == first_hashes
            destroyed = runner.invoke(app, ["destroy", str(scenario_path)])
            assert destroyed.exit_code == 0, destroyed.output
    finally:
        runner.invoke(app, ["destroy", str(scenario_path)])
