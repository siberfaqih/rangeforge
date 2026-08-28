import hashlib
from pathlib import Path

import pytest
from typer.testing import CliRunner

from rangeforge.cli import app
from rangeforge.host.models import Architecture, HostInfo, HostOS
from rangeforge.images.cache import ImageCache
from rangeforge.images.models import (
    ArtifactFormat,
    Checksum,
    ImageManifest,
    ImageOS,
    ImageSource,
    ImageSourceType,
)
from rangeforge.images.registry import ImageRegistry
from rangeforge.models import Scenario
from rangeforge.runtime.backends.base import BackendOperationError
from rangeforge.runtime.backends.utm import UTMBackend
from rangeforge.runtime.models import RuntimeType, VMBackend
from rangeforge.serialization.yaml import ScenarioYamlSerializer


def test_generate_cli_dry_run(tmp_path: Path) -> None:
    result = CliRunner().invoke(
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
            "medium",
            "--seed",
            "1337",
            "--dry-run",
            "--output",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "Graph solvable" in result.output
    assert "YES" in result.output
    assert (tmp_path / "scenario-1337" / "scenario.yaml").is_file()


def test_generate_cli_without_dry_run_is_metadata_only(tmp_path: Path) -> None:
    result = CliRunner().invoke(
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
            "1",
            "--output",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "Graph solvable" in result.output
    assert (tmp_path / "scenario-1" / "scenario.yaml").is_file()


def test_doctor_is_diagnostic(tmp_path: Path) -> None:
    config = tmp_path / "config.yaml"
    cache = tmp_path / "images"
    config.write_text(f"images:\n  cache_dir: {cache}\n", encoding="utf-8")
    result = CliRunner().invoke(app, ["doctor", "--config", str(config)])
    assert result.exit_code == 0, result.output
    assert "RangeForge Environment" in result.output
    assert "VM Backend" in result.output
    assert not cache.exists()


def test_images_list_cli(tmp_path: Path) -> None:
    config = tmp_path / "config.yaml"
    config.write_text(f"images:\n  cache_dir: {tmp_path / 'images'}\n", encoding="utf-8")
    result = CliRunner().invoke(app, ["images", "list", "--config", str(config)])
    assert result.exit_code == 0, result.output
    assert "ubuntu-24.04-arm64" in result.output
    assert "ubuntu-24.04-amd64" in result.output
    assert "windows-11-arm64" in result.output
    assert "windows-11-amd64" in result.output
    assert "MANUAL" in result.output


def test_windows_image_info_displays_acquisition_and_checksum(tmp_path: Path) -> None:
    config = tmp_path / "config.yaml"
    config.write_text(f"images:\n  cache_dir: {tmp_path / 'images'}\n", encoding="utf-8")
    result = CliRunner().invoke(
        app,
        ["images", "info", "windows-11-arm64", "--config", str(config)],
    )
    assert result.exit_code == 0, result.output
    assert "MANUAL" in result.output
    assert "638aa2c88e94385b00f4f178d071e3df" in result.output


def test_artifacts_list_and_info_cli(tmp_path: Path) -> None:
    config = tmp_path / "config.yaml"
    config.write_text(
        f"artifacts:\n  cache_dir: {tmp_path / 'artifacts'}\n",
        encoding="utf-8",
    )
    listing = CliRunner().invoke(app, ["artifacts", "list", "--config", str(config)])
    assert listing.exit_code == 0, listing.output
    assert "apache-activemq-5.18.2" in listing.output
    assert "temurin-jre-17.0.19-linux-arm64" in listing.output

    info = CliRunner().invoke(
        app,
        ["artifacts", "info", "apache-activemq-5.18.2", "--config", str(config)],
    )
    assert info.exit_code == 0, info.output
    assert "5.18.2" in info.output
    assert "MISSING" in info.output


def test_cve_registry_cli(tmp_path: Path) -> None:
    config = tmp_path / "config.yaml"
    config.write_text(
        f"artifacts:\n  cache_dir: {tmp_path / 'artifacts'}\n",
        encoding="utf-8",
    )
    listing = CliRunner().invoke(app, ["cve", "list"])
    assert listing.exit_code == 0, listing.output
    assert "CVE-2023-46604" in listing.output

    info = CliRunner().invoke(
        app,
        ["cve", "info", "CVE-2023-46604", "--config", str(config)],
    )
    assert info.exit_code == 0, info.output
    assert "Apache ActiveMQ Classic" in info.output
    assert "MISSING" in info.output

    validation = CliRunner().invoke(app, ["cve", "validate-registry"])
    assert validation.exit_code == 0, validation.output
    assert "registry version 1: VALID" in validation.output


def test_runtime_plan_cli(scenario: Scenario, tmp_path: Path) -> None:
    scenario_path = ScenarioYamlSerializer().dump(scenario, tmp_path)
    config = tmp_path / "config.yaml"
    config.write_text(f"images:\n  cache_dir: {tmp_path / 'images'}\n", encoding="utf-8")
    result = CliRunner().invoke(
        app,
        [
            "runtime",
            "plan",
            str(scenario_path),
            "--runtime",
            "vm",
            "--config",
            str(config),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "RangeForge Runtime Plan" in result.output
    assert "Deployable" in result.output
    assert "NO" in result.output


def test_images_verify_cli_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    content = b"cli fixture image"
    manifest = ImageManifest(
        id="cli-test-image",
        os=ImageOS(family="linux", distribution="ubuntu", version="24.04"),
        architecture=Architecture.ARM64,
        runtimes=(RuntimeType.VM,),
        backends=(VMBackend.UTM,),
        source=ImageSource(
            type=ImageSourceType.OFFICIAL,
            vendor="fixture",
            artifact_format=ArtifactFormat.QCOW2,
            version="test",
            filename="cli-test.iso",
        ),
        checksum=Checksum(value=hashlib.sha256(content).hexdigest()),
    )
    registry = ImageRegistry((manifest,))
    monkeypatch.setattr(ImageRegistry, "load", classmethod(lambda cls: registry))
    cache = ImageCache(tmp_path / "images")
    cache.ensure()
    cache.artifact_path(manifest).write_bytes(content)
    config = tmp_path / "config.yaml"
    config.write_text(f"images:\n  cache_dir: {cache.root}\n", encoding="utf-8")

    result = CliRunner().invoke(app, ["images", "verify", manifest.id, "--config", str(config)])
    assert result.exit_code == 0, result.output
    assert "VALID" in result.output


def _windows_scenario_path(scenario: Scenario, tmp_path: Path) -> Path:
    windows_scenario = scenario.model_copy(
        update={
            "scenario": scenario.scenario.model_copy(
                update={"platform": "windows", "guest_architecture": "arm64"}
            )
        }
    )
    return ScenarioYamlSerializer().dump(windows_scenario, tmp_path)


def _config_path(tmp_path: Path) -> Path:
    config = tmp_path / "config.yaml"
    config.write_text(
        f"images:\n  cache_dir: {tmp_path / 'images'}\n", encoding="utf-8"
    )
    return config


def _hermetic_utm_inventory(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin standalone lifecycle commands to a deterministic darwin/UTM host.

    Lifecycle commands reconcile backend inventory before reporting state;
    pinning the detected host and the inventory response keeps these tests
    independent of whether a local UTM app is installed and responsive.
    """
    monkeypatch.setattr(
        "rangeforge.cli._host",
        lambda _config: HostInfo(
            os=HostOS.DARWIN,
            architecture=Architecture.ARM64,
            apple_silicon=True,
        ),
    )
    monkeypatch.setattr(UTMBackend, "list_vms", lambda self: ())


def test_stop_command_is_registered(tmp_path: Path) -> None:
    result = CliRunner().invoke(app, ["stop", "--help"])
    assert result.exit_code == 0, result.output
    assert "Stop the owned scenario VM" in result.output


def test_windows_scenario_runtime_plan_is_accepted(
    scenario: Scenario, tmp_path: Path
) -> None:
    scenario_path = _windows_scenario_path(scenario, tmp_path)
    config = _config_path(tmp_path)
    result = CliRunner().invoke(
        app,
        ["runtime", "plan", str(scenario_path), "--runtime", "vm", "--config", str(config)],
    )
    # A standalone Windows lifecycle scenario must pass lifecycle structural
    # validation and reach the planner (it may not be deployable here).
    assert result.exit_code == 0, result.output
    assert "RangeForge Runtime Plan" in result.output


def test_windows_scenario_status_is_accepted_and_reports_not_built(
    scenario: Scenario, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _hermetic_utm_inventory(monkeypatch)
    scenario_path = _windows_scenario_path(scenario, tmp_path)
    config = _config_path(tmp_path)
    result = CliRunner().invoke(
        app, ["status", str(scenario_path), "--config", str(config)]
    )
    assert result.exit_code == 0, result.output
    assert "Scenario VM is not built." in result.output


def test_windows_scenario_stop_is_accepted_and_reports_not_built(
    scenario: Scenario, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _hermetic_utm_inventory(monkeypatch)
    scenario_path = _windows_scenario_path(scenario, tmp_path)
    config = _config_path(tmp_path)
    result = CliRunner().invoke(
        app, ["stop", str(scenario_path), "--config", str(config)]
    )
    assert result.exit_code == 0, result.output
    assert "Scenario VM is not built." in result.output


def test_lifecycle_cli_envelopes_backend_operation_error(
    scenario: Scenario,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Backend identity/inventory failures render as controlled failures.

    A backend operation error raised from the lifecycle (here: an unavailable
    UTM backend during status reconciliation) must be reported through the
    lifecycle error envelope with exit code 1, never escape as an uncaught
    exception.
    """
    monkeypatch.setattr(
        "rangeforge.cli._host",
        lambda _config: HostInfo(
            os=HostOS.DARWIN,
            architecture=Architecture.ARM64,
            apple_silicon=True,
        ),
    )
    scenario_path = ScenarioYamlSerializer().dump(scenario, tmp_path)
    config = _config_path(tmp_path)
    result = CliRunner().invoke(
        app, ["status", str(scenario_path), "--config", str(config)]
    )
    assert result.exit_code == 1, result.output
    assert "Status failed:" in result.output
    assert "UTM backend is unavailable" in result.output
    assert not isinstance(result.exception, BackendOperationError)


@pytest.mark.parametrize(
    ("command", "context_factory", "message"),
    [
        ("provision", "_runtime_context", "Provisioning failed:"),
        ("validate", "_lifecycle_only_context", "Runtime validation failed:"),
    ],
)
def test_runtime_cli_envelopes_backend_operation_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
    context_factory: str,
    message: str,
) -> None:
    def fail_context(*_args: object, **_kwargs: object) -> None:
        raise BackendOperationError("UTM inventory unavailable")

    monkeypatch.setattr(f"rangeforge.cli.{context_factory}", fail_context)
    result = CliRunner().invoke(app, [command, str(tmp_path / "scenario.yaml")])

    assert result.exit_code == 1, result.output
    assert message in result.output
    assert "UTM inventory unavailable" in result.output
    assert not isinstance(result.exception, BackendOperationError)


def test_windows_scenario_provision_is_denied(
    scenario: Scenario, tmp_path: Path
) -> None:
    scenario_path = _windows_scenario_path(scenario, tmp_path)
    config = _config_path(tmp_path)
    result = CliRunner().invoke(
        app, ["provision", str(scenario_path), "--config", str(config)]
    )
    assert result.exit_code == 1
    assert "failed" in result.output


def test_windows_scenario_validate_is_denied(
    scenario: Scenario, tmp_path: Path
) -> None:
    scenario_path = _windows_scenario_path(scenario, tmp_path)
    config = _config_path(tmp_path)
    result = CliRunner().invoke(
        app, ["validate", str(scenario_path), "--config", str(config)]
    )
    assert result.exit_code == 1
    assert "failed" in result.output


def test_windows_platform_generation_is_denied(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        app,
        [
            "generate",
            "--profile",
            "oscp",
            "--mode",
            "standalone",
            "--platform",
            "windows",
            "--difficulty",
            "medium",
            "--seed",
            "1337",
            "--dry-run",
            "--output",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 1
