import hashlib
from pathlib import Path

import pytest
from typer.testing import CliRunner

from rangeforge.cli import app
from rangeforge.host.models import Architecture
from rangeforge.images.cache import ImageCache
from rangeforge.images.models import Checksum, ImageManifest, ImageOS, ImageSource, ImageSourceType
from rangeforge.images.registry import ImageRegistry
from rangeforge.models import Scenario
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


def test_generate_cli_requires_dry_run(tmp_path: Path) -> None:
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
    assert result.exit_code == 2
    assert "dry-run generation only" in result.output
    assert not list(tmp_path.iterdir())


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
    config.write_text(
        f"images:\n  cache_dir: {tmp_path / 'images'}\n", encoding="utf-8"
    )
    result = CliRunner().invoke(app, ["images", "list", "--config", str(config)])
    assert result.exit_code == 0, result.output
    assert "ubuntu-24.04-arm64" in result.output
    assert "ubuntu-24.04-amd64" in result.output


def test_runtime_plan_cli(scenario: Scenario, tmp_path: Path) -> None:
    scenario_path = ScenarioYamlSerializer().dump(scenario, tmp_path)
    config = tmp_path / "config.yaml"
    config.write_text(
        f"images:\n  cache_dir: {tmp_path / 'images'}\n", encoding="utf-8"
    )
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

    result = CliRunner().invoke(
        app, ["images", "verify", manifest.id, "--config", str(config)]
    )
    assert result.exit_code == 0, result.output
    assert "VALID" in result.output
