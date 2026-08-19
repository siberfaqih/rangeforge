from pathlib import Path

from typer.testing import CliRunner

from rangeforge.cli import app


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

