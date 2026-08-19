"""RangeForge command-line interface."""

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from rangeforge.generator.scenario import GenerationError, ScenarioGenerator
from rangeforge.models import AccessState, DifficultyLevel, Scenario
from rangeforge.primitives.loader import PrimitiveLoader, PrimitiveLoadError
from rangeforge.profiles.loader import ProfileLoader, ProfileLoadError
from rangeforge.serialization.yaml import ScenarioYamlSerializer

app = typer.Typer(help="Deterministic cyber-range scenario generation.", no_args_is_help=True)
console = Console()


@app.callback()
def main() -> None:
    """Build deterministic, statically validated training scenarios."""


def _render_scenario(scenario: Scenario, output_path: Path) -> None:
    console.print("[bold cyan]RangeForge[/bold cyan]\n")
    metadata = Table(show_header=False, box=None, pad_edge=False)
    metadata.add_column(style="bold")
    metadata.add_column()
    metadata.add_row("Scenario ID", scenario.scenario.id)
    metadata.add_row("Seed", str(scenario.scenario.seed))
    metadata.add_row("Profile", scenario.scenario.profile_name)
    metadata.add_row("Mode", scenario.scenario.mode)
    metadata.add_row("Platform", scenario.scenario.platform)
    metadata.add_row(
        "Difficulty",
        f"{scenario.scenario.difficulty.value} ({scenario.scenario.difficulty_score:.2f})",
    )
    console.print(metadata)

    console.print("\n[bold]Attack Path[/bold]\n")
    current: AccessState = scenario.attack_graph.start
    console.print(current.value.upper())
    for primitive in scenario.attack_graph.selected_primitives:
        console.print(f"   [cyan]↓ {primitive.id}[/cyan]")
        current = primitive.provides
        console.print(current.value.upper())

    console.print("\n[bold]Validation[/bold]\n")
    validation = Table(show_header=False, box=None, pad_edge=False)
    validation.add_column(style="bold")
    validation.add_column()
    validation.add_row("Graph solvable", "YES" if scenario.validation.solvable else "NO")
    validation.add_row(
        "Profile violations", str(len(scenario.validation.profile_violations))
    )
    validation.add_row("VM deployed", "NO")
    validation.add_row("Scenario YAML", str(output_path))
    console.print(validation)


@app.command()
def generate(
    profile: Annotated[str, typer.Option(help="Training profile identifier.")],
    mode: Annotated[str, typer.Option(help="Scenario mode.")],
    platform: Annotated[str, typer.Option(help="Target lab platform.")],
    difficulty: Annotated[DifficultyLevel, typer.Option(help="Learner difficulty.")],
    seed: Annotated[int, typer.Option(help="Deterministic numeric seed.")],
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Generate metadata only; required in Phase 1."),
    ] = False,
    output: Annotated[
        Path,
        typer.Option(help="Root directory for generated scenario files."),
    ] = Path("output"),
) -> None:
    """Generate and statically validate a standalone scenario definition."""
    if not dry_run:
        console.print("[red]Phase 1 supports dry-run generation only; pass --dry-run.[/red]")
        raise typer.Exit(code=2)
    try:
        loaded_profile = ProfileLoader().load(profile)
        registry = PrimitiveLoader().load()
        scenario = ScenarioGenerator(loaded_profile, registry).generate(
            mode=mode,
            platform=platform,
            difficulty=difficulty,
            seed=seed,
        )
        output_path = ScenarioYamlSerializer().dump(scenario, output)
    except (ProfileLoadError, PrimitiveLoadError, GenerationError, OSError) as exc:
        console.print(f"[red]Scenario generation failed: {exc}[/red]")
        raise typer.Exit(code=1) from exc
    _render_scenario(scenario, output_path)


if __name__ == "__main__":
    app()
