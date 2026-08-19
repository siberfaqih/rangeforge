"""RangeForge command-line interface."""

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from rangeforge.config import ConfigError, ConfigLoader, RangeForgeConfig
from rangeforge.generator.scenario import GenerationError, ScenarioGenerator
from rangeforge.host.detector import HostDetector
from rangeforge.host.models import HostInfo
from rangeforge.images.cache import ImageCache
from rangeforge.images.manager import ImageManager, ImageManagerError
from rangeforge.images.registry import ImageRegistry, ImageRegistryError
from rangeforge.images.resolver import ImageResolver
from rangeforge.models import AccessState, DifficultyLevel, Scenario
from rangeforge.primitives.loader import PrimitiveLoader, PrimitiveLoadError
from rangeforge.profiles.loader import ProfileLoader, ProfileLoadError
from rangeforge.runtime.models import RuntimePlan, RuntimeType
from rangeforge.runtime.planner import RuntimePlanner
from rangeforge.runtime.resolver import RuntimeResolver
from rangeforge.serialization.yaml import ScenarioYamlSerializer

app = typer.Typer(help="Deterministic cyber-range scenario generation.", no_args_is_help=True)
images_app = typer.Typer(help="Inspect and manage trusted local image artifacts.")
runtime_app = typer.Typer(help="Build non-destructive runtime plans.")
app.add_typer(images_app, name="images")
app.add_typer(runtime_app, name="runtime")
console = Console()


@app.callback()
def main() -> None:
    """Build deterministic, statically validated training scenarios."""


def _config(path: Path | None) -> RangeForgeConfig:
    return ConfigLoader(path).load()


def _host(config: RangeForgeConfig) -> HostInfo:
    return HostDetector().detect(executable_overrides=config.executable_overrides)


def _manager(config: RangeForgeConfig) -> ImageManager:
    return ImageManager(ImageRegistry.load(), ImageCache(config.images.cache_dir))


def _installed(path: Path | None) -> str:
    return "installed" if path is not None and path.is_file() else "not found"


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


@app.command()
def doctor(
    config: Annotated[
        Path | None,
        typer.Option(help="Optional runtime configuration file."),
    ] = None,
) -> None:
    """Inspect host and runtime dependencies without changing the machine."""
    try:
        loaded_config = _config(config)
        host = _host(loaded_config)
        vm_resolution = RuntimeResolver().resolve(RuntimeType.VM, host)
        cache = ImageCache(loaded_config.images.cache_dir)
    except (ConfigError, OSError) as exc:
        console.print(f"[red]Environment inspection failed: {exc}[/red]")
        raise typer.Exit(code=1) from exc

    console.print("[bold cyan]RangeForge Environment[/bold cyan]\n")
    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_column(style="bold")
    table.add_column()
    table.add_row("Host OS", host.os.display_name)
    table.add_row("Architecture", host.architecture.value)
    table.add_row("Apple Silicon", "yes" if host.apple_silicon else "no")
    console.print(table)

    console.print("\n[bold]Runtime Support[/bold]\n")
    support = Table(show_header=False, box=None, pad_edge=False)
    support.add_column(style="bold")
    support.add_column()
    support.add_row("Docker", _installed(host.executables.docker))
    support.add_row("UTM", _installed(host.executables.utmctl))
    support.add_row("Vagrant", _installed(host.executables.vagrant))
    console.print(support)

    console.print("\n[bold]VM Backend[/bold]\n")
    backend = Table(show_header=False, box=None, pad_edge=False)
    backend.add_column(style="bold")
    backend.add_column()
    backend.add_row(
        "Selected", vm_resolution.backend.value.upper() if vm_resolution.backend else "UNSUPPORTED"
    )
    backend.add_row("Reason", vm_resolution.reason)
    console.print(backend)

    console.print("\n[bold]Image Cache[/bold]\n")
    image_cache = Table(show_header=False, box=None, pad_edge=False)
    image_cache.add_column(style="bold")
    image_cache.add_column()
    image_cache.add_row("Path", str(cache.root))
    image_cache.add_row("Status", cache.status())
    console.print(image_cache)


@images_app.command("list")
def images_list(
    config: Annotated[Path | None, typer.Option(help="Optional configuration file.")] = None,
) -> None:
    """List trusted registry images and local source-artifact state."""
    try:
        manager = _manager(_config(config))
        inspections = manager.list()
    except (ConfigError, ImageRegistryError, OSError) as exc:
        console.print(f"[red]Image listing failed: {exc}[/red]")
        raise typer.Exit(code=1) from exc
    table = Table("Image", "Guest", "Architecture", "Runtime", "Source")
    for inspection in inspections:
        manifest = inspection.manifest
        table.add_row(
            manifest.id,
            f"{manifest.os.distribution} {manifest.os.version}",
            manifest.architecture.value,
            ", ".join(item.value for item in manifest.runtimes),
            inspection.artifact_state.value.upper(),
        )
    console.print(table)


@images_app.command("info")
def images_info(
    image: Annotated[str, typer.Argument(help="Registry image identifier.")],
    config: Annotated[Path | None, typer.Option(help="Optional configuration file.")] = None,
) -> None:
    """Inspect one trusted image manifest and its local readiness."""
    try:
        inspection = _manager(_config(config)).inspect(image)
    except (ConfigError, ImageRegistryError, OSError) as exc:
        console.print(f"[red]Image inspection failed: {exc}[/red]")
        raise typer.Exit(code=1) from exc
    manifest = inspection.manifest
    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_column(style="bold")
    table.add_column()
    table.add_row("Image", manifest.id)
    table.add_row("Guest", f"{manifest.os.distribution} {manifest.os.version}")
    table.add_row("Architecture", manifest.architecture.value)
    table.add_row("Runtime", ", ".join(item.value for item in manifest.runtimes))
    table.add_row("Backends", ", ".join(item.value for item in manifest.backends))
    table.add_row("Vendor", manifest.source.vendor)
    table.add_row("Source artifact", inspection.artifact_state.value.upper())
    for backend, state in inspection.template_states.items():
        table.add_row(f"{backend.value.upper()} template", state.value.upper())
    console.print(table)


@images_app.command("verify")
def images_verify(
    image: Annotated[str, typer.Argument(help="Registry image identifier.")],
    config: Annotated[Path | None, typer.Option(help="Optional configuration file.")] = None,
) -> None:
    """Verify a cached source artifact against its configured SHA-256."""
    try:
        result = _manager(_config(config)).verify(image)
    except (ConfigError, ImageRegistryError, OSError) as exc:
        console.print(f"[red]Image verification failed: {exc}[/red]")
        raise typer.Exit(code=1) from exc
    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_column(style="bold")
    table.add_column()
    table.add_row("Image", result.image_id)
    table.add_row("Expected SHA-256", result.expected_sha256 or "not configured")
    table.add_row("Actual SHA-256", result.actual_sha256 or "not available")
    table.add_row("Status", result.status.value.upper())
    table.add_row("Message", result.message)
    console.print(table)
    if not result.valid:
        raise typer.Exit(code=1)


@images_app.command("import")
def images_import(
    source: Annotated[Path, typer.Argument(help="Local source artifact path.")],
    image: Annotated[str, typer.Option(help="Trusted registry image identifier.")],
    config: Annotated[Path | None, typer.Option(help="Optional configuration file.")] = None,
) -> None:
    """Import a local artifact, verifying it when a checksum is configured."""
    try:
        inspection = _manager(_config(config)).import_image(source, image)
    except (ConfigError, ImageRegistryError, ImageManagerError, OSError) as exc:
        console.print(f"[red]Image import failed: {exc}[/red]")
        raise typer.Exit(code=1) from exc
    console.print(f"Image {image}: {inspection.artifact_state.value.upper()}")
    console.print(f"Cached at: {inspection.artifact_path}")


@images_app.command("prepare")
def images_prepare(
    image: Annotated[str, typer.Argument(help="Registry image identifier.")],
    config: Annotated[Path | None, typer.Option(help="Optional configuration file.")] = None,
) -> None:
    """Report image and template readiness; never install an operating system."""
    try:
        inspection = _manager(_config(config)).inspect(image)
    except (ConfigError, ImageRegistryError, OSError) as exc:
        console.print(f"[red]Image readiness check failed: {exc}[/red]")
        raise typer.Exit(code=1) from exc
    console.print(f"Source artifact: {inspection.artifact_state.value.upper()}")
    for backend, state in inspection.template_states.items():
        console.print(f"{backend.value.upper()} template: {state.value.upper()}")
    console.print("Phase 2A performs readiness checks only; template creation is disabled.")


def _render_runtime_plan(plan: RuntimePlan) -> None:
    console.print("[bold cyan]RangeForge Runtime Plan[/bold cyan]\n")
    console.print(f"[bold]Scenario[/bold]          {plan.scenario_id}\n")
    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_column(style="bold")
    table.add_column()
    table.add_row("Host OS", plan.host.os.display_name)
    table.add_row("Architecture", plan.host.architecture.value)
    table.add_row("Runtime", plan.runtime.runtime.value.upper())
    table.add_row(
        "Backend", plan.runtime.backend.value.upper() if plan.runtime.backend else "none"
    )
    if plan.guest:
        table.add_row("Guest", f"{plan.guest.distribution} {plan.guest.version}")
        table.add_row("Guest architecture", plan.guest.architecture.value)
        table.add_row("Image", plan.guest.image_id or "unresolved")
    if plan.image_status:
        table.add_row("Source status", plan.image_status.source.upper())
        table.add_row("Template status", plan.image_status.template.upper())
    table.add_row("Compatible", "YES" if plan.compatible else "NO")
    table.add_row("Deployable", "YES" if plan.deployable else "NO")
    table.add_row("Next action", plan.next_action)
    console.print(table)
    for issue in plan.issues:
        console.print(f"[red]Issue: {issue}[/red]")


@runtime_app.command("plan")
def runtime_plan(
    scenario_path: Annotated[Path, typer.Argument(help="Generated scenario.yaml path.")],
    runtime: Annotated[
        RuntimeType | None,
        typer.Option(help="Explicit runtime override (docker or vm)."),
    ] = None,
    config: Annotated[Path | None, typer.Option(help="Optional configuration file.")] = None,
) -> None:
    """Resolve a deterministic deployment plan without deploying anything."""
    try:
        loaded_config = _config(config)
        scenario = ScenarioYamlSerializer().load(scenario_path)
        profile = ProfileLoader().load(scenario.scenario.profile)
        primitive_registry = PrimitiveLoader().load()
        image_registry = ImageRegistry.load()
        manager = ImageManager(image_registry, ImageCache(loaded_config.images.cache_dir))
        requirement = profile.runtime_defaults.get(scenario.scenario.platform)
        default_runtime = requirement.default_runtime if requirement else "vm"
        configured_runtime = loaded_config.runtime.default
        selected = runtime or RuntimeType(
            default_runtime if configured_runtime == "auto" else configured_runtime
        )
        plan = RuntimePlanner(
            profile=profile,
            primitive_registry=primitive_registry,
            image_resolver=ImageResolver(image_registry),
            image_manager=manager,
        ).plan(
            scenario,
            requested_runtime=selected,
            host=_host(loaded_config),
        )
    except (
        ConfigError,
        ImageRegistryError,
        ProfileLoadError,
        PrimitiveLoadError,
        OSError,
        ValueError,
    ) as exc:
        console.print(f"[red]Runtime planning failed: {exc}[/red]")
        raise typer.Exit(code=1) from exc
    _render_runtime_plan(plan)


if __name__ == "__main__":
    app()
