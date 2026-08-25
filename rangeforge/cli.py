"""RangeForge command-line interface."""

from dataclasses import dataclass
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.progress import DownloadColumn, Progress, TransferSpeedColumn
from rich.table import Table

from rangeforge.artifacts.cache import ArtifactCache
from rangeforge.artifacts.manager import ArtifactManager, ArtifactManagerError
from rangeforge.artifacts.registry import ArtifactRegistry, ArtifactRegistryError
from rangeforge.config import ConfigError, ConfigLoader, RangeForgeConfig
from rangeforge.cve.loader import CVELoader, CVELoadError
from rangeforge.cve.registry import CVERegistry, CVERegistryError
from rangeforge.generator.scenario import GenerationError, ScenarioGenerator
from rangeforge.host.detector import HostDetector
from rangeforge.host.models import Architecture, HostInfo
from rangeforge.images.cache import ImageCache
from rangeforge.images.downloader import ImageDownloadError
from rangeforge.images.manager import ImageManager, ImageManagerError
from rangeforge.images.registry import ImageRegistry, ImageRegistryError
from rangeforge.images.resolver import ImageResolver
from rangeforge.images.templates import TemplateManager
from rangeforge.models import AccessState, DifficultyLevel, Scenario
from rangeforge.primitives.loader import PrimitiveLoader, PrimitiveLoadError
from rangeforge.profiles.loader import ProfileLoader, ProfileLoadError
from rangeforge.runtime.backends.base import BackendOperationError
from rangeforge.runtime.backends.utm import UTMBackend
from rangeforge.runtime.backends.vagrant import VagrantBackend
from rangeforge.runtime.lifecycle import LifecycleError, ScenarioLifecycle
from rangeforge.runtime.metadata import RuntimeMetadataError
from rangeforge.runtime.models import LifecycleResult, RuntimePlan, RuntimeType, VMBackend
from rangeforge.runtime.planner import RuntimePlanner
from rangeforge.runtime.resolver import RuntimeResolver
from rangeforge.runtime_primitives.artifacts import RuntimeArtifactError
from rangeforge.runtime_primitives.engine import (
    ProvisioningError,
    RuntimePrimitiveEngine,
    RuntimeValidationError,
)
from rangeforge.runtime_primitives.loader import (
    RuntimePrimitiveLoader,
    RuntimePrimitiveLoadError,
)
from rangeforge.runtime_primitives.models import RuntimeValidationResult
from rangeforge.runtime_primitives.registry import RuntimeImplementationError
from rangeforge.runtime_primitives.transport import owned_guest_transport
from rangeforge.serialization.yaml import ScenarioYamlSerializer
from rangeforge.validation.scenario import ScenarioValidator

app = typer.Typer(help="Deterministic cyber-range scenario generation.", no_args_is_help=True)
images_app = typer.Typer(help="Inspect and manage trusted local image artifacts.")
artifacts_app = typer.Typer(help="Inspect and manage trusted CVE service artifacts.")
cve_app = typer.Typer(help="Inspect the curated CVE primitive registry.")
runtime_app = typer.Typer(help="Build non-destructive runtime plans.")
app.add_typer(images_app, name="images")
app.add_typer(artifacts_app, name="artifacts")
app.add_typer(cve_app, name="cve")
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


def _artifact_manager(config: RangeForgeConfig) -> ArtifactManager:
    return ArtifactManager(
        ArtifactRegistry.load(),
        ArtifactCache(config.artifacts.cache_dir),
    )


def _cves(artifacts: ArtifactRegistry | None = None) -> CVERegistry:
    return CVELoader().load(artifacts)


def _installed(path: Path | None) -> str:
    return "installed" if path is not None and path.is_file() else "not found"


@dataclass(frozen=True)
class _RuntimeContext:
    scenario: Scenario
    plan: RuntimePlan
    lifecycle: ScenarioLifecycle
    primitive_engine: RuntimePrimitiveEngine


@dataclass(frozen=True)
class _LifecycleContext:
    scenario: Scenario
    lifecycle: ScenarioLifecycle
    primitive_engine: RuntimePrimitiveEngine


def _runtime_context(
    scenario_path: Path,
    runtime: RuntimeType | None,
    config_path: Path | None,
) -> _RuntimeContext:
    loaded_config = _config(config_path)
    scenario = ScenarioYamlSerializer().load(scenario_path)
    profile = ProfileLoader().load(scenario.scenario.profile)
    primitive_registry = PrimitiveLoader().load()
    validation = ScenarioValidator(profile, primitive_registry).validate(scenario)
    if not validation.valid:
        details = "; ".join((*validation.profile_violations, *validation.errors))
        raise ValueError(f"Scenario static validation failed: {details}")
    image_registry = ImageRegistry.load()
    manager = ImageManager(image_registry, ImageCache(loaded_config.images.cache_dir))
    artifact_manager = _artifact_manager(loaded_config)
    cves = _cves(artifact_manager.registry)
    requirement = profile.runtime_defaults.get(scenario.scenario.platform)
    default_runtime = scenario.scenario.target_runtime or (
        requirement.default_runtime if requirement else "vm"
    )
    configured_runtime = loaded_config.runtime.default
    selected = runtime or RuntimeType(
        default_runtime if configured_runtime == "auto" else configured_runtime
    )
    host = _host(loaded_config)
    plan = RuntimePlanner(
        profile=profile,
        primitive_registry=primitive_registry,
        image_resolver=ImageResolver(image_registry),
        image_manager=manager,
        cve_registry=cves,
        artifact_manager=artifact_manager,
    ).plan(scenario, requested_runtime=selected, host=host)
    lifecycle = ScenarioLifecycle(
        template_manager=TemplateManager(manager),
        host=host,
        utm=UTMBackend(host.executables.utmctl),
        vagrant=VagrantBackend(host.executables.vagrant),
    )
    primitive_engine = RuntimePrimitiveEngine(
        RuntimePrimitiveLoader().load(primitive_registry, cves),
        artifact_manager=artifact_manager,
    )
    return _RuntimeContext(
        scenario=scenario,
        plan=plan,
        lifecycle=lifecycle,
        primitive_engine=primitive_engine,
    )


def _lifecycle_only_context(
    scenario_path: Path,
    config_path: Path | None,
) -> _LifecycleContext:
    loaded_config = _config(config_path)
    scenario = ScenarioYamlSerializer().load(scenario_path)
    profile = ProfileLoader().load(scenario.scenario.profile)
    primitive_registry = PrimitiveLoader().load()
    validation = ScenarioValidator(profile, primitive_registry).validate(scenario)
    if not validation.valid:
        details = "; ".join((*validation.profile_violations, *validation.errors))
        raise ValueError(f"Scenario static validation failed: {details}")
    manager = ImageManager(ImageRegistry.load(), ImageCache(loaded_config.images.cache_dir))
    artifact_manager = _artifact_manager(loaded_config)
    cves = _cves(artifact_manager.registry)
    host = _host(loaded_config)
    lifecycle = ScenarioLifecycle(
        template_manager=TemplateManager(manager),
        host=host,
        utm=UTMBackend(host.executables.utmctl),
        vagrant=VagrantBackend(host.executables.vagrant),
    )
    primitive_engine = RuntimePrimitiveEngine(
        RuntimePrimitiveLoader().load(primitive_registry, cves),
        artifact_manager=artifact_manager,
    )
    return _LifecycleContext(
        scenario=scenario,
        lifecycle=lifecycle,
        primitive_engine=primitive_engine,
    )


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
    validation.add_row("Profile violations", str(len(scenario.validation.profile_violations)))
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
    runtime: Annotated[
        RuntimeType,
        typer.Option(help="Target runtime used for compatibility filtering."),
    ] = RuntimeType.VM,
    architecture: Annotated[
        Architecture,
        typer.Option(help="Target guest architecture used for compatibility filtering."),
    ] = Architecture.ARM64,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Generate scenario metadata without runtime changes."),
    ] = False,
    output: Annotated[
        Path,
        typer.Option(help="Root directory for generated scenario files."),
    ] = Path("output"),
) -> None:
    """Generate and statically validate a standalone scenario definition."""
    _ = dry_run
    try:
        loaded_profile = ProfileLoader().load(profile)
        registry = PrimitiveLoader().load()
        scenario = ScenarioGenerator(loaded_profile, registry).generate(
            mode=mode,
            platform=platform,
            difficulty=difficulty,
            seed=seed,
            runtime=runtime,
            architecture=architecture,
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
    table = Table("Image", "Architecture", "Runtime/Backend", "Acquisition", "Source")
    for inspection in inspections:
        manifest = inspection.manifest
        table.add_row(
            manifest.id,
            manifest.architecture.value,
            ", ".join(
                item.value for item in (*manifest.runtimes, *manifest.backends)
            ),
            manifest.acquisition_method.value.upper(),
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
    table.add_row("Acquisition", manifest.acquisition_method.value.upper())
    table.add_row("SHA-256", manifest.checksum.value or "not configured")
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


@images_app.command("pull")
def images_pull(
    image: Annotated[str, typer.Argument(help="Trusted registry image identifier.")],
    replace_invalid: Annotated[
        bool,
        typer.Option("--replace-invalid", help="Explicitly replace an invalid cached artifact."),
    ] = False,
    config: Annotated[Path | None, typer.Option(help="Optional configuration file.")] = None,
) -> None:
    """Stream a trusted configured image, verify it, and atomically cache it."""
    try:
        manager = _manager(_config(config))
        with Progress(
            "[progress.description]{task.description}",
            DownloadColumn(),
            TransferSpeedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task(f"Pulling {image}", total=None)

            def update(downloaded: int, total: int | None) -> None:
                progress.update(task, completed=downloaded, total=total)

            result = manager.pull(
                image,
                replace_invalid=replace_invalid,
                progress=update,
            )
    except (
        ConfigError,
        ImageRegistryError,
        ImageManagerError,
        ImageDownloadError,
        OSError,
    ) as exc:
        console.print(f"[red]Image pull failed: {exc}[/red]")
        raise typer.Exit(code=1) from exc
    action = "reused" if result.reused else "downloaded"
    console.print(f"Image {image}: READY ({action})")
    console.print(f"Cached at: {result.inspection.artifact_path}")


@images_app.command("import")
def images_import(
    source: Annotated[Path, typer.Argument(help="Local source artifact path.")],
    image: Annotated[str, typer.Option(help="Trusted registry image identifier.")],
    config: Annotated[Path | None, typer.Option(help="Optional configuration file.")] = None,
) -> None:
    """Import a local artifact, verifying it when a checksum is configured."""
    try:
        inspection = _manager(_config(config)).import_image(source, image)
    except (
        ConfigError,
        ImageRegistryError,
        ImageManagerError,
        OSError,
    ) as exc:
        console.print(f"[red]Image import failed: {exc}[/red]")
        raise typer.Exit(code=1) from exc
    console.print(f"Image {image}: {inspection.artifact_state.value.upper()}")
    console.print(f"Cached at: {inspection.artifact_path}")


@images_app.command("prepare")
def images_prepare(
    image: Annotated[str, typer.Argument(help="Registry image identifier.")],
    backend: Annotated[
        VMBackend | None,
        typer.Option(help="Backend override when a manifest supports multiple backends."),
    ] = None,
    template_name: Annotated[
        str | None,
        typer.Option(help="Existing clean backend template/box reference to register."),
    ] = None,
    force: Annotated[
        bool,
        typer.Option("--force", help="Replace stale RangeForge template metadata."),
    ] = False,
    config: Annotated[Path | None, typer.Option(help="Optional configuration file.")] = None,
) -> None:
    """Register a verified, existing clean backend template for cloning."""
    try:
        loaded_config = _config(config)
        host = _host(loaded_config)
        manager = _manager(loaded_config)
        manifest = manager.registry.require(image)
        selected = backend or (manifest.backends[0] if len(manifest.backends) == 1 else None)
        if selected is None:
            raise ImageManagerError("Specify --backend for this multi-backend image.")
        driver = (
            UTMBackend(host.executables.utmctl)
            if selected is VMBackend.UTM
            else VagrantBackend(host.executables.vagrant)
        )
        template = TemplateManager(manager).prepare(
            image,
            selected,
            driver,
            reference=template_name,
            force=force,
        )
    except (
        BackendOperationError,
        ConfigError,
        ImageRegistryError,
        ImageManagerError,
        OSError,
    ) as exc:
        console.print(f"[red]Image preparation failed: {exc}[/red]")
        raise typer.Exit(code=1) from exc
    console.print(f"Template {template.id}: READY")
    console.print(f"Backend reference: {template.reference}")
    console.print(f"Fingerprint: {template.fingerprint}")


@artifacts_app.command("list")
def artifacts_list(
    config: Annotated[Path | None, typer.Option(help="Optional configuration file.")] = None,
) -> None:
    """List only artifacts declared by the trusted local registry."""
    try:
        inspections = _artifact_manager(_config(config)).list()
    except (ConfigError, ArtifactRegistryError, OSError) as exc:
        console.print(f"[red]Artifact listing failed: {exc}[/red]")
        raise typer.Exit(code=1) from exc
    table = Table("Artifact", "Version", "Architecture", "Status")
    for inspection in inspections:
        table.add_row(
            inspection.manifest.id,
            inspection.manifest.version,
            "/".join(item.value for item in inspection.manifest.architectures),
            inspection.state.value.upper(),
        )
    console.print(table)


@artifacts_app.command("info")
def artifacts_info(
    artifact: Annotated[str, typer.Argument(help="Trusted artifact identifier.")],
    config: Annotated[Path | None, typer.Option(help="Optional configuration file.")] = None,
) -> None:
    """Inspect one version-pinned artifact and its checksum readiness."""
    try:
        inspection = _artifact_manager(_config(config)).inspect(artifact)
    except (ConfigError, ArtifactRegistryError, OSError) as exc:
        console.print(f"[red]Artifact inspection failed: {exc}[/red]")
        raise typer.Exit(code=1) from exc
    manifest = inspection.manifest
    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_column(style="bold")
    table.add_column()
    table.add_row("Artifact", manifest.id)
    table.add_row("Type", manifest.type.value)
    table.add_row("Version", manifest.version)
    table.add_row("Vendor", manifest.source.vendor)
    table.add_row("Architecture", ", ".join(item.value for item in manifest.architectures))
    table.add_row("SHA-256", manifest.checksum.value.lower())
    table.add_row("Status", inspection.state.value.upper())
    table.add_row("Cache", str(inspection.path))
    console.print(table)


@artifacts_app.command("verify")
def artifacts_verify(
    artifact: Annotated[str, typer.Argument(help="Trusted artifact identifier.")],
    config: Annotated[Path | None, typer.Option(help="Optional configuration file.")] = None,
) -> None:
    """Verify a cached artifact against its mandatory SHA-256 pin."""
    try:
        result = _artifact_manager(_config(config)).verify(artifact)
    except (ConfigError, ArtifactRegistryError, OSError) as exc:
        console.print(f"[red]Artifact verification failed: {exc}[/red]")
        raise typer.Exit(code=1) from exc
    console.print(f"Artifact: {result.artifact_id}")
    console.print(f"Expected SHA-256: {result.expected_sha256}")
    console.print(f"Actual SHA-256: {result.actual_sha256 or 'not available'}")
    console.print(f"Status: {result.status.value.upper()}")
    if not result.valid:
        raise typer.Exit(code=1)


@artifacts_app.command("pull")
def artifacts_pull(
    artifact: Annotated[str, typer.Argument(help="Trusted artifact identifier.")],
    replace_invalid: Annotated[
        bool,
        typer.Option("--replace-invalid", help="Explicitly replace an invalid cached artifact."),
    ] = False,
    config: Annotated[Path | None, typer.Option(help="Optional configuration file.")] = None,
) -> None:
    """Download only a registry URL, verify it, and atomically cache it."""
    try:
        manager = _artifact_manager(_config(config))
        with Progress(
            "[progress.description]{task.description}",
            DownloadColumn(),
            TransferSpeedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task(f"Pulling {artifact}", total=None)

            def update(downloaded: int, total: int | None) -> None:
                progress.update(task, completed=downloaded, total=total)

            result = manager.pull(
                artifact,
                replace_invalid=replace_invalid,
                progress=update,
            )
    except (
        ArtifactManagerError,
        ArtifactRegistryError,
        ConfigError,
        ImageDownloadError,
        OSError,
    ) as exc:
        console.print(f"[red]Artifact pull failed: {exc}[/red]")
        raise typer.Exit(code=1) from exc
    action = "reused" if result.reused else "downloaded"
    console.print(f"Artifact {artifact}: READY ({action})")
    console.print(f"Cached at: {result.inspection.path}")


@cve_app.command("list")
def cve_list() -> None:
    """List the small, curated CVE set without exploit instructions."""
    try:
        registry = _cves()
    except (CVELoadError, ArtifactRegistryError) as exc:
        console.print(f"[red]CVE registry loading failed: {exc}[/red]")
        raise typer.Exit(code=1) from exc
    table = Table("CVE", "Product", "Architecture", "Runtime")
    for item in registry.all():
        manifest = item.manifest
        table.add_row(
            manifest.cve.id,
            manifest.cve.product,
            "/".join(arch.value for arch in manifest.architectures),
            "/".join(support.runtime.value.upper() for support in manifest.runtime_support),
        )
    console.print(table)


@cve_app.command("info")
def cve_info(
    cve: Annotated[str, typer.Argument(help="CVE ID or curated primitive ID.")],
    config: Annotated[Path | None, typer.Option(help="Optional configuration file.")] = None,
) -> None:
    """Show administrative CVE metadata without payloads or exploit commands."""
    try:
        manager = _artifact_manager(_config(config))
        registry = _cves(manager.registry)
        item = registry.require(cve)
    except (ConfigError, CVELoadError, CVERegistryError, ArtifactRegistryError) as exc:
        console.print(f"[red]CVE inspection failed: {exc}[/red]")
        raise typer.Exit(code=1) from exc
    manifest = item.manifest
    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_column(style="bold")
    table.add_column()
    table.add_row("CVE", manifest.cve.id)
    table.add_row("Product", manifest.cve.product)
    table.add_row("Affected version", manifest.cve.affected_version)
    table.add_row("Training role", manifest.primitive.provides.state.value)
    table.add_row("Profiles", ", ".join(manifest.primitive.profiles))
    table.add_row("Architecture", ", ".join(item.value for item in manifest.architectures))
    table.add_row("Runtime", ", ".join(item.runtime.value for item in manifest.runtime_support))
    for artifact_id in dict.fromkeys(item.id for item in manifest.artifacts):
        state = manager.inspect(artifact_id).state.value.upper()
        table.add_row(f"Artifact {artifact_id}", state)
    console.print(table)


@cve_app.command("validate-registry")
def cve_validate_registry() -> None:
    """Validate CVE IDs, transitions, profiles, artifacts, and runtime files."""
    try:
        registry = _cves()
    except (CVELoadError, ArtifactRegistryError) as exc:
        console.print(f"[red]CVE registry is invalid: {exc}[/red]")
        raise typer.Exit(code=1) from exc
    console.print(
        f"CVE registry version {registry.version}: VALID ({len(registry.all())} primitive(s))"
    )


def _render_runtime_plan(plan: RuntimePlan) -> None:
    console.print("[bold cyan]RangeForge Runtime Plan[/bold cyan]\n")
    console.print(f"[bold]Scenario[/bold]          {plan.scenario_id}\n")
    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_column(style="bold")
    table.add_column()
    table.add_row("Host OS", plan.host.os.display_name)
    table.add_row("Architecture", plan.host.architecture.value)
    table.add_row("Runtime", plan.runtime.runtime.value.upper())
    table.add_row("Backend", plan.runtime.backend.value.upper() if plan.runtime.backend else "none")
    if plan.guest:
        table.add_row("Guest", f"{plan.guest.distribution} {plan.guest.version}")
        table.add_row("Guest architecture", plan.guest.architecture.value)
        table.add_row("Image", plan.guest.image_id or "unresolved")
    if plan.image_status:
        table.add_row("Acquisition", plan.image_status.acquisition.upper())
        table.add_row("Source status", plan.image_status.source.upper())
        table.add_row("Template status", plan.image_status.template.upper())
    for cve in plan.cve_status:
        table.add_row("CVE", cve.cve_id)
        table.add_row("Product", cve.product)
        table.add_row("Expected version", cve.expected_version)
        for artifact in cve.artifacts:
            table.add_row(f"Artifact {artifact.id}", artifact.status.upper())
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
        plan = _runtime_context(scenario_path, runtime, config).plan
    except (
        ConfigError,
        ArtifactRegistryError,
        CVELoadError,
        ImageRegistryError,
        ProfileLoadError,
        PrimitiveLoadError,
        OSError,
        ValueError,
    ) as exc:
        console.print(f"[red]Runtime planning failed: {exc}[/red]")
        raise typer.Exit(code=1) from exc
    _render_runtime_plan(plan)


def _render_lifecycle(result: LifecycleResult) -> None:
    console.print(f"[bold]{result.message}[/bold]")
    metadata = result.metadata
    if metadata is None:
        return
    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_column(style="bold")
    table.add_column()
    table.add_row("Scenario", metadata.scenario_id)
    table.add_row("Runtime", metadata.runtime.value.upper())
    table.add_row("Backend", metadata.backend.value.upper())
    table.add_row("VM", metadata.vm.name)
    table.add_row("State", metadata.vm.state.value.upper())
    table.add_row("Template", metadata.template.name)
    table.add_row("Guest architecture", metadata.guest.architecture.value)
    table.add_row("IP", metadata.guest.ip or "unavailable")
    table.add_row("Management", metadata.guest.management.value.upper())
    table.add_row("Provisioning", metadata.provisioning.state.value.upper())
    table.add_row("Validation", metadata.validation.state.value.upper())
    console.print(table)


def _lifecycle_command(
    operation: str,
    scenario_path: Path,
    runtime: RuntimeType | None,
    config: Path | None,
) -> None:
    try:
        if operation in {"build", "up"}:
            context = _runtime_context(scenario_path, runtime, config)
            context.primitive_engine.compile_plan(context.scenario, context.plan)
            method = getattr(context.lifecycle, operation)
            result = method(context.scenario, scenario_path, context.plan)
        else:
            context_without_plan = _lifecycle_only_context(scenario_path, config)
            method = getattr(context_without_plan.lifecycle, operation)
            result = method(context_without_plan.scenario, scenario_path)
    except (
        ConfigError,
        ArtifactManagerError,
        ArtifactRegistryError,
        CVELoadError,
        CVERegistryError,
        ImageRegistryError,
        ImageManagerError,
        LifecycleError,
        RuntimeMetadataError,
        RuntimePrimitiveLoadError,
        RuntimeImplementationError,
        ProvisioningError,
        ProfileLoadError,
        PrimitiveLoadError,
        OSError,
        ValueError,
    ) as exc:
        console.print(f"[red]{operation.capitalize()} failed: {exc}[/red]")
        raise typer.Exit(code=1) from exc
    _render_lifecycle(result)


def _render_runtime_validation(result: RuntimeValidationResult) -> None:
    console.print("[bold cyan]RangeForge Runtime Validation[/bold cyan]\n")
    console.print(f"[bold]Scenario[/bold]     {result.scenario_id}")
    console.print(f"[bold]Backend[/bold]      {result.backend.value.upper()}\n")
    primitives = Table("Primitive Runtime", "Status")
    for primitive in result.primitives:
        primitives.add_row(primitive.primitive, "VALID" if primitive.valid else "INVALID")
    console.print(primitives)
    flags = Table("Flags", "Status")
    for flag in result.flags:
        flags.add_row(flag.flag, "VALID" if flag.valid else "INVALID")
    console.print(flags)
    negative = Table("Negative Checks", "Observed")
    for check in result.negative_checks:
        negative.add_row(check.name.replace("_", " ").title(), "YES" if check.triggered else "NO")
    console.print(negative)
    console.print(
        f"\n[bold]Runtime Status[/bold]\n\n"
        f"[{'green' if result.valid else 'red'}]{result.status.upper()}[/]"
    )


@app.command()
def build(
    scenario_path: Annotated[Path, typer.Argument(help="Generated scenario.yaml path.")],
    runtime: Annotated[RuntimeType | None, typer.Option(help="Runtime override.")] = None,
    config: Annotated[Path | None, typer.Option(help="Optional configuration file.")] = None,
) -> None:
    """Clone a clean prepared base template without starting the scenario VM."""
    _lifecycle_command("build", scenario_path, runtime, config)


@app.command()
def up(
    scenario_path: Annotated[Path, typer.Argument(help="Generated scenario.yaml path.")],
    runtime: Annotated[RuntimeType | None, typer.Option(help="Runtime override.")] = None,
    config: Annotated[Path | None, typer.Option(help="Optional configuration file.")] = None,
) -> None:
    """Ensure the scenario VM exists, start it, and inspect management readiness."""
    _lifecycle_command("up", scenario_path, runtime, config)


@app.command()
def provision(
    scenario_path: Annotated[Path, typer.Argument(help="Generated scenario.yaml path.")],
    runtime: Annotated[RuntimeType | None, typer.Option(help="Runtime override.")] = None,
    config: Annotated[Path | None, typer.Option(help="Optional configuration file.")] = None,
) -> None:
    """Converge runtime primitives on the owned VM, then validate the result."""
    try:
        context = _runtime_context(scenario_path, runtime, config)
        context.primitive_engine.compile_plan(context.scenario, context.plan)
        running = context.lifecycle.up(context.scenario, scenario_path, context.plan)
        metadata = running.metadata
        if metadata is None:
            raise ProvisioningError("Scenario VM metadata is unavailable after startup.")
        transport = owned_guest_transport(
            context.scenario,
            scenario_path,
            metadata,
            utm=context.lifecycle.utm,
            vagrant=context.lifecycle.vagrant,
        )
        result = context.primitive_engine.provision(
            context.scenario,
            scenario_path,
            context.plan,
            transport,
        )
    except (
        ConfigError,
        ArtifactManagerError,
        ArtifactRegistryError,
        CVELoadError,
        CVERegistryError,
        ImageRegistryError,
        ImageManagerError,
        LifecycleError,
        RuntimeMetadataError,
        RuntimePrimitiveLoadError,
        RuntimeImplementationError,
        RuntimeArtifactError,
        ProvisioningError,
        RuntimeValidationError,
        ProfileLoadError,
        PrimitiveLoadError,
        OSError,
        ValueError,
    ) as exc:
        console.print(f"[red]Provisioning failed: {exc}[/red]")
        raise typer.Exit(code=1) from exc
    _render_runtime_validation(result)
    if not result.valid:
        raise typer.Exit(code=1)


@app.command("validate")
def validate_runtime(
    scenario_path: Annotated[Path, typer.Argument(help="Generated scenario.yaml path.")],
    config: Annotated[Path | None, typer.Option(help="Optional configuration file.")] = None,
) -> None:
    """Validate deployed runtime state separately from static graph validation."""
    try:
        context = _lifecycle_only_context(scenario_path, config)
        refreshed = context.lifecycle.status(context.scenario, scenario_path)
        metadata = refreshed.metadata
        if metadata is None:
            raise RuntimeValidationError("Scenario VM is not built.")
        transport = owned_guest_transport(
            context.scenario,
            scenario_path,
            metadata,
            utm=context.lifecycle.utm,
            vagrant=context.lifecycle.vagrant,
        )
        result = context.primitive_engine.validate(
            context.scenario,
            scenario_path,
            transport,
        )
    except (
        ConfigError,
        ArtifactManagerError,
        ArtifactRegistryError,
        CVELoadError,
        CVERegistryError,
        ImageRegistryError,
        ImageManagerError,
        LifecycleError,
        RuntimeMetadataError,
        RuntimePrimitiveLoadError,
        RuntimeImplementationError,
        RuntimeArtifactError,
        ProvisioningError,
        RuntimeValidationError,
        ProfileLoadError,
        PrimitiveLoadError,
        OSError,
        ValueError,
    ) as exc:
        console.print(f"[red]Runtime validation failed: {exc}[/red]")
        raise typer.Exit(code=1) from exc
    _render_runtime_validation(result)
    if not result.valid:
        raise typer.Exit(code=1)


@app.command()
def status(
    scenario_path: Annotated[Path, typer.Argument(help="Generated scenario.yaml path.")],
    config: Annotated[Path | None, typer.Option(help="Optional configuration file.")] = None,
) -> None:
    """Refresh and display scenario-owned runtime state."""
    _lifecycle_command("status", scenario_path, None, config)


@app.command()
def destroy(
    scenario_path: Annotated[Path, typer.Argument(help="Generated scenario.yaml path.")],
    config: Annotated[Path | None, typer.Option(help="Optional configuration file.")] = None,
) -> None:
    """Destroy only the scenario-owned VM, preserving images and templates."""
    _lifecycle_command("destroy", scenario_path, None, config)


if __name__ == "__main__":
    app()
