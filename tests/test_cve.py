from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest
from pydantic import ValidationError

from rangeforge.artifacts.cache import ArtifactCache
from rangeforge.artifacts.manager import ArtifactManager, ArtifactManagerError
from rangeforge.artifacts.models import (
    ArtifactChecksum,
    ArtifactManifest,
    ArtifactSource,
    ArtifactSourceType,
    ArtifactType,
    ArtifactVerification,
)
from rangeforge.artifacts.registry import ArtifactRegistry
from rangeforge.cve.loader import CVELoader
from rangeforge.cve.models import CVEManifest, CVERuntimeSupport
from rangeforge.generator.scenario import ScenarioGenerator
from rangeforge.host.models import Architecture, HostInfo, HostOS
from rangeforge.images.cache import ImageCache
from rangeforge.images.downloader import ImageDownloadError, ProgressCallback
from rangeforge.images.manager import ImageManager
from rangeforge.images.models import VerificationStatus
from rangeforge.images.registry import ImageRegistry
from rangeforge.images.resolver import ImageResolver
from rangeforge.models import (
    AttackGraphSpec,
    DifficultyLevel,
    Scenario,
    SelectedPrimitive,
    TrainingProfile,
)
from rangeforge.primitives.registry import PrimitiveRegistry
from rangeforge.runtime.backends.base import CommandResult
from rangeforge.runtime.metadata import (
    RuntimeMetadataStore,
    scenario_managed_id,
    scenario_vm_name,
)
from rangeforge.runtime.models import (
    BackendStatus,
    BackendType,
    GuestPlan,
    ManagementState,
    RuntimeGuestState,
    RuntimeMetadata,
    RuntimePlan,
    RuntimeResolution,
    RuntimeTemplateReference,
    RuntimeType,
    VMBackend,
    VMIdentity,
    VMState,
)
from rangeforge.runtime.planner import RuntimePlanner
from rangeforge.runtime_primitives.artifacts import RuntimeArtifactStore
from rangeforge.runtime_primitives.engine import RuntimePrimitiveEngine
from rangeforge.runtime_primitives.loader import RuntimePrimitiveLoader
from rangeforge.serialization.yaml import ScenarioYamlSerializer
from rangeforge.validation.scenario import ScenarioValidator

CVE_PATH = (
    "service_enumeration",
    "cve_2023_46604_activemq_rce",
    "credential_discovery_config",
    "linux_sudo_misconfiguration",
)


def _artifact(content: bytes = b"trusted artifact") -> ArtifactManifest:
    return ArtifactManifest(
        id="fixture-service-1.2.3",
        type=ArtifactType.ARCHIVE,
        filename="fixture-service-1.2.3.tar.gz",
        version="1.2.3",
        platforms=("linux",),
        architectures=(Architecture.ARM64, Architecture.AMD64),
        source=ArtifactSource(
            type=ArtifactSourceType.UPSTREAM,
            vendor="Fixture upstream",
            url="https://example.invalid/fixture-service-1.2.3.tar.gz",
        ),
        checksum=ArtifactChecksum(value=hashlib.sha256(content).hexdigest()),
        license="MIT",
    )


class FakeDownloader:
    def __init__(self, content: bytes, *, fail: bool = False) -> None:
        self.content = content
        self.fail = fail
        self.calls = 0

    def download(
        self,
        url: str,
        destination: Path,
        progress: ProgressCallback | None = None,
    ) -> None:
        assert url.startswith("https://")
        self.calls += 1
        destination.write_bytes(self.content[:3])
        if self.fail:
            raise ImageDownloadError("fixture transfer interrupted")
        destination.write_bytes(self.content)
        if progress:
            progress(len(self.content), len(self.content))


def _cve_scenario(
    profile: TrainingProfile,
    registry: PrimitiveRegistry,
) -> Scenario:
    scenario = ScenarioGenerator(profile, registry).generate(
        mode="standalone",
        platform="linux",
        difficulty=DifficultyLevel.EASY,
        seed=85,
        runtime=RuntimeType.VM,
        architecture=Architecture.ARM64,
    )
    assert scenario.attack_graph.path == CVE_PATH
    return scenario


def _plan(scenario: Scenario) -> RuntimePlan:
    host = HostInfo(
        os=HostOS.DARWIN,
        architecture=Architecture.ARM64,
        apple_silicon=True,
    )
    return RuntimePlan(
        scenario_id=scenario.scenario.id,
        host=host,
        runtime=RuntimeResolution(
            runtime=RuntimeType.VM,
            backend=VMBackend.UTM,
            guest_architecture=Architecture.ARM64,
            compatible=True,
            reason="fixture",
        ),
        guest=GuestPlan(
            family="linux",
            distribution="ubuntu",
            version="24.04",
            architecture=Architecture.ARM64,
            image_id="ubuntu-24.04-arm64",
        ),
        compatible=True,
        deployable=True,
        next_action="ready",
    )


def _deployed(scenario: Scenario, scenario_path: Path) -> None:
    RuntimeMetadataStore(scenario_path).save(
        RuntimeMetadata(
            scenario_id=scenario.scenario.id,
            profile=scenario.scenario.profile,
            runtime=RuntimeType.VM,
            backend=VMBackend.UTM,
            vm=VMIdentity(
                name=scenario_vm_name(scenario),
                managed_id=scenario_managed_id(scenario),
                state=VMState.RUNNING,
            ),
            template=RuntimeTemplateReference(
                image_id="ubuntu-24.04-arm64",
                template_id="rf-base-ubuntu-24.04-arm64",
                name="rf-base-ubuntu-24.04-arm64",
                fingerprint="f" * 64,
            ),
            guest=RuntimeGuestState(
                architecture=Architecture.ARM64,
                ip="192.168.64.85",
                management=ManagementState.READY,
            ),
        )
    )


class ReadyArtifactManager:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True)
        self.registry = ArtifactRegistry.load()

    def verify(self, artifact_id: str) -> ArtifactVerification:
        manifest = self.registry.require(artifact_id)
        path = self.root / manifest.filename
        path.write_bytes(b"fixture")
        return ArtifactVerification(
            artifact_id=artifact_id,
            status=VerificationStatus.VALID,
            expected_sha256=manifest.checksum.value.lower(),
            actual_sha256=manifest.checksum.value.lower(),
            path=path,
            message="fixture ready",
        )


class SuccessfulGuest:
    def __init__(self) -> None:
        self.pushed: list[tuple[Path, str]] = []

    def push(self, source: Path, destination: str, *, timeout: float = 300) -> CommandResult:
        self.pushed.append((source, destination))
        return CommandResult(returncode=0)

    def execute(self, script: str, *, timeout: float = 120) -> CommandResult:
        checks = re.findall(r"RF_CHECK ([a-z_]+) [01]", script)
        return CommandResult(
            returncode=0,
            stdout="\n".join(f"RF_CHECK {name} 1" for name in dict.fromkeys(checks)),
        )


def test_cve_manifest_registry_and_id_validation() -> None:
    cves = CVELoader().load()
    item = cves.require("CVE-2023-46604")
    assert cves.version == 1
    assert item.manifest.primitive.id == "cve_2023_46604_activemq_rce"
    assert item.manifest.service.expected_version == "5.18.2"
    assert "cve_base_guest" in item.manifest.validation.expected_checks
    assert 'test "$VERSION_ID" = 24.04' in (
        item.definition_path / "provision.sh"
    ).read_text(encoding="utf-8")
    invalid = item.manifest.model_dump(mode="json")
    invalid["cve"]["id"] = "not-a-cve"
    with pytest.raises(ValidationError, match="CVE"):
        CVEManifest.model_validate(invalid)


def test_profile_architecture_runtime_and_base_compatibility(
    profile: TrainingProfile,
) -> None:
    cves = CVELoader().load()
    arm = cves.compatible_ids(
        profile=profile,
        platform="linux",
        architecture=Architecture.ARM64,
        runtime=RuntimeType.VM,
        backend=VMBackend.UTM,
    )
    amd = cves.compatible_ids(
        profile=profile,
        platform="linux",
        architecture=Architecture.AMD64,
        runtime=RuntimeType.VM,
        backend=VMBackend.VAGRANT,
    )
    docker = cves.compatible_ids(
        profile=profile,
        platform="linux",
        architecture=Architecture.ARM64,
        runtime=RuntimeType.DOCKER,
        backend=None,
    )
    forbidden = profile.model_copy(update={"allowed_techniques": ("service_enumeration",)})
    assert arm == amd == ("cve_2023_46604_activemq_rce",)
    assert docker == ()
    assert cves.compatible_ids(
        profile=forbidden,
        platform="linux",
        architecture=Architecture.ARM64,
        runtime=RuntimeType.VM,
        backend=VMBackend.UTM,
    ) == ()


def test_amd_only_and_docker_vm_compatibility_fixtures() -> None:
    source = CVELoader().load().require("CVE-2023-46604").manifest
    amd_data = source.model_dump(mode="json")
    amd_data["architectures"] = ["amd64"]
    amd_data["primitive"]["architectures"] = ["amd64"]
    amd_data["artifacts"] = [
        item
        for item in amd_data["artifacts"]
        if "amd64" in item["architectures"]
    ]
    amd_only = CVEManifest.model_validate(amd_data)
    assert Architecture.ARM64 not in amd_only.architectures
    assert Architecture.AMD64 in amd_only.architectures

    docker = CVERuntimeSupport(runtime=RuntimeType.DOCKER, backends=())
    both = source.model_copy(update={"runtime_support": (*source.runtime_support, docker)})
    assert {item.runtime for item in both.runtime_support} == {
        RuntimeType.DOCKER,
        RuntimeType.VM,
    }


def test_artifact_manifest_checksum_cache_reuse_and_partial_failure(tmp_path: Path) -> None:
    content = b"trusted artifact"
    manifest = _artifact(content)
    registry = ArtifactRegistry((manifest,))
    downloader = FakeDownloader(content)
    manager = ArtifactManager(registry, ArtifactCache(tmp_path / "cache"), downloader)
    first = manager.pull(manifest.id)
    second = manager.pull(manifest.id)
    assert first.downloaded and second.reused
    assert downloader.calls == 1
    assert manager.verify(manifest.id).valid

    failed = ArtifactManager(
        registry,
        ArtifactCache(tmp_path / "failed"),
        FakeDownloader(content, fail=True),
    )
    with pytest.raises(ImageDownloadError, match="interrupted"):
        failed.pull(manifest.id)
    assert not failed.cache.artifact_path(manifest).with_suffix(".gz.partial").exists()

    bad = ArtifactManager(
        registry,
        ArtifactCache(tmp_path / "bad"),
        FakeDownloader(b"wrong"),
    )
    with pytest.raises(ArtifactManagerError, match="Checksum mismatch"):
        bad.pull(manifest.id)
    assert not bad.cache.artifact_path(manifest).exists()


def test_invalid_artifact_manifest_rejected() -> None:
    invalid = _artifact().model_dump(mode="json")
    invalid["source"]["url"] = "http://untrusted.invalid/artifact"
    invalid["checksum"]["value"] = "bad"
    with pytest.raises(ValidationError):
        ArtifactManifest.model_validate(invalid)


def test_seeded_cve_selection_is_deterministic_and_runtime_filtered(
    profile: TrainingProfile,
    registry: PrimitiveRegistry,
) -> None:
    generator = ScenarioGenerator(profile, registry)
    first = generator.generate(
        mode="standalone",
        platform="linux",
        difficulty=DifficultyLevel.EASY,
        seed=85,
        runtime=RuntimeType.VM,
        architecture=Architecture.ARM64,
    )
    second = generator.generate(
        mode="standalone",
        platform="linux",
        difficulty=DifficultyLevel.EASY,
        seed=85,
        runtime=RuntimeType.VM,
        architecture=Architecture.ARM64,
    )
    docker = generator.generate(
        mode="standalone",
        platform="linux",
        difficulty=DifficultyLevel.EASY,
        seed=85,
        runtime=RuntimeType.DOCKER,
        architecture=Architecture.ARM64,
    )
    assert first == second
    assert first.attack_graph.path == CVE_PATH
    assert "cve_2023_46604_activemq_rce" not in docker.attack_graph.path


def test_runtime_plan_reports_missing_cve_artifacts(
    profile: TrainingProfile,
    registry: PrimitiveRegistry,
    tmp_path: Path,
) -> None:
    scenario = _cve_scenario(profile, registry)
    image_registry = ImageRegistry.load()
    artifact_manager = ArtifactManager(
        ArtifactRegistry.load(),
        ArtifactCache(tmp_path / "artifacts"),
    )

    def ready_backend(_: RuntimeResolution, __: HostInfo) -> BackendStatus:
        return BackendStatus(backend=BackendType.UTM, available=True)

    plan = RuntimePlanner(
        profile=profile,
        primitive_registry=registry,
        image_resolver=ImageResolver(image_registry),
        image_manager=ImageManager(image_registry, ImageCache(tmp_path / "images")),
        cve_registry=CVELoader().load(artifact_manager.registry),
        artifact_manager=artifact_manager,
        backend_status_provider=ready_backend,
    ).plan(scenario, requested_runtime=RuntimeType.VM, host=_plan(scenario).host)
    assert len(plan.cve_status) == 1
    assert plan.cve_status[0].cve_id == "CVE-2023-46604"
    assert {item.status for item in plan.cve_status[0].artifacts} == {"missing"}
    assert not plan.deployable


def test_cve_provision_validation_lock_and_student_redaction(
    profile: TrainingProfile,
    registry: PrimitiveRegistry,
    tmp_path: Path,
) -> None:
    scenario = _cve_scenario(profile, registry)
    scenario_path = ScenarioYamlSerializer().dump(scenario, tmp_path)
    _deployed(scenario, scenario_path)
    cves = CVELoader().load()
    manager = ReadyArtifactManager(tmp_path / "artifacts")
    engine = RuntimePrimitiveEngine(
        RuntimePrimitiveLoader().load(registry, cves),
        artifact_manager=manager,  # type: ignore[arg-type]
    )
    guest = SuccessfulGuest()
    first = engine.provision(scenario, scenario_path, _plan(scenario), guest)
    lock_content = RuntimeArtifactStore(scenario_path).lock_path.read_bytes()
    second = engine.provision(scenario, scenario_path, _plan(scenario), guest)
    assert first.valid and second.valid
    assert RuntimeArtifactStore(scenario_path).lock_path.read_bytes() == lock_content
    assert len(guest.pushed) == 4
    lock = RuntimeArtifactStore(scenario_path).load_lock()
    assert lock is not None
    cve_lock = next(item for item in lock.primitives if item.cve_id)
    assert cve_lock.cve_id == "CVE-2023-46604"
    assert cve_lock.service_version == "5.18.2"
    assert tuple(item.id for item in cve_lock.artifacts) == (
        "apache-activemq-5.18.2",
        "temurin-jre-17.0.19-linux-arm64",
    )
    student = RuntimeArtifactStore(scenario_path).student_text()
    assert "CVE-2023-46604" not in student
    assert "ActiveMQ" not in student
    assert "5.18.2" not in student


def test_cve_graph_transition_remains_static_and_valid(
    profile: TrainingProfile,
    registry: PrimitiveRegistry,
) -> None:
    scenario = _cve_scenario(profile, registry)
    primitives = tuple(registry.require(identifier) for identifier in CVE_PATH)
    graph = AttackGraphSpec(
        start=scenario.attack_graph.start,
        objective=scenario.attack_graph.objective,
        path=CVE_PATH,
        selected_primitives=tuple(SelectedPrimitive.from_primitive(item) for item in primitives),
    )
    draft = scenario.model_copy(update={"attack_graph": graph})
    validation = ScenarioValidator(profile, registry).validate(draft)
    assert validation.valid
    assert scenario.attack_graph.selected_primitives[1].provides.value == "low_priv_shell"
