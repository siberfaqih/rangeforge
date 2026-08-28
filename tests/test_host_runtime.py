from __future__ import annotations

from pathlib import Path

import pytest

from rangeforge.host.detector import HostDetector
from rangeforge.host.models import Architecture, HostInfo, HostOS
from rangeforge.images.models import VagrantBox
from rangeforge.models import Primitive
from rangeforge.primitives.registry import PrimitiveRegistry
from rangeforge.runtime.backends.base import BackendOperationError, CommandResult
from rangeforge.runtime.backends.docker import DockerBackend
from rangeforge.runtime.backends.utm import UTMBackend, parse_utm_state
from rangeforge.runtime.backends.vagrant import VagrantBackend, map_vagrant_state
from rangeforge.runtime.models import BackendType, RuntimeType, VMBackend, VMState
from rangeforge.runtime.resolver import RuntimeResolver

_UUID_A = "11111111-2222-3333-4444-555555555555"
_UUID_B = "66666666-7777-8888-9999-000000000000"


def _host(os: HostOS, architecture: Architecture) -> HostInfo:
    return HostInfo(
        os=os,
        architecture=architecture,
        apple_silicon=os is HostOS.DARWIN and architecture is Architecture.ARM64,
    )


def test_host_os_normalization() -> None:
    assert HostDetector.normalize_os("Darwin") is HostOS.DARWIN
    assert HostDetector.normalize_os("LINUX") is HostOS.LINUX
    assert HostDetector.normalize_os("Windows") is HostOS.WINDOWS
    assert HostDetector.normalize_os("FreeBSD") is HostOS.UNSUPPORTED


def test_architecture_normalization() -> None:
    assert HostDetector.normalize_architecture("aarch64") is Architecture.ARM64
    assert HostDetector.normalize_architecture("arm64") is Architecture.ARM64
    assert HostDetector.normalize_architecture("x86_64") is Architecture.AMD64
    assert HostDetector.normalize_architecture("AMD64") is Architecture.AMD64
    assert HostDetector.normalize_architecture("riscv64") is Architecture.UNSUPPORTED


def test_apple_silicon_detection() -> None:
    detector = HostDetector(which=lambda _: None)
    detected = detector.detect(system="darwin", machine="aarch64")
    assert detected.apple_silicon
    assert detected.os is HostOS.DARWIN
    assert detected.architecture is Architecture.ARM64


def test_host_executable_detection_is_injectable() -> None:
    detector = HostDetector(which=lambda name: f"/tools/{name}")
    detected = detector.detect(system="linux", machine="amd64")
    assert detected.executables.docker == Path("/tools/docker")
    assert detected.executables.vagrant == Path("/tools/vagrant")


def test_darwin_arm64_resolves_to_utm() -> None:
    result = RuntimeResolver().resolve(
        RuntimeType.VM, _host(HostOS.DARWIN, Architecture.ARM64)
    )
    assert result.compatible
    assert result.backend is VMBackend.UTM


def test_x86_64_hosts_resolve_to_vagrant() -> None:
    resolver = RuntimeResolver()
    for host_os in (HostOS.DARWIN, HostOS.LINUX, HostOS.WINDOWS):
        result = resolver.resolve(RuntimeType.VM, _host(host_os, Architecture.AMD64))
        assert result.compatible
        assert result.backend is VMBackend.VAGRANT


def test_docker_explicit_runtime_does_not_select_vm_backend() -> None:
    result = RuntimeResolver().resolve(
        RuntimeType.DOCKER, _host(HostOS.DARWIN, Architecture.ARM64)
    )
    assert result.compatible
    assert result.backend is None
    assert "directly" in result.reason


def test_unsupported_vm_host_fails_explicitly() -> None:
    result = RuntimeResolver().resolve(
        RuntimeType.VM, _host(HostOS.LINUX, Architecture.ARM64)
    )
    assert not result.compatible
    assert result.backend is None
    assert any("Unsupported for VM runtime" in error for error in result.errors)


def test_primitive_architecture_incompatibility(registry: PrimitiveRegistry) -> None:
    original = registry.require("service_enumeration")
    amd64_only: Primitive = original.model_copy(update={"architectures": ("amd64",)})
    result = RuntimeResolver().resolve(
        RuntimeType.VM,
        _host(HostOS.DARWIN, Architecture.ARM64),
        (amd64_only,),
    )
    assert not result.compatible
    assert any("incompatible with architecture" in error for error in result.errors)


def test_backend_dependency_status_models(tmp_path: Path) -> None:
    executable = tmp_path / "tool"
    executable.write_text("fixture", encoding="utf-8")

    docker = DockerBackend(
        executable,
        runner=lambda _: CommandResult(returncode=0, stdout="27.0|aarch64"),
    ).status()
    vagrant = VagrantBackend(
        executable,
        runner=lambda _: CommandResult(returncode=0, stdout="Vagrant 2.4.0"),
    ).status()
    utm = UTMBackend(
        executable,
        runner=lambda _: CommandResult(returncode=0, stdout="utmctl 4.6"),
    ).status()

    assert docker.backend is BackendType.DOCKER and docker.available
    assert docker.architecture is Architecture.ARM64
    assert vagrant.backend is BackendType.VAGRANT and vagrant.available
    assert utm.backend is BackendType.UTM and utm.available


def test_missing_backend_dependency_status() -> None:
    status = VagrantBackend(None).status()
    assert not status.available
    assert "not found" in status.details[0]


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("started", VMState.RUNNING),
        ("running", VMState.RUNNING),
        ("stopped", VMState.STOPPED),
        ("starting", VMState.STARTING),
        ("stopping", VMState.STOPPING),
        ("paused", VMState.UNKNOWN),
        ("suspended", VMState.UNKNOWN),
        ("", VMState.UNKNOWN),
    ],
)
def test_utm_state_token_mapping(raw: str, expected: VMState) -> None:
    assert parse_utm_state(raw) is expected


@pytest.mark.parametrize(
    ("row", "expected_uuid", "expected_state", "expected_name"),
    [
        pytest.param(
            f"{_UUID_A} stopped rf-base-image",
            _UUID_A,
            VMState.STOPPED,
            "rf-base-image",
            id="plain-row",
        ),
        pytest.param(
            f"{_UUID_A} started My VM With Spaces",
            _UUID_A,
            VMState.RUNNING,
            "My VM With Spaces",
            id="name-with-spaces",
        ),
        pytest.param(
            f"{_UUID_A}\tstarted\tTabbed\tName",
            _UUID_A,
            VMState.RUNNING,
            "Tabbed\tName",
            id="tab-separated-name-with-tab",
        ),
        pytest.param(
            f"{_UUID_A} starting rf-1337", _UUID_A, VMState.STARTING, "rf-1337",
            id="starting-state",
        ),
        pytest.param(
            f"{_UUID_A} stopping rf-1337", _UUID_A, VMState.STOPPING, "rf-1337",
            id="stopping-state",
        ),
        pytest.param(
            f"{_UUID_B} suspended rf-1337", _UUID_B, VMState.UNKNOWN, "rf-1337",
            id="unknown-state-token",
        ),
    ],
)
def test_utm_inventory_row_parsing_preserves_names_and_states(
    row: str, expected_uuid: str, expected_state: VMState, expected_name: str
) -> None:
    records = UTMBackend._records_from_listing(row)
    assert len(records) == 1
    record = records[0]
    assert record.uuid == expected_uuid
    assert record.name == expected_name
    assert record.vm_state is expected_state


@pytest.mark.parametrize(
    "header",
    [
        "UUID Status Name",
        "uuid status name",
        "UUID   Status   Name",
        "UUID: Status: Name",
        "UUID:Status:Name",
    ],
)
def test_utm_inventory_header_variants_are_skipped(header: str) -> None:
    listing = (
        f"{header}\n{_UUID_A} stopped rf-base-image\n"
        f"{_UUID_B} started rf-1337"
    )
    records = UTMBackend._records_from_listing(listing)
    assert [record.name for record in records] == ["rf-base-image", "rf-1337"]


@pytest.mark.parametrize(
    ("row", "match"),
    [
        pytest.param("one-field", "Malformed UTM inventory row", id="one-field"),
        pytest.param(
            f"{_UUID_A} stopped", "Malformed UTM inventory row", id="two-fields"
        ),
        pytest.param(
            "not-a-uuid stopped rf-1337",
            "Invalid UTM inventory UUID",
            id="invalid-uuid",
        ),
        pytest.param(
            "11111111-2222-3333-4444-55555555555 stopped rf-1337",
            "Invalid UTM inventory UUID",
            id="truncated-uuid",
        ),
        pytest.param(
            f"{_UUID_A} stopped", "Malformed UTM inventory row", id="missing-name"
        ),
    ],
)
def test_utm_inventory_malformed_rows_fail_closed(row: str, match: str) -> None:
    with pytest.raises(BackendOperationError, match=match):
        UTMBackend._records_from_listing(row)


def test_utm_inventory_blank_lines_are_ignored() -> None:
    listing = f"\n{_UUID_A} stopped rf-base-image\n\n"
    records = UTMBackend._records_from_listing(listing)
    assert [record.name for record in records] == ["rf-base-image"]


def test_utm_inventory_command_failure_is_not_empty_inventory(tmp_path: Path) -> None:
    """A failing ``utmctl list`` raises; it never reads as an empty inventory."""
    executable = tmp_path / "utmctl"
    executable.write_text("fixture", encoding="utf-8")
    backend = UTMBackend(
        executable,
        runner=lambda _: CommandResult(
            returncode=1, stderr="utmctl: unable to connect to the UTM app"
        ),
    )
    with pytest.raises(BackendOperationError, match="unable to connect"):
        backend.inventory()
    with pytest.raises(BackendOperationError):
        backend.find_by_uuid(_UUID_A)
    with pytest.raises(BackendOperationError):
        backend.find_by_name("rf-1337")
    with pytest.raises(BackendOperationError):
        backend.vm_names()


def test_utm_unavailable_backend_inventory_fails_closed() -> None:
    backend = UTMBackend(None)
    with pytest.raises(BackendOperationError, match="UTM backend is unavailable"):
        backend.find_by_name("rf-1337")


@pytest.mark.parametrize(
    ("tokens", "expected"),
    [
        (["running"], VMState.RUNNING),
        (["poweroff"], VMState.STOPPED),
        (["saved"], VMState.STOPPED),
        (["aborted"], VMState.STOPPED),
        (["stopped"], VMState.STOPPED),
        # The genuine never-created token is startable and cleanable.
        (["not created"], VMState.STOPPED),
        (["not_created"], VMState.STOPPED),
        # Transitional and active-mutation tokens fail closed, never STOPPED.
        (["preparing"], VMState.UNKNOWN),
        (["starting"], VMState.UNKNOWN),
        (["stopping"], VMState.UNKNOWN),
        (["saving"], VMState.UNKNOWN),
        (["restoring"], VMState.UNKNOWN),
        (["deleting"], VMState.UNKNOWN),
        (["unheard-of"], VMState.UNKNOWN),
        ([""], VMState.UNKNOWN),
        (["not created", "running"], VMState.RUNNING),
    ],
)
def test_vagrant_state_token_mapping(tokens: list[str], expected: VMState) -> None:
    assert map_vagrant_state(tokens) is expected


@pytest.mark.parametrize(
    ("stdout", "expected"),
    [
        pytest.param(
            "1626000000,default,default,virtualbox,state,not created",
            VMState.STOPPED,
            id="not-created",
        ),
        pytest.param(
            "1626000000,default,default,virtualbox,state,poweroff",
            VMState.STOPPED,
            id="poweroff",
        ),
        pytest.param(
            "1626000000,default,default,virtualbox,state,running",
            VMState.RUNNING,
            id="running",
        ),
        pytest.param(
            "1626000000,default,default,virtualbox,state,preparing",
            VMState.UNKNOWN,
            id="preparing",
        ),
    ],
)
def test_vagrant_vm_state_parses_machine_readable_tokens(
    tmp_path: Path, stdout: str, expected: VMState
) -> None:
    executable = tmp_path / "vagrant"
    executable.write_text("fixture", encoding="utf-8")
    environment = tmp_path / "environment"
    environment.mkdir()
    (environment / "Vagrantfile").write_text("# fixture\n", encoding="utf-8")
    backend = VagrantBackend(
        executable,
        runner=lambda _: CommandResult(returncode=0, stdout=stdout),
    )
    assert backend.vm_state(environment) is expected


def test_utm_backend_lifecycle_command_construction(tmp_path: Path) -> None:
    executable = tmp_path / "utmctl"
    executable.write_text("fixture", encoding="utf-8")
    commands: list[tuple[str, ...]] = []

    def runner(command: tuple[str, ...]) -> CommandResult:
        commands.append(command)
        if command[1] == "list":
            return CommandResult(
                returncode=0,
                stdout=(
                    "UUID Status Name\n"
                    "11111111-2222-3333-4444-555555555555 stopped rf-base-image\n"
                    "66666666-7777-8888-9999-000000000000 started rf-1337"
                ),
            )
        if command[1] == "status":
            return CommandResult(returncode=0, stdout="started")
        if command[1] == "ip-address":
            return CommandResult(returncode=0, stdout="127.0.0.1\n192.168.64.5")
        return CommandResult(returncode=0)

    backend = UTMBackend(executable, runner=runner)
    assert backend.template_exists("rf-base-image")
    backend.clone("rf-base-image", "rf-1337")
    backend.start("rf-1337")
    backend.stop("rf-1337", force=True)
    assert backend.vm_state("rf-1337").value == "running"
    assert backend.ip_addresses("rf-1337") == ("192.168.64.5",)
    backend.delete("rf-1337")
    assert (str(executable), "clone", "rf-base-image", "--name", "rf-1337") in commands
    assert (str(executable), "start", "rf-1337") in commands
    assert (str(executable), "stop", "rf-1337", "--force") in commands
    assert (str(executable), "delete", "rf-1337") in commands


def test_vagrant_backend_lifecycle_command_construction(tmp_path: Path) -> None:
    executable = tmp_path / "vagrant"
    executable.write_text("fixture", encoding="utf-8")
    environment = tmp_path / "environment"
    commands: list[tuple[str, ...]] = []

    def runner(command: tuple[str, ...]) -> CommandResult:
        commands.append(command)
        if command[1:4] == ("box", "list", "--machine-readable"):
            return CommandResult(returncode=0, stdout="1,,box-name,ubuntu/noble64")
        if "status" in command:
            return CommandResult(returncode=0, stdout="1,default,state,running")
        if "ssh-config" in command:
            return CommandResult(returncode=0, stdout="  HostName 192.168.56.10")
        return CommandResult(returncode=0)

    backend = VagrantBackend(executable, runner=runner)
    assert backend.box_exists("ubuntu/noble64")
    vagrantfile = backend.prepare_environment(
        environment, VagrantBox(name="ubuntu/noble64")
    )
    assert "ubuntu/noble64" in vagrantfile.read_text(encoding="utf-8")
    backend.start(environment)
    assert backend.vm_state(environment).value == "running"
    assert backend.ip_addresses(environment) == ("192.168.56.10",)
    backend.stop(environment)
    backend.delete(environment)
    prefix = (str(executable), "--chdir", str(environment))
    assert (*prefix, "up") in commands
    assert (*prefix, "halt") in commands
    assert (*prefix, "destroy", "--force") in commands
