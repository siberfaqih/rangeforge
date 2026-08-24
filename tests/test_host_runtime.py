from __future__ import annotations

from pathlib import Path

from rangeforge.host.detector import HostDetector
from rangeforge.host.models import Architecture, HostInfo, HostOS
from rangeforge.images.models import VagrantBox
from rangeforge.models import Primitive
from rangeforge.primitives.registry import PrimitiveRegistry
from rangeforge.runtime.backends.base import CommandResult
from rangeforge.runtime.backends.docker import DockerBackend
from rangeforge.runtime.backends.utm import UTMBackend
from rangeforge.runtime.backends.vagrant import VagrantBackend
from rangeforge.runtime.models import BackendType, RuntimeType, VMBackend
from rangeforge.runtime.resolver import RuntimeResolver


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


def test_utm_backend_lifecycle_command_construction(tmp_path: Path) -> None:
    executable = tmp_path / "utmctl"
    executable.write_text("fixture", encoding="utf-8")
    commands: list[tuple[str, ...]] = []

    def runner(command: tuple[str, ...]) -> CommandResult:
        commands.append(command)
        if command[1] == "list":
            return CommandResult(
                returncode=0,
                stdout="UUID Status Name\nabc stopped rf-base-image\ndef started rf-1337",
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
