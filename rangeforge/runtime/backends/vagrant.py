"""Non-destructive Vagrant dependency, version, and box inspection."""

import re
from pathlib import Path

from rangeforge.images.models import VagrantBox
from rangeforge.runtime.backends.base import (
    BackendOperationError,
    CommandResult,
    CommandRunner,
    run_read_only,
)
from rangeforge.runtime.models import BackendCapability, BackendStatus, BackendType, VMState


class VagrantBackend:
    def __init__(
        self,
        executable: Path | None,
        runner: CommandRunner = run_read_only,
    ) -> None:
        self.executable = executable
        self.runner = runner

    def available(self) -> bool:
        return self.executable is not None and self.executable.is_file()

    def status(self) -> BackendStatus:
        capabilities = (
            BackendCapability.DEPENDENCY_DETECTION,
            BackendCapability.VERSION_INSPECTION,
            BackendCapability.IMAGE_INSPECTION,
            BackendCapability.VM_START,
            BackendCapability.VM_STOP,
            BackendCapability.VM_DESTROY,
            BackendCapability.GUEST_IP,
        )
        if not self.available():
            return BackendStatus(
                backend=BackendType.VAGRANT,
                available=False,
                executable=self.executable,
                capabilities=capabilities,
                details=("Vagrant executable was not found.",),
            )
        result = self.runner((str(self.executable), "--version"))
        return BackendStatus(
            backend=BackendType.VAGRANT,
            available=result.returncode == 0,
            executable=self.executable,
            version=result.stdout or None,
            capabilities=capabilities,
            details=(() if result.returncode == 0 else (result.stderr or "Vagrant failed.",)),
        )

    def list_boxes(self) -> tuple[str, ...]:
        if not self.available():
            return ()
        result = self.runner((str(self.executable), "box", "list", "--machine-readable"))
        if result.returncode != 0:
            return ()
        return tuple(line for line in result.stdout.splitlines() if line)

    def template_exists(self, reference: str) -> bool:
        if not self.available() or self.executable is None:
            raise BackendOperationError("Vagrant backend is unavailable.")
        result = self.runner(
            (str(self.executable), "box", "list", "--machine-readable")
        )
        if result.returncode != 0:
            raise BackendOperationError(
                result.stderr or "Unable to inspect Vagrant boxes."
            )
        return any(f",box-name,{reference}" in line for line in result.stdout.splitlines())

    def box_exists(self, name: str) -> bool:
        return any(f",box-name,{name}" in line for line in self.list_boxes())

    def prepare_environment(
        self, directory: Path, box: VagrantBox, vm_name: str = "rangeforge"
    ) -> Path:
        if not re.fullmatch(r"[a-zA-Z0-9_-]+", vm_name):
            raise BackendOperationError("Unsafe Vagrant machine name.")
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "Vagrantfile"
        if path.exists():
            return path
        lines = [
            'Vagrant.configure("2") do |config|',
            f'  config.vm.define "{vm_name}"',
            f'  config.vm.box = "{box.name}"',
        ]
        if box.version:
            lines.append(f'  config.vm.box_version = "{box.version}"')
        if box.provider:
            lines.append(f'  config.vm.provider "{box.provider}"')
        lines.append("end")
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    def environment_exists(self, directory: Path) -> bool:
        return (directory / "Vagrantfile").is_file()

    def start(self, directory: Path) -> None:
        self._execute(directory, "up")

    def stop(self, directory: Path) -> None:
        self._execute(directory, "halt")

    def delete(self, directory: Path) -> None:
        self._execute(directory, "destroy", "--force")

    def vm_state(self, directory: Path) -> VMState:
        if not self.environment_exists(directory):
            return VMState.NOT_BUILT
        result = self._command(directory, "status", "--machine-readable")
        if result.returncode != 0:
            return VMState.UNKNOWN
        states = re.findall(r",state,([^\n,]+)", result.stdout)
        if "running" in states:
            return VMState.RUNNING
        if any(state in {"poweroff", "saved", "aborted"} for state in states):
            return VMState.STOPPED
        return VMState.UNKNOWN

    def ip_addresses(self, directory: Path) -> tuple[str, ...]:
        result = self._command(directory, "ssh-config")
        if result.returncode != 0:
            return ()
        match = re.search(r"^\s*HostName\s+(\S+)\s*$", result.stdout, re.MULTILINE)
        return (match.group(1),) if match else ()

    def _command(self, directory: Path, *arguments: str) -> CommandResult:
        if not self.available() or self.executable is None:
            return CommandResult(returncode=1, stderr="Vagrant backend is unavailable.")
        return self.runner(
            (str(self.executable), "--chdir", str(directory), *arguments)
        )

    def _execute(self, directory: Path, *arguments: str) -> None:
        result = self._command(directory, *arguments)
        if result.returncode != 0:
            raise BackendOperationError(
                result.stderr or f"vagrant {' '.join(arguments)} failed."
            )
