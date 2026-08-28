"""Non-destructive Vagrant dependency, version, and box inspection."""

import hashlib
import json
import re
from collections.abc import Iterable
from pathlib import Path

from rangeforge.images.models import VagrantBox
from rangeforge.runtime.backends.base import (
    BackendOperationError,
    CommandResult,
    CommandRunner,
    run_read_only,
)
from rangeforge.runtime.models import BackendCapability, BackendStatus, BackendType, VMState

# Machine-readable ``vagrant status --machine-readable`` state tokens.
#
# The genuine never-created token (``not created`` / the underscore-encoded
# ``not_created``) describes an environment whose machine was never provisioned.
# It is startable (``vagrant up``) and cleanable (``vagrant destroy``), so it
# maps to STOPPED, never UNKNOWN: a freshly built environment must be able to
# converge through up() and destroy().
_VAGRANT_STATE_TOKENS: dict[str, VMState] = {
    "running": VMState.RUNNING,
    "poweroff": VMState.STOPPED,
    "saved": VMState.STOPPED,
    "aborted": VMState.STOPPED,
    "stopped": VMState.STOPPED,
    "not created": VMState.STOPPED,
    "not_created": VMState.STOPPED,
    # Transitional and active-mutation tokens are deliberately not classified
    # as STOPPED: reporting an in-flight start/stop/save as a cleanable state
    # could double-issue lifecycle operations. They fail closed as UNKNOWN.
    "preparing": VMState.UNKNOWN,
    "starting": VMState.UNKNOWN,
    "stopping": VMState.UNKNOWN,
    "saving": VMState.UNKNOWN,
    "restoring": VMState.UNKNOWN,
    "deleting": VMState.UNKNOWN,
    "pausing": VMState.UNKNOWN,
    "resuming": VMState.UNKNOWN,
    "aborting": VMState.UNKNOWN,
}


def map_vagrant_state(tokens: Iterable[str]) -> VMState:
    """Map machine-readable Vagrant state tokens onto the lifecycle state.

    ``RUNNING`` wins when any observed machine reports it. Unrecognized and
    transitional tokens fail closed as ``UNKNOWN`` so no caller infers a
    startable or cleanable power state from data Vagrant did not assert.
    """
    mapped = [
        _VAGRANT_STATE_TOKENS.get(token.strip().lower(), VMState.UNKNOWN)
        for token in tokens
    ]
    if VMState.RUNNING in mapped:
        return VMState.RUNNING
    if VMState.STOPPED in mapped:
        return VMState.STOPPED
    return VMState.UNKNOWN


def vagrant_environment_fingerprint(
    directory: Path, vm_name: str, box: VagrantBox
) -> str:
    """Deterministic identity of a scenario-local Vagrant environment.

    Binds the canonical environment path, expected machine name, generated
    Vagrantfile content, box identity, and provider. A foreign environment
    that replaced the directory or Vagrantfile yields a different fingerprint.
    """
    vagrantfile = directory / "Vagrantfile"
    content = vagrantfile.read_text(encoding="utf-8") if vagrantfile.is_file() else ""
    payload = {
        "environment_path": str(directory.resolve()),
        "vm_name": vm_name,
        "vagrantfile": content,
        "box": box.name,
        "box_version": box.version,
        "provider": box.provider,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


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
        # Reject symlink substitution before writing to the directory.
        resolved = directory.resolve()
        if directory.is_symlink() or (directory.exists() and directory != resolved):
            raise BackendOperationError(
                f"Refusing to prepare Vagrant environment through a symlink: {directory}."
            )
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

    def machine_id(self, directory: Path) -> str | None:
        """Read the provider machine ID from the scenario-local environment.

        Vagrant persists the provider machine ID in
        ``.vagrant/machines/<name>/<provider>/id`` after a machine has been
        booted. It is never available during build, so callers must only
        query it after ``up``.
        """
        machine_root = directory / ".vagrant" / "machines"
        if not machine_root.is_dir():
            return None
        try:
            id_files = list(machine_root.glob("*/*/id"))
        except OSError:
            return None
        if len(id_files) != 1:
            return None
        try:
            machine_id = id_files[0].read_text(encoding="utf-8").strip()
        except OSError:
            return None
        return machine_id or None

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
        return map_vagrant_state(re.findall(r",state,([^\n,]+)", result.stdout))

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
