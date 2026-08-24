"""Direct UTM/utmctl inspection for Apple Silicon hosts."""

import ipaddress
from pathlib import Path

from rangeforge.runtime.backends.base import (
    BackendOperationError,
    CommandResult,
    CommandRunner,
    run_read_only,
)
from rangeforge.runtime.models import BackendCapability, BackendStatus, BackendType, VMState


class UTMBackend:
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
            BackendCapability.VM_LISTING,
            BackendCapability.VM_CLONE,
            BackendCapability.VM_START,
            BackendCapability.VM_STOP,
            BackendCapability.VM_DESTROY,
            BackendCapability.GUEST_IP,
        )
        if not self.available():
            return BackendStatus(
                backend=BackendType.UTM,
                available=False,
                executable=self.executable,
                capabilities=capabilities,
                details=("utmctl was not found in PATH or the UTM application bundle.",),
            )
        result = self.runner((str(self.executable), "list"))
        return BackendStatus(
            backend=BackendType.UTM,
            available=result.returncode == 0,
            executable=self.executable,
            capabilities=capabilities,
            details=(
                ("utmctl inventory is responsive; version was not queried.",)
                if result.returncode == 0
                else (result.stderr or "utmctl is installed but not responsive.",)
            ),
        )

    def list_vms(self) -> tuple[str, ...]:
        if not self.available():
            return ()
        result = self.runner((str(self.executable), "list"))
        if result.returncode != 0:
            return ()
        return tuple(line for line in result.stdout.splitlines() if line)

    def template_exists(self, reference: str) -> bool:
        result = self._command("list")
        if result.returncode != 0:
            raise BackendOperationError(
                result.stderr or "Unable to inspect UTM templates."
            )
        return reference in self._names_from_listing(result.stdout)

    def vm_exists(self, name: str) -> bool:
        return name in self.vm_names()

    def vm_names(self) -> tuple[str, ...]:
        return self._names_from_listing("\n".join(self.list_vms()))

    @staticmethod
    def _names_from_listing(output: str) -> tuple[str, ...]:
        lines = output.splitlines()
        names: list[str] = []
        for line in lines:
            if line.strip().lower() == "uuid status name":
                continue
            parts = line.split(maxsplit=2)
            if len(parts) == 3:
                names.append(parts[2])
        return tuple(names)

    def clone(self, template: str, name: str) -> None:
        self._execute("clone", template, "--name", name)

    def start(self, name: str) -> None:
        self._execute("start", name)

    def stop(self, name: str, *, force: bool = False) -> None:
        self._execute("stop", name, "--force" if force else "--request")

    def delete(self, name: str) -> None:
        self._execute("delete", name)

    def vm_state(self, name: str) -> VMState:
        result = self._command("status", name)
        if result.returncode != 0:
            return VMState.NOT_BUILT if "not found" in result.stderr.lower() else VMState.UNKNOWN
        raw = result.stdout.strip().lower()
        return {
            "started": VMState.RUNNING,
            "running": VMState.RUNNING,
            "starting": VMState.STARTING,
            "stopped": VMState.STOPPED,
            "stopping": VMState.STOPPED,
        }.get(raw, VMState.UNKNOWN)

    def ip_addresses(self, name: str) -> tuple[str, ...]:
        result = self._command("ip-address", name)
        if result.returncode != 0:
            return ()
        addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
        for line in result.stdout.splitlines():
            try:
                address = ipaddress.ip_address(line.strip())
            except ValueError:
                continue
            if not address.is_loopback and not address.is_link_local:
                addresses.append(address)
        addresses.sort(key=lambda address: (address.version != 4, str(address)))
        return tuple(str(address) for address in addresses)

    def _command(self, *arguments: str) -> CommandResult:
        if not self.available() or self.executable is None:
            return CommandResult(returncode=1, stderr="UTM backend is unavailable.")
        return self.runner((str(self.executable), *arguments))

    def _execute(self, *arguments: str) -> None:
        result = self._command(*arguments)
        if result.returncode != 0:
            raise BackendOperationError(
                result.stderr or f"utmctl {' '.join(arguments)} failed."
            )
