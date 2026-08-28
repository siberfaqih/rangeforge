"""Direct UTM/utmctl inspection for Apple Silicon hosts."""

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path

from rangeforge.runtime.backends.base import (
    BackendOperationError,
    CommandResult,
    CommandRunner,
    run_read_only,
)
from rangeforge.runtime.models import BackendCapability, BackendStatus, BackendType, VMState

# UUID format: 8-4-4-4-12 hex digits.
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


@dataclass(frozen=True)
class UTMInventoryRecord:
    """Typed ``utmctl list`` record retaining UUID, name, and state.

    The UUID is the backend-native resource identity that proves a named VM
    is the exact object RangeForge created; a name alone is never sufficient
    ownership evidence.
    """

    uuid: str
    name: str
    state: str

    @property
    def vm_state(self) -> VMState:
        return parse_utm_state(self.state)


def parse_utm_state(raw: str) -> VMState:
    """Map a raw UTM state token onto the lifecycle state machine.

    ``stopping`` is a distinct transitional state and must never be reported
    as ``STOPPED``. Unknown tokens fail closed as ``UNKNOWN`` so no caller
    infers power state.
    """
    return {
        "started": VMState.RUNNING,
        "running": VMState.RUNNING,
        "starting": VMState.STARTING,
        "stopped": VMState.STOPPED,
        "stopping": VMState.STOPPING,
    }.get(raw.strip().lower(), VMState.UNKNOWN)


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
        """Raw ``utmctl list`` lines; raises on backend command failure.

        A non-zero ``utmctl list`` exit is a backend failure, never an empty
        inventory. Returning ``()`` here would make lifecycle reconciliation
        mistake a transient ``utmctl`` failure for resource absence and let
        destructive paths delete metadata while a live VM remains, so every
        listing consumer fails closed through ``BackendOperationError``.
        """
        result = self._command("list")
        if result.returncode != 0:
            raise BackendOperationError(
                result.stderr or "Unable to inspect UTM inventory."
            )
        return tuple(line for line in result.stdout.splitlines() if line)

    def inventory(self) -> tuple[UTMInventoryRecord, ...]:
        """Parse ``utmctl list`` into typed UUID/name/state records.

        Raises ``BackendOperationError`` when the inventory command fails, so
        callers never interpret a transient failure as an empty inventory.
        """
        return self._records_from_listing("\n".join(self.list_vms()))

    def find_by_uuid(self, uuid: str) -> UTMInventoryRecord | None:
        """Look up exactly one inventory record by backend-native UUID."""
        matches = [record for record in self.inventory() if record.uuid == uuid]
        if len(matches) > 1:
            raise BackendOperationError(
                f"UTM inventory reports multiple resources for UUID '{uuid}'."
            )
        return matches[0] if matches else None

    def find_by_name(self, name: str) -> UTMInventoryRecord | None:
        """Look up inventory records by name; multiple matches are a conflict."""
        matches = [record for record in self.inventory() if record.name == name]
        if len(matches) > 1:
            raise BackendOperationError(
                f"UTM inventory reports multiple resources named '{name}'."
            )
        return matches[0] if matches else None

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
        """Names from the inventory; raises on backend command failure."""
        return self._names_from_listing("\n".join(self.list_vms()))

    @staticmethod
    def _names_from_listing(output: str) -> tuple[str, ...]:
        return tuple(record.name for record in UTMBackend._records_from_listing(output))

    @staticmethod
    def _records_from_listing(output: str) -> tuple[UTMInventoryRecord, ...]:
        """Parse ``utmctl list`` output into typed records, failing closed.

        Header rows are matched case-insensitively and tolerate whitespace
        variation. Every data row must have exactly three fields (UUID, state,
        name) with a well-formed UUID; malformed rows, invalid UUIDs, and
        empty rows fail closed with ``BackendOperationError`` instead of being
        silently dropped. Names are taken as the remainder of the line, so
        names containing spaces are preserved. Duplicate UUIDs or names are
        rejected at lookup time by ``find_by_uuid``/``find_by_name``.
        """
        lines = output.splitlines()
        records: list[UTMInventoryRecord] = []
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            header = stripped.lower()
            if re.fullmatch(r"uuid[\s:]+status[\s:]+name", header):
                continue
            parts = stripped.split(maxsplit=2)
            if len(parts) != 3:
                raise BackendOperationError(
                    f"Malformed UTM inventory row (expected UUID status name): "
                    f"{stripped!r}."
                )
            uuid, state, name = parts
            if not _UUID_RE.fullmatch(uuid):
                raise BackendOperationError(
                    f"Invalid UTM inventory UUID: {uuid!r}."
                )
            if not name.strip():
                raise BackendOperationError(
                    f"UTM inventory row has an empty VM name: {stripped!r}."
                )
            records.append(
                UTMInventoryRecord(uuid=uuid, name=name, state=state)
            )
        return tuple(records)

    def _validate_target(self, name: str, uuid: str | None = None) -> None:
        """Revalidate backend-native identity immediately before mutation.

        utmctl addresses VMs by name, so every name-addressed mutation first
        revalidates that the persisted UUID (when provided) still resolves to
        exactly the expected name. A foreign same-name resource with a
        different UUID is a conflict that must never be mutated.
        """
        if uuid is None:
            return
        record = self.find_by_uuid(uuid)
        if record is None:
            raise BackendOperationError(
                f"Owned UTM scenario VM '{name}' (UUID '{uuid}') is missing from inventory."
            )
        if record.name != name:
            raise BackendOperationError(
                f"UTM resource UUID '{uuid}' is named '{record.name}', not "
                f"'{name}'; ownership conflict."
            )

    def clone(self, template: str, name: str) -> None:
        self._execute("clone", template, "--name", name)

    def start(self, name: str, *, uuid: str | None = None) -> None:
        self._validate_target(name, uuid)
        self._execute("start", name)

    def stop(self, name: str, *, force: bool = False, uuid: str | None = None) -> None:
        self._validate_target(name, uuid)
        self._execute("stop", name, "--force" if force else "--request")

    def delete(self, name: str, *, uuid: str | None = None) -> None:
        self._validate_target(name, uuid)
        self._execute("delete", name)

    def vm_state(self, name: str, *, uuid: str | None = None) -> VMState:
        if uuid is not None:
            record = self.find_by_uuid(uuid)
            if record is None:
                return VMState.MISSING
            if record.name != name:
                raise BackendOperationError(
                    f"UTM resource UUID '{uuid}' is named '{record.name}', not "
                    f"'{name}'; ownership conflict."
                )
            return record.vm_state
        result = self._command("status", name)
        if result.returncode != 0:
            return VMState.NOT_BUILT if "not found" in result.stderr.lower() else VMState.UNKNOWN
        return parse_utm_state(result.stdout)

    def ip_addresses(self, name: str, *, uuid: str | None = None) -> tuple[str, ...]:
        if uuid is not None:
            self._validate_target(name, uuid)
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
