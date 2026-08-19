"""Direct UTM/utmctl inspection for Apple Silicon hosts."""

from pathlib import Path

from rangeforge.runtime.backends.base import CommandRunner, run_read_only
from rangeforge.runtime.models import BackendCapability, BackendStatus, BackendType


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
            BackendCapability.VERSION_INSPECTION,
            BackendCapability.VM_LISTING,
        )
        if not self.available():
            return BackendStatus(
                backend=BackendType.UTM,
                available=False,
                executable=self.executable,
                capabilities=capabilities,
                details=("utmctl was not found in PATH or the UTM application bundle.",),
            )
        result = self.runner((str(self.executable), "--version"))
        return BackendStatus(
            backend=BackendType.UTM,
            available=True,
            executable=self.executable,
            version=result.stdout if result.returncode == 0 and result.stdout else None,
            capabilities=capabilities,
            details=(
                ()
                if result.returncode == 0
                else ("utmctl is installed; version reporting is unavailable.",)
            ),
        )

    def list_vms(self) -> tuple[str, ...]:
        if not self.available():
            return ()
        result = self.runner((str(self.executable), "list"))
        if result.returncode != 0:
            return ()
        return tuple(line for line in result.stdout.splitlines() if line)

