"""Non-destructive Vagrant dependency, version, and box inspection."""

from pathlib import Path

from rangeforge.runtime.backends.base import CommandRunner, run_read_only
from rangeforge.runtime.models import BackendCapability, BackendStatus, BackendType


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

