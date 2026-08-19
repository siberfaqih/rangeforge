"""Non-destructive Docker dependency and readiness inspection."""

from pathlib import Path

from rangeforge.host.detector import HostDetector
from rangeforge.host.models import Architecture
from rangeforge.runtime.backends.base import CommandRunner, run_read_only
from rangeforge.runtime.models import BackendCapability, BackendStatus, BackendType


class DockerBackend:
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
                backend=BackendType.DOCKER,
                available=False,
                executable=self.executable,
                capabilities=capabilities,
                details=("Docker executable was not found.",),
            )
        result = self.runner(
            (str(self.executable), "version", "--format", "{{.Server.Version}}|{{.Server.Arch}}")
        )
        if result.returncode != 0:
            return BackendStatus(
                backend=BackendType.DOCKER,
                available=False,
                executable=self.executable,
                capabilities=capabilities,
                details=(result.stderr or "Docker daemon is not ready.",),
            )
        version, _, raw_arch = result.stdout.partition("|")
        architecture = HostDetector.normalize_architecture(raw_arch) if raw_arch else None
        return BackendStatus(
            backend=BackendType.DOCKER,
            available=True,
            executable=self.executable,
            version=version or None,
            architecture=(
                architecture if architecture is not Architecture.UNSUPPORTED else None
            ),
            capabilities=capabilities,
        )

