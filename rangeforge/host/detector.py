"""Read-only host and executable discovery."""

from __future__ import annotations

import platform
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import ClassVar

from rangeforge.host.models import Architecture, HostInfo, HostOS, RuntimeExecutables

WhichFunction = Callable[[str], str | None]


class HostDetector:
    _OS_ALIASES: ClassVar[dict[str, HostOS]] = {
        "darwin": HostOS.DARWIN,
        "macos": HostOS.DARWIN,
        "mac": HostOS.DARWIN,
        "linux": HostOS.LINUX,
        "windows": HostOS.WINDOWS,
        "win32": HostOS.WINDOWS,
    }
    _ARCHITECTURE_ALIASES: ClassVar[dict[str, Architecture]] = {
        "arm64": Architecture.ARM64,
        "aarch64": Architecture.ARM64,
        "x86_64": Architecture.AMD64,
        "amd64": Architecture.AMD64,
        "x64": Architecture.AMD64,
    }

    def __init__(self, which: WhichFunction = shutil.which) -> None:
        self.which = which

    @classmethod
    def normalize_os(cls, value: str) -> HostOS:
        return cls._OS_ALIASES.get(value.strip().lower(), HostOS.UNSUPPORTED)

    @classmethod
    def normalize_architecture(cls, value: str) -> Architecture:
        return cls._ARCHITECTURE_ALIASES.get(
            value.strip().lower(), Architecture.UNSUPPORTED
        )

    def detect(
        self,
        *,
        system: str | None = None,
        machine: str | None = None,
        executable_overrides: RuntimeExecutables | None = None,
    ) -> HostInfo:
        host_os = self.normalize_os(system or platform.system())
        architecture = self.normalize_architecture(machine or platform.machine())
        discovered = self._detect_executables(host_os)
        overrides = executable_overrides or RuntimeExecutables()
        executables = RuntimeExecutables(
            docker=overrides.docker or discovered.docker,
            vagrant=overrides.vagrant or discovered.vagrant,
            utmctl=overrides.utmctl or discovered.utmctl,
        )
        return HostInfo(
            os=host_os,
            architecture=architecture,
            apple_silicon=(host_os is HostOS.DARWIN and architecture is Architecture.ARM64),
            executables=executables,
        )

    def _detect_executables(self, host_os: HostOS) -> RuntimeExecutables:
        docker = self._which_path("docker")
        vagrant = self._which_path("vagrant")
        utmctl = self._which_path("utmctl")
        if utmctl is None and host_os is HostOS.DARWIN:
            utmctl = self._discover_utm_bundle()
        return RuntimeExecutables(docker=docker, vagrant=vagrant, utmctl=utmctl)

    def _which_path(self, executable: str) -> Path | None:
        result = self.which(executable)
        return Path(result).expanduser() if result else None

    @staticmethod
    def _discover_utm_bundle() -> Path | None:
        candidates = (
            Path("/Applications/UTM.app/Contents/MacOS/utmctl"),
            Path.home() / "Applications/UTM.app/Contents/MacOS/utmctl",
        )
        return next((path for path in candidates if path.is_file()), None)
