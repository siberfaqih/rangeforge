"""Typed host facts shared by runtime planning and backend inspection."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from rangeforge.models import StrictModel


class HostOS(StrEnum):
    DARWIN = "darwin"
    LINUX = "linux"
    WINDOWS = "windows"
    UNSUPPORTED = "unsupported"

    @property
    def display_name(self) -> str:
        return {
            HostOS.DARWIN: "macOS",
            HostOS.LINUX: "Linux",
            HostOS.WINDOWS: "Windows",
            HostOS.UNSUPPORTED: "Unsupported",
        }[self]


class Architecture(StrEnum):
    ARM64 = "arm64"
    AMD64 = "amd64"
    UNSUPPORTED = "unsupported"


class RuntimeExecutables(StrictModel):
    docker: Path | None = None
    vagrant: Path | None = None
    utmctl: Path | None = None


class HostInfo(StrictModel):
    os: HostOS
    architecture: Architecture
    apple_silicon: bool
    executables: RuntimeExecutables = RuntimeExecutables()

