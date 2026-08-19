"""Small shared contract for read-only runtime backend inspection."""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Protocol

from rangeforge.models import StrictModel
from rangeforge.runtime.models import BackendStatus


class CommandResult(StrictModel):
    returncode: int
    stdout: str = ""
    stderr: str = ""


CommandRunner = Callable[[tuple[str, ...]], CommandResult]


def run_read_only(command: tuple[str, ...]) -> CommandResult:
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            check=False,
            text=True,
            timeout=5,
        )
        return CommandResult(
            returncode=completed.returncode,
            stdout=completed.stdout.strip(),
            stderr=completed.stderr.strip(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return CommandResult(returncode=1, stderr=str(exc))


class RuntimeBackend(Protocol):
    executable: Path | None

    def available(self) -> bool: ...

    def status(self) -> BackendStatus: ...
