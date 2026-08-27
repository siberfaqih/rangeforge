"""Trusted guest-command transports derived only from owned runtime metadata.

The Linux transports here execute root-owned provisioning through the QEMU
Guest Agent or scenario-specific Vagrant SSH. Windows management is handled
by the dedicated control plane in ``rangeforge.runtime.management``; there is
no parallel Windows backend.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import time
from collections.abc import Callable
from pathlib import Path
from typing import Protocol

from rangeforge.runtime.backends.base import CommandResult
from rangeforge.runtime.guest import ExecutionLanguage

GuestCommandRunner = Callable[[tuple[str, ...], str, float], CommandResult]
GuestFileRunner = Callable[[tuple[str, ...], bytes, float], CommandResult]

_COMPLETION_PATTERN = re.compile(r"^RF_TRANSPORT_COMPLETE:(\d+)$", re.MULTILINE)

# Conventional failure codes used by the process runners so callers can
# distinguish transport timeouts (124) and local failures (125) from guest
# exit statuses.
_TIMEOUT_CODE = 124
_TRANSPORT_ERROR_CODE = 125


def run_guest_command(command: tuple[str, ...], script: str, timeout: float) -> CommandResult:
    try:
        completed = subprocess.run(
            command,
            input=script.encode("utf-8"),
            capture_output=True,
            check=False,
            timeout=timeout,
        )
        # Guest output is decoded explicitly with replacement so arbitrary
        # guest bytes can never raise UnicodeDecodeError through the runner.
        return CommandResult(
            returncode=completed.returncode,
            stdout=completed.stdout.decode("utf-8", errors="replace").strip(),
            stderr=completed.stderr.decode("utf-8", errors="replace").strip(),
        )
    except subprocess.TimeoutExpired:
        return CommandResult(returncode=_TIMEOUT_CODE, stderr="Guest command timed out.")
    except OSError as exc:
        return CommandResult(returncode=_TRANSPORT_ERROR_CODE, stderr=str(exc))


def run_guest_file(command: tuple[str, ...], content: bytes, timeout: float) -> CommandResult:
    try:
        completed = subprocess.run(
            command,
            input=content,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
        return CommandResult(
            returncode=completed.returncode,
            stdout=completed.stdout.decode(errors="replace").strip(),
            stderr=completed.stderr.decode(errors="replace").strip(),
        )
    except subprocess.TimeoutExpired:
        return CommandResult(returncode=_TIMEOUT_CODE, stderr="Guest file transfer timed out.")
    except OSError as exc:
        return CommandResult(returncode=_TRANSPORT_ERROR_CODE, stderr=str(exc))


class GuestTransport(Protocol):
    """Protocol for guest provisioning transports.

    ``language`` is a required attribute: the primitive engine refuses any
    transport that does not explicitly declare its execution language
    (default-deny), so an undeclared transport can never silently execute
    shell manifests.
    """

    language: ExecutionLanguage

    def execute(self, script: str, *, timeout: float = 120) -> CommandResult: ...

    def push(self, source: Path, destination: str, *, timeout: float = 300) -> CommandResult: ...


class UTMGuestTransport:
    """Execute root-owned provisioning through the QEMU Guest Agent."""

    language = ExecutionLanguage.SHELL

    def __init__(
        self,
        executable: Path,
        vm_name: str,
        runner: GuestCommandRunner = run_guest_command,
        file_runner: GuestFileRunner = run_guest_file,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self.executable = executable
        self.vm_name = vm_name
        self.runner = runner
        self.file_runner = file_runner
        self.sleeper = sleeper

    def execute(self, script: str, *, timeout: float = 120) -> CommandResult:
        # UTM 4.7.5 can return empty stdout for a completed guest process. Write
        # results to a root-only guest file and pull it independently instead.
        script_id = hashlib.sha256(script.encode("utf-8")).hexdigest()[:16]
        guest_path = f"/root/.rangeforge-{os.getpid()}-{script_id}.sh"
        result_path = f"/root/.rangeforge-{os.getpid()}-{script_id}.out"
        framed_script = (
            f"rm -f /root/.rangeforge-*.out\n"
            f"exec >{result_path} 2>&1\n"
            "trap 'rm -f -- \"$0\"' EXIT\n"
            "(\n"
            + script
            + "\n)\n"
            "rf_transport_status=$?\n"
            "printf 'RF_TRANSPORT_COMPLETE:%s\\n' \"$rf_transport_status\"\n"
            "exit \"$rf_transport_status\"\n"
        )
        upload_command = (
            str(self.executable),
            "file",
            "push",
            self.vm_name,
            guest_path,
        )
        pull_command = (
            str(self.executable),
            "file",
            "pull",
            self.vm_name,
            guest_path,
        )
        upload = CommandResult(returncode=1, stderr="UTM guest upload did not run.")
        verified = False
        for _ in range(3):
            upload = self.runner(upload_command, framed_script, timeout)
            if upload.returncode != 0:
                return upload
            self.sleeper(1.0)
            pulled = self.runner(pull_command, "", timeout)
            if pulled.returncode == 0 and pulled.stdout == framed_script.strip():
                verified = True
                break
        if not verified:
            return CommandResult(
                returncode=1,
                stderr="UTM guest script upload could not be verified.",
            )
        command = (
            str(self.executable),
            "exec",
            self.vm_name,
            "--cmd",
            "/bin/bash",
            guest_path,
        )
        execution = self.runner(command, "", timeout)
        if execution.returncode != 0:
            return execution
        result_command = (
            str(self.executable),
            "file",
            "pull",
            self.vm_name,
            result_path,
        )
        pulled_result = CommandResult(
            returncode=1,
            stderr="UTM guest result file could not be retrieved.",
        )
        deadline = time.monotonic() + timeout
        while time.monotonic() <= deadline:
            self.sleeper(1.0)
            pulled_result = self.runner(result_command, "", timeout)
            if pulled_result.returncode == 0:
                completion = _COMPLETION_PATTERN.search(pulled_result.stdout)
                if completion is not None:
                    return pulled_result.model_copy(
                        update={"returncode": int(completion.group(1))}
                    )
        return pulled_result.model_copy(
            update={
                "returncode": 1,
                "stderr": (
                    "Guest execution completion marker missing. "
                    + pulled_result.stdout[-2000:]
                ).strip(),
            }
        )

    def push(self, source: Path, destination: str, *, timeout: float = 300) -> CommandResult:
        if not destination.startswith("/var/lib/rangeforge/artifacts/"):
            return CommandResult(
                returncode=1,
                stderr="Artifact destination is outside the lab cache.",
            )
        prepared = self.execute("install -d -o root -g root -m 0700 /var/lib/rangeforge/artifacts")
        if prepared.returncode != 0:
            return prepared
        try:
            content = source.read_bytes()
        except OSError as exc:
            return CommandResult(returncode=1, stderr=str(exc))
        return self.file_runner(
            (str(self.executable), "file", "push", self.vm_name, destination),
            content,
            timeout,
        )


class VagrantGuestTransport:
    """Execute through Vagrant's scenario-specific SSH configuration."""

    language = ExecutionLanguage.SHELL

    def __init__(
        self,
        executable: Path,
        directory: Path,
        runner: GuestCommandRunner = run_guest_command,
    ) -> None:
        self.executable = executable
        self.directory = directory
        self.runner = runner

    def execute(self, script: str, *, timeout: float = 120) -> CommandResult:
        return self.runner(
            (
                str(self.executable),
                "--chdir",
                str(self.directory),
                "ssh",
                "-c",
                "sudo -n /bin/bash -s",
            ),
            script,
            timeout,
        )

    def push(self, source: Path, destination: str, *, timeout: float = 300) -> CommandResult:
        if not destination.startswith("/var/lib/rangeforge/artifacts/"):
            return CommandResult(
                returncode=1,
                stderr="Artifact destination is outside the lab cache.",
            )
        prepared = self.execute("install -d -o root -g root -m 0700 /var/lib/rangeforge/artifacts")
        if prepared.returncode != 0:
            return prepared
        temporary = f"/tmp/{source.name}"
        uploaded = self.runner(
            (
                str(self.executable),
                "--chdir",
                str(self.directory),
                "upload",
                str(source),
                temporary,
            ),
            "",
            timeout,
        )
        if uploaded.returncode != 0:
            return uploaded
        return self.execute(
            f"install -o root -g root -m 0600 -- {temporary} {destination} && rm -f -- {temporary}",
            timeout=timeout,
        )
