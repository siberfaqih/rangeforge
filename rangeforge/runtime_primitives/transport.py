"""Trusted guest-command transports derived only from owned runtime metadata."""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import time
from collections.abc import Callable
from pathlib import Path
from typing import Protocol

from rangeforge.models import Scenario
from rangeforge.runtime.backends.base import CommandResult
from rangeforge.runtime.backends.utm import UTMBackend
from rangeforge.runtime.backends.vagrant import VagrantBackend
from rangeforge.runtime.metadata import RuntimeMetadataStore
from rangeforge.runtime.models import RuntimeMetadata, VMBackend

GuestCommandRunner = Callable[[tuple[str, ...], str, float], CommandResult]
GuestFileRunner = Callable[[tuple[str, ...], bytes, float], CommandResult]

_COMPLETION_PATTERN = re.compile(r"^RF_TRANSPORT_COMPLETE:(\d+)$", re.MULTILINE)


def run_guest_command(command: tuple[str, ...], script: str, timeout: float) -> CommandResult:
    try:
        completed = subprocess.run(
            command,
            input=script,
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout,
        )
        return CommandResult(
            returncode=completed.returncode,
            stdout=completed.stdout.strip(),
            stderr=completed.stderr.strip(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return CommandResult(returncode=1, stderr=str(exc))


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
    except (OSError, subprocess.TimeoutExpired) as exc:
        return CommandResult(returncode=1, stderr=str(exc))


class GuestTransport(Protocol):
    def execute(self, script: str, *, timeout: float = 120) -> CommandResult: ...

    def push(self, source: Path, destination: str, *, timeout: float = 300) -> CommandResult: ...


class UTMGuestTransport:
    """Execute root-owned provisioning through the QEMU Guest Agent."""

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


def owned_guest_transport(
    scenario: Scenario,
    scenario_path: Path,
    metadata: RuntimeMetadata,
    *,
    utm: UTMBackend,
    vagrant: VagrantBackend,
) -> GuestTransport:
    """Resolve a transport only after scenario ownership and local resource checks."""
    store = RuntimeMetadataStore(scenario_path)
    store.validate_ownership(scenario, metadata)
    if metadata.vm.name == metadata.template.name:
        raise ValueError("Refusing guest transport to a shared base template.")
    if metadata.backend is VMBackend.UTM:
        if utm.executable is None or not utm.vm_exists(metadata.vm.name):
            raise ValueError("Owned UTM scenario VM is unavailable.")
        return UTMGuestTransport(utm.executable, metadata.vm.name)
    if vagrant.executable is None or not vagrant.environment_exists(store.vagrant_directory):
        raise ValueError("Owned Vagrant scenario environment is unavailable.")
    return VagrantGuestTransport(vagrant.executable, store.vagrant_directory)
