"""Unit and adversarial tests for the Windows/UTM/QGA management transport.

Every test is deterministic and offline: utmctl semantics are simulated by a
directive-driven fake, so no real VM, backend, or network resource is touched.
"""

from __future__ import annotations

import itertools
import re
from collections.abc import Callable
from pathlib import Path
from unittest.mock import patch

import pytest

from rangeforge.host.models import Architecture, HostInfo, HostOS
from rangeforge.images.models import BaseTemplate, TemplateState
from rangeforge.models import Scenario
from rangeforge.runtime.backends.base import CommandResult
from rangeforge.runtime.backends.utm import UTMInventoryRecord
from rangeforge.runtime.guest import ExecutionLanguage, GuestPlatform
from rangeforge.runtime.management import (
    ManagementProbeResult,
    ManagementTransportError,
    _owned_management_transport,
    _run_readiness_probe,
    _WindowsPowerShellTransport,
    effective_guest_platform,
    management_language,
    management_transport_kind,
    owned_guest_transport,
    safe_stage_name,
    validate_management_target,
)
from rangeforge.runtime.metadata import (
    RuntimeMetadataStore,
    ownership_fingerprint,
    scenario_managed_id,
    scenario_vm_name,
)
from rangeforge.runtime.models import (
    ManagementOutcome,
    ManagementResult,
    ManagementState,
    ManagementTransportKind,
    RuntimeGuestState,
    RuntimeMetadata,
    RuntimeType,
    VMBackend,
    VMIdentity,
    VMState,
)
from rangeforge.runtime.models import (
    RuntimeTemplateReference as TemplateRef,
)
from rangeforge.runtime_primitives.transport import UTMGuestTransport
from rangeforge.serialization.yaml import ScenarioYamlSerializer

UTMCTL = Path("/usr/local/bin/utmctl")
VAGRANT = Path("/usr/bin/vagrant")
ROOT = "C:\\ProgramData\\RangeForge\\Transport"
TEMPLATE_NAME = "rf-base-windows-11-arm64"
HOST = HostInfo(os=HostOS.DARWIN, architecture=Architecture.ARM64, apple_silicon=True)
POWERSHELL = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
BOOTSTRAP_PATH = "C:\\Windows\\Temp\\rf-bootstrap.ps1"
WARMUP_PATH = "C:\\Windows\\Temp\\rf-warmup.ps1"
SWEEP_PATH = "C:\\Windows\\Temp\\rf-sweep.ps1"

EXEC_FLAGS = (
    "--cmd",
    POWERSHELL,
    "-NoLogo",
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy",
    "Bypass",
    "-File",
)

# Real UTM 4.7.5 QGA diagnostics observed on the owned clone.
_PULL_MISSING_STDERR = (
    "Error from event: failed to open file: The system cannot find the file specified."
)
_PULL_LOCKED_STDERR = (
    "Error from event: failed to open file: The process cannot access the file "
    "because it is being used by another process."
)


def digest_of(script: str) -> str:
    import hashlib

    return hashlib.sha256(script.encode("utf-8")).hexdigest()[:16]


class FakeGuest:
    """Faithful directive-driven utmctl/QGA simulator for one Windows clone.

    Real UTM 4.7.5 semantics are modeled explicitly:

    * ``utmctl exec`` returns host code 0 immediately; guest work continues
      asynchronously and progresses between subsequent host commands
      (``exec_latency`` host calls after launch).
    * ``utmctl file pull`` reports host code 0 even when the file is missing
      or locked; stdout is empty and stderr carries the QGA diagnostic.
    * Only fixed existing Windows directories exist at start
      (``C:\\Windows\\Temp``); the transport root does not exist on a clean
      clone and pushes never create parent directories.
    * A frame writes ``.out`` (locked briefly) then ``.done``, deletes its
      body and itself, and never touches pulled files.
    * Bootstrap creates the root then self-deletes; cleanup scripts remove
      every ``rf-<digest>.*`` sibling and themselves.

    Body directives (never produced by RangeForge itself):
      ``#FAKE:NO_DONE``          completion marker is never written
      ``#FAKE:NO_RESULT``        marker written but the result file is not
      ``#FAKE:HUGE``             result file exceeds the output bound
      ``#FAKE:KEEP_FILES``       frame does not delete its body/frame files
      ``#FAKE:DONE_DIGEST:<d>``  marker carries a spoofed digest
      ``#FAKE:OUTPUT:<text>``    guest stdout payload
      ``#FAKE:EMPTY_OUT``        guest produces a genuinely empty .out file
      ``exit <n>``               guest exit status

    Constructor knobs:
      ``fail_clean=True``         cleanup scripts remove nothing
      ``mutate_body_pulls``       corrupt body round-trip verification
      ``push_error_stderr``       every push fails with code 0 + that stderr
      ``locked_push_paths``       pushes to these paths hit the real locked-
                                  file conflict (code 0 + locked diagnostic,
                                  nothing stored)
      ``stuck_bootstrap``         root is created but the bootstrap script
                                  never self-deletes
      ``weird_pull_stderr``       every pull returns unrecognized code-0
                                  stderr (TRANSIENT)
      ``exec_rpc_stderr``         the first N execs return the real cold-
                                  boot RPC-timeout diagnostic and queue
                                  NOTHING (provably not delivered);
                                  subsequent execs submit cleanly and queue
                                  with normal latency
      ``unknown_exec_stderr``     every exec returns code 0 with an
                                  unrecognized diagnostic and queues nothing
                                  (ambiguous → fail closed)
      ``never_execute``           execs use clean code 0 submission (queued)
                                  but the guest action never runs
      ``local_exec_failure``      every exec returns the runner-synthetic
                                  code 125 (definite local invocation failure)
      ``transient_pulls_remaining first N pulls report the real locked-file
                                  diagnostic regardless of file state
      ``transient_done_pulls``    first N pulls of any ``.done`` marker file
                                  report the locked diagnostic (models
                                  TRANSIENT during the queued-execution
                                  window)
      ``done_poison`` / ``forced_stage_output`` override guest marker/output
                                  content for adversarial tests.
    """

    def __init__(
        self,
        *,
        clock_step: float = 0.0,
        mutate_body_pulls: bool = False,
        exec_latency: int = 2,
        fail_clean: bool = False,
        push_error_stderr: str | None = None,
        locked_push_paths: set[str] | None = None,
        stuck_bootstrap: bool = False,
        weird_pull_stderr: bool = False,
        exec_rpc_stderr: int = 0,
        unknown_exec_stderr: bool = False,
        never_execute: bool = False,
        local_exec_failure: bool = False,
        transient_pulls_remaining: int = 0,
        transient_done_pulls: int = 0,
        locked_pull_paths: set[str] | None = None,
        fail_sweep: bool = False,
    ) -> None:
        self.commands: list[tuple[str, ...]] = []
        self.uploads: list[tuple[str, bytes]] = []
        self.files: dict[str, bytes] = {}
        self.directories: set[str] = {"C:\\Windows\\Temp"}
        self.locked: set[str] = set()
        self.clock_value = 0.0
        self.clock_step = clock_step
        self.mutate_body_pulls = mutate_body_pulls
        self.exec_latency = exec_latency
        self.fail_clean = fail_clean
        self.push_error_stderr = push_error_stderr
        self.locked_push_paths = locked_push_paths or set()
        self.stuck_bootstrap = stuck_bootstrap
        self.weird_pull_stderr = weird_pull_stderr
        self.exec_rpc_stderr_remaining = exec_rpc_stderr
        self.unknown_exec_stderr = unknown_exec_stderr
        self.never_execute = never_execute
        self.local_exec_failure = local_exec_failure
        self.transient_pulls_remaining = transient_pulls_remaining
        self.transient_done_pulls = transient_done_pulls
        self.locked_pull_paths = locked_pull_paths or set()
        self.fail_sweep = fail_sweep
        self.exec_targets: list[str] = []
        self._submitted_frame_digests: set[str] = set()
        self.done_poison: bytes | None = None
        self.forced_stage_output: str | None = None
        self._pending: list[tuple[int, Callable[[], None]]] = []
        self._host_calls = 0
        # Concrete (body, out, done) paths parsed from the most recently
        # executed frame; used by generation-coherence assertions.
        self.last_frame_paths: tuple[str, str, str] | None = None

    def clock(self) -> float:
        self.clock_value += self.clock_step
        return self.clock_value

    def sleeper(self, seconds: float) -> None:
        self.clock_value += seconds

    def _frame_submitted(self, done_path: str) -> bool:
        match = re.search(r"rf-([0-9a-f]{16})\.done$", done_path)
        return bool(match and match.group(1) in self._submitted_frame_digests)

    def residue(self) -> set[str]:
        """Every transport-root file left in the guest filesystem."""
        return {path for path in self.files if path.startswith(ROOT + "\\")}

    def drain(self) -> None:
        """Test utility: run every pending asynchronous guest action now."""
        while self._pending:
            _, action = self._pending.pop(0)
            action()

    def _schedule(self, action: Callable[[], None], *, extra: int = 0) -> None:
        self._pending.append((self.exec_latency + extra, action))

    def _tick(self) -> None:
        """Guest progress between host commands."""
        self._host_calls += 1
        still_pending: list[tuple[int, Callable[[], None]]] = []
        for countdown, action in self._pending:
            countdown -= 1
            if countdown <= 0:
                action()
            else:
                still_pending.append((countdown, action))
        self._pending = still_pending

    def run(self, command: tuple[str, ...], script: str, timeout: float) -> CommandResult:
        self.commands.append(command)
        self._tick()
        assert command[1:3] != ("file", "push"), "pushes use the file runner"
        if command[1:3] == ("file", "pull"):
            return self._pull(command[-1])
        if command[1] == "exec":
            return self._launch_exec(command[-1])
        return CommandResult(returncode=0)

    def _launch_exec(self, guest_path: str) -> CommandResult:
        """Model real UTM exec submission semantics.

        * The first ``exec_rpc_stderr`` execs return the real cold-boot
          RPC-timeout diagnostic and provably queue nothing; the transport
          may safely resubmit after verifying presence.
        * Later (or all, with ``unknown_exec_stderr``) unrecognized code-0
          stderr results are ambiguous and queue nothing.
        * Clean code-0 submissions queue the guest action, which runs after
          ``exec_latency`` subsequent host commands — or never, with
          ``never_execute``.
        * ``local_exec_failure`` models the runner-synthetic code 125.
        """
        self.exec_targets.append(guest_path)
        if self.local_exec_failure:
            return CommandResult(
                returncode=125,
                stdout="",
                stderr="OSError: could not spawn utmctl process.",
            )
        if self.exec_rpc_stderr_remaining > 0:
            self.exec_rpc_stderr_remaining -= 1
            return CommandResult(
                returncode=0,
                stdout="",
                stderr="Error from event: Timed out waiting for RPC.",
            )
        if self.unknown_exec_stderr:
            return CommandResult(
                returncode=0,
                stdout="",
                stderr="Error from event: unclassified exec failure.",
            )
        if not self.never_execute:
            self._launch(guest_path)
        return CommandResult(returncode=0)

    def file_run(
        self, command: tuple[str, ...], content: bytes, timeout: float
    ) -> CommandResult:
        self.commands.append(command)
        self._tick()
        assert command[1:3] == ("file", "push")
        if self.push_error_stderr is not None:
            # Real UTM 4.7.5: host code 0 with a diagnostic on stderr and
            # nothing stored.
            return CommandResult(returncode=0, stdout="", stderr=self.push_error_stderr)
        if command[-1] in self.locked_push_paths and command[-1] in self.files:
            # Locked-inode conflict: the resident file holds the handle.
            return CommandResult(returncode=0, stdout="", stderr=_PULL_LOCKED_STDERR)
        parent = command[-1].rsplit("\\", 1)[0]
        if parent not in self.directories:
            return CommandResult(returncode=1, stderr="parent directory is missing")
        self.uploads.append((command[-1], content))
        self.files[command[-1]] = content
        return CommandResult(returncode=0)

    def _pull(self, guest_path: str) -> CommandResult:
        if self.weird_pull_stderr:
            return CommandResult(
                returncode=0,
                stdout="",
                stderr="Error from event: unclassified guest failure.",
            )
        if guest_path in self.locked_pull_paths:
            # Permanently QGA-locked inode: every pull reports the locked
            # diagnostic regardless of stored content.
            return CommandResult(returncode=0, stdout="", stderr=_PULL_LOCKED_STDERR)
        if self.transient_pulls_remaining > 0:
            # Real cold-QGA behavior: freshly pushed files can read back as
            # locked for the first pulls regardless of eventual state.
            self.transient_pulls_remaining -= 1
            return CommandResult(returncode=0, stdout="", stderr=_PULL_LOCKED_STDERR)
        if (
            guest_path.endswith(".done")
            and self.transient_done_pulls > 0
            and self._frame_submitted(guest_path)
        ):
            # TRANSIENT while a submitted frame has not written/locked its
            # marker yet; never fires before that frame exists.
            self.transient_done_pulls -= 1
            return CommandResult(returncode=0, stdout="", stderr=_PULL_LOCKED_STDERR)
        if guest_path in self.locked:
            return CommandResult(returncode=0, stdout="", stderr=_PULL_LOCKED_STDERR)
        data = self.files.get(guest_path)
        if data is None:
            return CommandResult(returncode=0, stdout="", stderr=_PULL_MISSING_STDERR)
        stdout = data.decode("utf-8")
        if self.mutate_body_pulls and guest_path.endswith(".body.ps1"):
            stdout += "X"
        return CommandResult(returncode=0, stdout=stdout)

    def _launch(self, guest_path: str) -> None:
        bootstrap_match = re.search(r"rf-bootstrap(-r\d+)?\.ps1$", guest_path)
        warmup_match = re.search(r"rf-warmup(-r\d+)?\.ps1$", guest_path)
        sweep_match = re.search(r"rf-sweep(-r\d+)?\.ps1$", guest_path)
        clean = re.search(r"rf-([0-9a-f]{16})(?:-r\d+)?\.clean\.ps1$", guest_path)
        frame = re.search(r"rf-([0-9a-f]{16})(?:-r\d+)?\.frame\.ps1$", guest_path)
        if warmup_match:
            def self_delete() -> None:
                # The disposable warmup probe only deletes itself.
                self.files.pop(guest_path, None)

            self._schedule(self_delete)
            return
        if sweep_match:
            def sweep_root() -> None:
                if self.fail_sweep:
                    return
                # Faithful sweep: remove every rf-* entry inside ONLY the
                # Transport root. Permanently QGA-locked inodes cannot be
                # deleted even with -Force, so locked paths survive.
                for name in list(self.files):
                    if name.startswith(ROOT + "\\rf-") and (
                        name not in self.locked_pull_paths
                    ):
                        del self.files[name]
                self.files.pop(guest_path, None)

            self._schedule(sweep_root)
            return
        if bootstrap_match:
            def create_root() -> None:
                self.directories.add(ROOT)
                if not self.stuck_bootstrap:
                    # A locked/stuck bootstrap file must never be mistaken
                    # for absent; the transport keeps polling until MISSING.
                    self.files.pop(guest_path, None)

            self._schedule(create_root)
            return
        if clean:
            digest = clean.group(1)

            def remove_digest_files() -> None:
                if self.fail_clean:
                    return
                # Prefix wildcard, matching the real cleanup script: removes
                # base names and escalated -rN generation variants alike.
                # A permanently QGA-locked inode cannot be deleted even with
                # -Force, so locked paths survive the glob (real behavior).
                prefix = f"{ROOT}\\rf-{digest}"
                for name in list(self.files):
                    if name.startswith(prefix) and name not in self.locked_pull_paths:
                        del self.files[name]

            self._schedule(remove_digest_files)
            return
        assert frame, f"unexpected exec target: {guest_path}"
        digest = frame.group(1)
        self._submitted_frame_digests.add(digest)
        # Faithful frame execution: parse the exact single-quoted literals
        # the production frame embeds, so an escalated body name or any
        # generation mismatch in the embedded paths is what actually runs.
        frame_text = self.files.get(guest_path, b"").decode("utf-8-sig")
        body_literal = re.search(r"\$rfBodyPath = '([^']+)'", frame_text)
        result_literal = re.search(r"\$rfResultPath = '([^']+)'", frame_text)
        done_literal = re.search(r"\$rfDonePath = '([^']+)'", frame_text)
        assert body_literal and result_literal and done_literal, (
            "uploaded frame must embed concrete body/result/done literals"
        )
        body_path = body_literal.group(1)
        out_path = result_literal.group(1)
        done_path = done_literal.group(1)
        self.last_frame_paths = (body_path, out_path, done_path)
        body = self.files.get(body_path, b"").decode("utf-8-sig")
        exit_match = re.search(r"^exit (\d+)\s*$", body, re.MULTILINE)
        exit_code = int(exit_match.group(1)) if exit_match else 0
        output = "ok\n"
        staged = re.search(r"-LiteralPath '([^']+)'", body)
        if "RF_STAGED" in body and staged:
            import hashlib

            data = self.files.get(staged.group(1), b"")
            output = f"RF_STAGED:{len(data)}:{hashlib.sha256(data).hexdigest()}\n"
            if self.forced_stage_output is not None:
                output = self.forced_stage_output
        elif "RF_PROBE" in body:
            # Canonical response of a real Windows ARM64 PowerShell 5.1 guest.
            output = "RF_PROBE ps=5 arch=ARM64\n"
        elif "RF_READ:" in body and staged:
            data = self.files.get(staged.group(1), b"")
            output = "RF_READ:" + data.decode("ascii", errors="replace")
        elif "RF_GONE" in body and staged:
            target = staged.group(1)
            self.files.pop(target, None)
            still_present = target in self.files
            output = f"RF_GONE:{0 if still_present else 1}\n"
        elif "RF_CLEAN" in body:
            # Same exclusion rule as the fixed probe script: only this
            # operation's own digest prefix is excluded, derived from the
            # body path ($PSCommandPath in the guest) and stripping the
            # escalated -rN suffix. Both gen-0 and escalated -rN variants
            # of the operation's own files are excluded by the same prefix
            # pattern, so an escalated workspace check never counts its own
            # in-flight files as residue.
            stem = body_path.rsplit("\\", 1)[-1].removesuffix(".ps1")
            derived = re.sub(r"^rf-|(-r\d+)?\.body$", "", stem)
            own_pattern = re.compile(rf"rf-{re.escape(derived)}(?:-r\d+)?\.")
            count = sum(
                1
                for name in self.files
                if name.startswith(ROOT + "\\")
                and own_pattern.match(name.rsplit("\\", 1)[-1]) is None
            )
            output = f"RF_CLEAN:{count}\n"
        custom = re.search(r"^#FAKE:OUTPUT:(.*)$", body, re.MULTILINE)
        if custom:
            output = custom.group(1) + "\n"
        if "#FAKE:HUGE" in body:
            output = "x" * 150_000
        done_digest = digest
        spoofed = re.search(r"#FAKE:DONE_DIGEST:([0-9a-f]{16})", body)
        if spoofed:
            done_digest = spoofed.group(1)

        def write_result() -> None:
            if "#FAKE:NO_RESULT" not in body:
                if "#FAKE:EMPTY_OUT" in body:
                    # A valid guest script may produce an empty .out file.
                    self.files[out_path] = b""
                else:
                    # Out-File -Encoding UTF8 writes a UTF-8 BOM.
                    self.files[out_path] = output.encode("utf-8-sig")
                self.locked.add(out_path)

        def write_marker_and_self_delete() -> None:
            self.locked.discard(out_path)
            if "#FAKE:NO_DONE" not in body:
                marker = self.done_poison or (
                    f"RF_MGMT_COMPLETE:{exit_code}:{done_digest}\n"
                ).encode("ascii")
                self.files[done_path] = marker
            if "#FAKE:KEEP_FILES" not in body:
                self.files.pop(body_path, None)
                self.files.pop(guest_path, None)

        self._schedule(write_result)
        self._schedule(write_marker_and_self_delete, extra=1)


def transport(fake: FakeGuest, vm_name: str = "rf-scenario") -> _WindowsPowerShellTransport:
    return _WindowsPowerShellTransport(
        executable=UTMCTL,
        vm_name=vm_name,
        runner=fake.run,
        file_runner=fake.file_run,
        sleeper=fake.sleeper,
        clock=fake.clock,
    )


class RecordingUTM:
    def __init__(self, vms: dict[str, VMState]) -> None:
        self.executable = UTMCTL
        self.vms = vms
        self.calls: list[str] = []
        # Deterministic UUID per VM name so UUID lookups work without caller
        # plumbing. Tests that need a specific UUID pass it explicitly.
        self.uuid_by_name: dict[str, str] = {
            name: f"uuid-{name}" for name in vms
        }

    def vm_exists(self, name: str) -> bool:
        self.calls.append("vm_exists")
        return name in self.vms

    def vm_state(self, name: str) -> VMState:
        self.calls.append("vm_state")
        return self.vms.get(name, VMState.NOT_BUILT)

    def find_by_name(self, name: str) -> UTMInventoryRecord | None:
        self.calls.append("find_by_name")
        if name not in self.vms:
            return None
        return UTMInventoryRecord(
            uuid=self.uuid_by_name.get(name, f"uuid-{name}"),
            name=name,
            state=self.vms[name].value,
        )

    def find_by_uuid(self, uuid: str) -> UTMInventoryRecord | None:
        self.calls.append("find_by_uuid")
        for name, candidate in self.uuid_by_name.items():
            if candidate == uuid:
                return UTMInventoryRecord(
                    uuid=uuid,
                    name=name,
                    state=self.vms[name].value,
                )
        return None


class RecordingVagrant:
    def __init__(self, exists: bool, state: VMState = VMState.RUNNING) -> None:
        self.executable = VAGRANT
        self.exists = exists
        self.state = state
        self.calls: list[str] = []

    def environment_exists(self, directory: Path) -> bool:
        self.calls.append("environment_exists")
        return self.exists

    def vm_state(self, directory: Path) -> VMState:
        self.calls.append("vm_state")
        return self.state


class StubTemplates:
    def __init__(self, template: BaseTemplate | None) -> None:
        self.template = template

    def require_ready(self, image_id: str, backend: VMBackend) -> BaseTemplate:
        assert self.template is not None
        return self.template


def _stub_templates(metadata: RuntimeMetadata | None) -> StubTemplates | None:
    """Build a trusted-template stub matching persisted metadata exactly."""
    if metadata is None:
        return None
    return StubTemplates(
        BaseTemplate(
            id=metadata.template.template_id,
            image_id=metadata.template.image_id,
            backend=metadata.backend,
            architecture=metadata.guest.architecture,
            reference=metadata.template.name,
            status=TemplateState.READY,
            source_checksum="0" * 64,
            created_by_version="test",
            fingerprint=metadata.template.fingerprint,
        )
    )


def _template_reference() -> TemplateRef:
    return TemplateRef(
        image_id="windows-11-arm64",
        template_id="rf-base-windows-11-arm64",
        name=TEMPLATE_NAME,
        fingerprint="a" * 64,
    )


def _metadata(
    scenario: Scenario,
    *,
    platform: GuestPlatform | None = GuestPlatform.WINDOWS,
    backend: VMBackend = VMBackend.UTM,
    architecture: Architecture = Architecture.ARM64,
    language: ExecutionLanguage | None = ExecutionLanguage.POWERSHELL,
    kind: ManagementTransportKind | None = ManagementTransportKind.QEMU_GUEST_AGENT,
    state: VMState = VMState.RUNNING,
    management: ManagementState = ManagementState.READY,
    vm_name: str | None = None,
    resource_id: str | None = None,
    metadata_version: int = 4,
) -> RuntimeMetadata:
    name = vm_name or scenario_vm_name(scenario)
    if resource_id is None:
        # Derived from the name so the synthetic RecordingUTM UUIDs agree.
        resource_id = f"uuid-{name}"
    guest = RuntimeGuestState(
        architecture=architecture,
        ip="192.168.64.9",
        management=management,
        platform=platform,
        management_transport=kind,
        execution_language=language,
    )
    metadata = RuntimeMetadata(
        scenario_id=scenario.scenario.id,
        profile=scenario.scenario.profile,
        runtime=RuntimeType.VM,
        backend=backend,
        vm=VMIdentity(
            name=name,
            managed_id=scenario_managed_id(scenario),
            state=state,
            resource_id=resource_id,
        ),
        template=_template_reference(),
        guest=guest,
        metadata_version=metadata_version,
    )
    return metadata.model_copy(
        update={"ownership_fingerprint": ownership_fingerprint(metadata)}
    )


@pytest.fixture
def windows_scenario(scenario: Scenario) -> Scenario:
    return scenario.model_copy(
        update={
            "scenario": scenario.scenario.model_copy(
                update={"platform": "windows", "guest_architecture": "arm64"}
            )
        }
    )


def _persisted(
    scenario_path: Path, metadata: RuntimeMetadata
) -> RuntimeMetadata:
    RuntimeMetadataStore(scenario_path).save(metadata)
    return metadata


def _expected_run_commands(vm: str, digest: str) -> list[tuple[str, ...]]:
    """Exact deterministic command sequence for one fresh-script run.

    Every PowerShell upload uses the deterministic barrier before its launch:
    semantic validated push, one bounded pause (no command), and a semantic
    pull verifying the exact uploaded content. A disposable Temp warmup probe
    runs first and is polled to observed self-deletion; bootstrap follows,
    then a one-shot rf-* root sweep, both polled the same way; the frame
    launch is followed by transient-aware marker polling and verified
    success cleanup.
    """

    def push(path: str) -> tuple[str, ...]:
        return (str(UTMCTL), "file", "push", vm, path)

    def pull(path: str) -> tuple[str, ...]:
        return (str(UTMCTL), "file", "pull", vm, path)

    def launch(path: str) -> tuple[str, ...]:
        return (str(UTMCTL), "exec", vm, *EXEC_FLAGS, path)

    clean = f"{ROOT}\\rf-{digest}.clean.ps1"
    body = f"{ROOT}\\rf-{digest}.body.ps1"
    frame = f"{ROOT}\\rf-{digest}.frame.ps1"
    out = f"{ROOT}\\rf-{digest}.out"
    done = f"{ROOT}\\rf-{digest}.done"
    # Absence verification (replay-critical pair) matches
    # _run_digest_cleanup: result then done, current generation.
    replay_absence = (out, done)
    warmup = WARMUP_PATH
    sweep = SWEEP_PATH

    def cleanup_block() -> list[tuple[str, ...]]:
        return [
            push(clean),
            pull(clean),
            launch(clean),
            pull(clean),
            pull(clean),
            *(pull(path) for path in replay_absence),
        ]

    commands: list[tuple[str, ...]] = [
        # Disposable channel warmup: barrier push+verify, single submission,
        # poll until the self-deleting probe is observably gone.
        push(warmup),
        pull(warmup),
        launch(warmup),
        pull(warmup),
        pull(warmup),
        # One-shot async bootstrap: barrier push+verify, launch, poll gone.
        push(BOOTSTRAP_PATH),
        pull(BOOTSTRAP_PATH),
        launch(BOOTSTRAP_PATH),
        pull(BOOTSTRAP_PATH),
        pull(BOOTSTRAP_PATH),
        # One-shot rf-* root sweep once the channel is proven healthy.
        push(sweep),
        pull(sweep),
        launch(sweep),
        pull(sweep),
        pull(sweep),
        # Mandatory digest-scoped pre-clean before any upload.
        *cleanup_block(),
        # Upload verification barrier for the body.
        push(body),
        pull(body),
        # Frame upload barrier, launch, and transient-aware marker polling.
        push(frame),
        pull(frame),
        launch(frame),
        pull(done),
        pull(done),
        pull(done),
        # Result retrieval once the output lock has cleared.
        pull(out),
        # Verified success-path cleanup.
        *cleanup_block(),
    ]
    return commands


class TestDeterministicCommandConstruction:
    SCRIPT = "Write-Output 'fixture'\nexit 0\n"

    def test_exact_argv_and_paths(self, windows_scenario: Scenario, tmp_path: Path) -> None:
        fake = FakeGuest()
        result = transport(fake).run(self.SCRIPT, timeout=30)
        assert result.outcome is ManagementOutcome.COMPLETED
        assert result.exit_code == 0
        digest = digest_of(self.SCRIPT)
        assert fake.commands == _expected_run_commands("rf-scenario", digest)

    def test_bootstrap_runs_once_per_transport(self) -> None:
        fake = FakeGuest()
        manager = transport(fake)
        assert manager.run(self.SCRIPT, timeout=30).outcome is ManagementOutcome.COMPLETED
        after_first = len(fake.commands)
        assert manager.run("exit 3\n", timeout=30).exit_code == 3
        assert not any(
            command[-1].endswith("rf-bootstrap.ps1")
            for command in fake.commands[after_first:]
        )

    def test_fast_bootstrap_and_cleanup_do_not_race_first_pull(self) -> None:
        fake = FakeGuest(exec_latency=0)
        result = transport(fake).run(self.SCRIPT, timeout=30)
        assert result.outcome is ManagementOutcome.COMPLETED
        assert result.exit_code == 0
        assert fake.residue() == set()

    def test_bootstrap_uses_fixed_existing_path_and_self_cleans(self) -> None:
        fake = FakeGuest()
        assert transport(fake).run(self.SCRIPT, timeout=30).outcome is ManagementOutcome.COMPLETED
        uploads = dict(fake.uploads)
        bootstrap = uploads["C:\\Windows\\Temp\\rf-bootstrap.ps1"]
        script_text = bootstrap.decode("utf-8-sig")
        assert f"New-Item -Path '{ROOT}' -ItemType Directory -Force" in script_text
        assert "$PSCommandPath" in script_text
        # The bootstrap script deleted itself and created nothing else.
        assert "C:\\Windows\\Temp\\rf-bootstrap.ps1" not in fake.files

    def test_bootstrap_failure_blocks_operation_without_body_upload(self) -> None:
        fake = FakeGuest()
        fake.directories.clear()  # No existing temp directory: push cannot land.
        result = transport(fake).run(self.SCRIPT, timeout=30)
        assert result.outcome is ManagementOutcome.TRANSPORT_FAILURE
        # The disposable warmup probe is the first upload attempt.
        assert "warmup" in (result.detail or "")
        assert not any(path.endswith(".body.ps1") for path, _ in fake.uploads)

    def test_bootstrap_respects_the_bounded_deadline(self) -> None:
        fake = FakeGuest(clock_step=100.0)
        result = transport(fake).run(self.SCRIPT, timeout=10)
        assert result.outcome is ManagementOutcome.TIMEOUT
        assert not any(path.endswith(".body.ps1") for path, _ in fake.uploads)

    def test_uploads_use_utf8_bom_encoding(self, tmp_path: Path) -> None:
        fake = FakeGuest()
        script = "Write-Output 'unicode: caf\xc3\xa9 '\nexit 0\n"
        transport(fake).run(script, timeout=30)
        digest = digest_of(script)
        uploads = dict(fake.uploads)
        body = uploads[f"{ROOT}\\rf-{digest}.body.ps1"]
        assert body.startswith(b"\xef\xbb\xbf")
        assert body.decode("utf-8-sig") == script
        frame = uploads[f"{ROOT}\\rf-{digest}.frame.ps1"]
        assert frame.startswith(b"\xef\xbb\xbf")

    def test_output_decoding_strips_bom(self) -> None:
        fake = FakeGuest()
        result = transport(fake).run("Write-Output 'x'", timeout=30)
        assert result.stdout == "ok"

    def test_repeated_inputs_produce_identical_construction(self) -> None:
        first, second = FakeGuest(), FakeGuest()
        transport(first).run(self.SCRIPT, timeout=30)
        transport(second).run(self.SCRIPT, timeout=30)
        assert first.commands == second.commands

    def test_metacharacters_cannot_alter_argv(self) -> None:
        adversarial = (
            "Write-Output 'spaces and  tabs\there'\n"
            '#FAKE:OUTPUT:"; rm -rf / & do $(evil) `x` | pipe > redirect\n'
            "Write-Output \"quote' and \\\" double; & | $ < > ^ % !\"\n"
            "\u00e9\u4e2d\u6587 emoji \U0001f600\n"
            "exit 0\n"
        )
        plain = FakeGuest()
        weird = FakeGuest()
        transport(plain).run("Write-Output 'plain'", timeout=30)
        transport(weird).run(adversarial, timeout=30)
        for command in weird.commands:
            for element in command:
                assert "; rm -rf" not in element
                assert "$(evil)" not in element
                assert "\u00e9" not in element
        plain_shape = [self._shape(command) for command in plain.commands]
        weird_shape = [self._shape(command) for command in weird.commands]
        assert plain_shape == weird_shape

    @staticmethod
    def _shape(command: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(
            "<path>"
            if element.startswith((ROOT, "C:\\Windows\\", "/usr/"))
            else element
            for element in command
        )


class TestAdversarialOutcomes:
    def test_nonzero_guest_status_is_preserved(self) -> None:
        fake = FakeGuest()
        result = transport(fake).run("Write-Output 'failed'\nexit 23\n", timeout=30)
        assert result.outcome is ManagementOutcome.COMPLETED
        assert result.exit_code == 23
        assert result.marker_verified is True

    def test_marker_digest_spoof_is_rejected(self) -> None:
        fake = FakeGuest()
        result = transport(fake).run("#FAKE:DONE_DIGEST:" + "b" * 16 + "\nexit 0\n", timeout=30)
        assert result.outcome is ManagementOutcome.TRANSPORT_FAILURE
        assert result.exit_code is None
        assert result.detail == "Completion marker failed integrity verification."

    def test_garbage_marker_is_rejected(self) -> None:
        fake = FakeGuest()
        fake.done_poison = b"RF_MGMT_COMPLETE:0:zzzz\n"
        result = transport(fake).run("exit 0", timeout=30)
        assert result.outcome is ManagementOutcome.TRANSPORT_FAILURE
        assert "integrity" in (result.detail or "")

    def test_stale_marker_replay_is_prevented(self) -> None:
        """Repeated identical scripts must never replay an old result."""
        fake = FakeGuest()
        manager = transport(fake)
        script = "#FAKE:OUTPUT:first\nexit 0\n"
        first = manager.run(script, timeout=60)
        assert first.outcome is ManagementOutcome.COMPLETED
        assert first.stdout == "first"
        # Simulate stale same-digest artifacts that survived a previous run.
        digest = digest_of(script)
        fake.files[f"{ROOT}\\rf-{digest}.done"] = (
            f"RF_MGMT_COMPLETE:9:{digest}\n"
        ).encode("ascii")
        fake.files[f"{ROOT}\\rf-{digest}.out"] = b"stale\n"
        second = manager.run(script, timeout=60)
        assert second.outcome is ManagementOutcome.COMPLETED
        assert second.exit_code == 0
        assert second.stdout == "first"

    def test_transient_missing_and_locked_done_are_polled_not_fatal(self) -> None:
        """Delayed async guest work is polled to completion, never misread."""
        fake = FakeGuest(exec_latency=5)
        result = transport(fake).run("exit 5\n", timeout=60)
        assert result.outcome is ManagementOutcome.COMPLETED
        assert result.exit_code == 5

    def test_exec_argv_uses_absolute_builtin_powershell(self) -> None:
        fake = FakeGuest()
        assert transport(fake).run("exit 0", timeout=30).outcome is ManagementOutcome.COMPLETED
        execs = [command for command in fake.commands if command[1] == "exec"]
        assert execs
        for command in execs:
            assert command[4] == POWERSHELL
            assert command[5:10] == (
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
            )
            assert command[10] == "-File"
        frame_upload = next(
            content
            for path, content in fake.uploads
            if path.endswith(".frame.ps1")
        ).decode("utf-8-sig")
        assert f"& '{POWERSHELL}'" in frame_upload

    def test_timeout_returns_typed_result_and_skips_expired_cleanup(self) -> None:
        fake = FakeGuest(clock_step=2.0)
        result = transport(fake).run("#FAKE:NO_DONE\nexit 0\n", timeout=10)
        assert result.outcome is ManagementOutcome.TIMEOUT
        assert result.exit_code is None
        # The deadline has already expired when the timeout is detected, so
        # best-effort cleanup must return promptly without new runner calls.
        assert not any(
            command[-1].endswith(".clean.ps1") for command in fake.commands
        )

    def test_failure_paths_cleanup_within_the_remaining_budget(self) -> None:
        fake = FakeGuest()
        result = transport(fake).run(
            "#FAKE:DONE_DIGEST:" + "b" * 16 + "\nexit 0\n", timeout=30
        )
        assert result.outcome is ManagementOutcome.TRANSPORT_FAILURE
        cleanup_pushes = [
            command
            for command in fake.commands
            if command[1:3] == ("file", "push")
            and command[-1].endswith(".clean.ps1")
        ]
        # One push from the mandatory pre-clean plus one best-effort push on
        # the failure path.
        assert len(cleanup_pushes) == 2
        fake.drain()
        assert fake.residue() == set()

    def test_success_leaves_no_guest_residue(self) -> None:
        fake = FakeGuest()
        result = transport(fake).run(
            "#FAKE:OUTPUT:payload\nexit 0\n", timeout=30
        )
        assert result.outcome is ManagementOutcome.COMPLETED
        assert result.exit_code == 0
        assert result.stdout == "payload"
        # Output and exit code are preserved before the verified success
        # cleanup runs; no asynchronous cleanup race is possible.
        assert fake.residue() == set()

    def test_upload_verification_failure_times_out_without_launch(self) -> None:
        """Patient verification runs to the deadline, then fails closed."""
        fake = FakeGuest(mutate_body_pulls=True)
        result = transport(fake).run("exit 0\n", timeout=30)
        assert result.outcome is ManagementOutcome.TIMEOUT
        assert result.exit_code is None
        # The frame was never uploaded or submitted; the uploaded body is the
        # only residue and the next same-digest pre-clean removes it.
        assert not any(path.endswith(".frame.ps1") for path, _ in fake.uploads)
        assert not any(
            path.endswith(".frame.ps1") for path in fake.exec_targets
        )
        digest = digest_of("exit 0\n")
        assert fake.residue() == {f"{ROOT}\\rf-{digest}.body.ps1"}

    def test_missing_result_file_is_transport_failure(self) -> None:
        fake = FakeGuest()
        result = transport(fake).run("#FAKE:NO_RESULT\nexit 0\n", timeout=30)
        assert result.outcome is ManagementOutcome.TRANSPORT_FAILURE
        assert result.exit_code is None
        assert result.detail == "Guest result could not be retrieved."
        # The deadline is exhausted on this path, so best-effort cleanup has
        # no budget left; only the already-pulled marker file may remain and
        # the next same-digest operation's mandatory pre-clean removes it.
        fake.drain()
        digest = digest_of("#FAKE:NO_RESULT\nexit 0\n")
        assert fake.residue() == {f"{ROOT}\\rf-{digest}.done"}

    def test_oversized_output_is_bounded(self) -> None:
        fake = FakeGuest()
        result = transport(fake).run("#FAKE:HUGE\nexit 0\n", timeout=30)
        assert result.outcome is ManagementOutcome.TRANSPORT_FAILURE
        assert result.stdout == ""
        assert "bound" in (result.detail or "")
        fake.drain()
        assert fake.residue() == set()

    def test_unverifiable_success_cleanup_is_a_typed_failure(self) -> None:
        """A success whose cleanup cannot be verified is never false success."""
        fake = FakeGuest(fail_clean=True)
        first = transport(fake).run("exit 0\n", timeout=30)
        assert first.outcome is not ManagementOutcome.COMPLETED
        assert first.outcome in (
            ManagementOutcome.TRANSPORT_FAILURE,
            ManagementOutcome.TIMEOUT,
        )
        # With an unverifiable cleaner, the mandatory pre-clean of any
        # follow-up operation also fails closed: no execution, no crash.
        second = transport(fake).run("exit 7\n", timeout=30)
        assert second.outcome is not ManagementOutcome.COMPLETED
        assert second.exit_code is None

    def test_secret_canary_never_leaks_into_diagnostics_or_argv(self) -> None:
        canary = "S3CRET-CANARY-VALUE"
        fake = FakeGuest(clock_step=5.0)
        manager = transport(fake)
        outcomes = [
            manager.run(f"# '{canary}'\n#FAKE:NO_DONE\nexit 3\n", timeout=10),
            manager.run(f"# '{canary}'\n#FAKE:DONE_DIGEST:" + "c" * 16 + "\nexit 0\n", timeout=30),
            manager.run(f"# '{canary}'\n#FAKE:NO_RESULT\nexit 0\n", timeout=30),
            manager.run(f"# '{canary}'\n#FAKE:HUGE\nexit 0\n", timeout=30),
        ]
        encoded = f"'{canary}'".encode()
        encoded_bom = b"\xef\xbb\xbf" + encoded
        for result in outcomes:
            diagnostics = " ".join(
                filter(None, (result.detail, result.stderr, result.stdout))
            )
            assert canary not in diagnostics
            assert canary.encode() not in diagnostics.encode()
        for command in fake.commands:
            joined = "\n".join(command)
            assert canary not in joined
            for element in command:
                assert encoded not in element.encode()
                assert encoded_bom not in element.encode()


def _assert_submission_profile(
    fake: FakeGuest,
    *,
    bootstrap_execs: int = 1,
    warmup_execs: int = 1,
    sweep_execs: int = 1,
) -> None:
    """Assert the exec-submission counts for one transport operation.

    The disposable warmup probe is submitted ``warmup_execs`` times (RPC-
    timeout rejections are retried because they provably never delivered);
    the digest-scoped cleanup script legitimately runs twice per operation
    (mandatory pre-clean and verified success cleanup); body and frame are
    submitted exactly once; the bootstrap is submitted ``bootstrap_execs``
    times. Body/frame/cleanup targets are never resubmitted, and no target
    other than an authorized warmup/bootstrap retry may repeat.
    """
    for path in set(fake.exec_targets):
        count = fake.exec_targets.count(path)
        if path.endswith((".body.ps1", ".frame.ps1")):
            assert count == 1, f"{path} submitted {count} times"
        elif path.endswith("rf-warmup.ps1") or (
            "-r" in path and "rf-warmup" in path
        ):
            assert count == warmup_execs, f"{path} submitted {count} times"
        elif path.endswith("rf-bootstrap.ps1"):
            assert count == bootstrap_execs, (
                f"{path} submitted {count} times"
            )
        elif path.endswith("rf-sweep.ps1"):
            assert count == sweep_execs, f"{path} submitted {count} times"
        elif path.endswith(".clean.ps1"):
            assert count == 2, f"{path} submitted {count} times"
    non_retry_repeats = [
        first
        for first, second in itertools.pairwise(fake.exec_targets)
        if first == second
        and not (
            first.endswith("rf-bootstrap.ps1")
            or re.search(r"rf-warmup(-r\d+)?\.ps1$", first)
        )
    ]
    assert non_retry_repeats == []


class TestRealTransferSemantics:
    """Observed real UTM 4.7.5 transfer semantics, classified explicitly."""

    def test_pull_classification_rules(self) -> None:
        from rangeforge.runtime.management import (
            _classify_guest_pull,
            _GuestFileState,
        )

        missing = (
            "Error from event: failed to open file: "
            "The system cannot find the file specified."
        )
        locked = (
            "Error from event: failed to open file: The process cannot access "
            "the file because it is being used by another process."
        )
        assert _classify_guest_pull(CommandResult(returncode=0)) is _GuestFileState.AVAILABLE
        # An empty .out from a valid script is AVAILABLE, not unavailable.
        assert _classify_guest_pull(
            CommandResult(returncode=0, stdout="")
        ) is _GuestFileState.AVAILABLE
        assert (
            _classify_guest_pull(CommandResult(returncode=0, stderr=missing))
            is _GuestFileState.MISSING
        )
        # Conservative equivalent diagnostic also counts as MISSING.
        assert (
            _classify_guest_pull(CommandResult(returncode=0, stderr="no such file"))
            is _GuestFileState.MISSING
        )
        # Locked, unknown, and nonzero-host-code results are never MISSING.
        assert (
            _classify_guest_pull(CommandResult(returncode=0, stderr=locked))
            is _GuestFileState.TRANSIENT
        )
        assert (
            _classify_guest_pull(
                CommandResult(returncode=0, stderr="Error from event: something else.")
            )
            is _GuestFileState.TRANSIENT
        )
        assert (
            _classify_guest_pull(CommandResult(returncode=1, stderr=missing))
            is _GuestFileState.TRANSIENT
        )

    def test_code_zero_stderr_push_fails_closed(self) -> None:
        """A code-0 push with diagnostic stderr never lands or launches."""
        fake = FakeGuest(push_error_stderr=_PULL_LOCKED_STDERR)
        result = transport(fake).run("exit 0\n", timeout=30)
        assert result.outcome is ManagementOutcome.TRANSPORT_FAILURE
        assert "warmup" in (result.detail or "")
        assert fake.uploads == []
        assert not any(command[1] == "exec" for command in fake.commands)

    def test_locked_bootstrap_push_fails_closed(self) -> None:
        """Pushing over a locked file reports code 0 + stderr and must abort."""

        fake = FakeGuest(locked_push_paths={BOOTSTRAP_PATH})
        # A resident file is required for the locked-inode conflict; its
        # foreign content means adoption/escalation can never apply.
        fake.files[BOOTSTRAP_PATH] = b"\xef\xbb\xbfWrite-Output 'stale'\n"
        result = transport(fake).run("exit 0\n", timeout=30)
        assert result.outcome is ManagementOutcome.TRANSPORT_FAILURE
        assert "bootstrap" in (result.detail or "")
        # Only the warmup probe ran; the poisoned bootstrap name was never
        # pushed or submitted.
        bootstrap_uploads = [
            path for path, _ in fake.uploads if "rf-bootstrap" in path
        ]
        assert bootstrap_uploads == []
        assert len(fake.exec_targets) == 1
        assert fake.exec_targets[0].endswith("rf-warmup.ps1")

    def test_stuck_bootstrap_is_never_mistaken_for_absent(self) -> None:
        """A bootstrap file that stays readable keeps the operation failing."""
        fake = FakeGuest(stuck_bootstrap=True)
        result = transport(fake).run("exit 0\n", timeout=10)
        assert result.outcome is ManagementOutcome.TIMEOUT
        # The root itself was created, but readiness was never claimed and
        # nothing was executed inside it.
        assert ROOT in fake.directories
        assert not any(path.endswith(".body.ps1") for path, _ in fake.uploads)

    def test_empty_out_is_valid_completed_output(self) -> None:
        """AVAILABLE with empty stdout is a valid empty guest result."""
        fake = FakeGuest()
        result = transport(fake).run("#FAKE:EMPTY_OUT\nexit 0\n", timeout=30)
        assert result.outcome is ManagementOutcome.COMPLETED
        assert result.exit_code == 0
        assert result.stdout == ""
        assert result.marker_verified is True

    def test_unknown_pull_stderr_fails_closed_to_timeout(self) -> None:
        """Unrecognized code-0 stderr is TRANSIENT and never treated as gone.

        Patient verification can never confirm content, so the bootstrap
        times out at the deadline without any launch.
        """
        fake = FakeGuest(weird_pull_stderr=True)
        result = transport(fake).run("exit 0\n", timeout=5)
        assert result.outcome is ManagementOutcome.TIMEOUT
        assert result.exit_code is None
        assert not any(path.endswith(".body.ps1") for path, _ in fake.uploads)
        assert fake.exec_targets == []

    def test_no_launch_after_verification_failure(self) -> None:
        """A failed upload barrier never submits the target script."""
        fake = FakeGuest(mutate_body_pulls=True)
        result = transport(fake).run("exit 0\n", timeout=30)
        assert result.outcome is ManagementOutcome.TIMEOUT
        assert result.exit_code is None
        assert not any(path.endswith(".frame.ps1") for path, _ in fake.uploads)
        assert not any(
            path.endswith(".frame.ps1") for path in fake.exec_targets
        )

    def test_rpc_timeout_launches_retry_then_execute_exactly_once(self) -> None:
        """Two RPC-timeout rejections then acceptance on the warmup probe.

        Real traces prove code0 + ``Timed out waiting for RPC`` means the
        request was never delivered, so resubmission is safe; the accepted
        submission queues the guest action exactly once. The warmup runs
        first, so it absorbs the wedge-window rejections while Transport-
        root work stays untouched until the channel is warm.
        """
        fake = FakeGuest(exec_rpc_stderr=2, exec_latency=4)
        manager = transport(fake)
        result = manager.run("exit 0\n", timeout=120)
        assert result.outcome is ManagementOutcome.COMPLETED
        assert result.exit_code == 0
        _assert_submission_profile(fake, warmup_execs=3)
        # The wedge was absorbed by the disposable probe; the channel is
        # marked warm and Transport-root work proceeded afterwards.
        assert manager._channel_warm is True
        # Ordering proof: no Transport-root file was pushed until after the
        # final (accepted) warmup submission.
        first_root_push = next(
            index
            for index, command in enumerate(fake.commands)
            if command[1:3] == ("file", "push")
            and command[-1].startswith(ROOT + "\\")
        )
        last_warmup_exec = max(
            index
            for index, command in enumerate(fake.commands)
            if command[1] == "exec" and "rf-warmup" in command[-1]
        )
        assert first_root_push > last_warmup_exec
        # Exactly one push: rejected submissions are never re-uploaded.
        bootstrap_pushes = [
            path
            for path, _ in fake.uploads
            if path.endswith("rf-bootstrap.ps1")
        ]
        assert len(bootstrap_pushes) == 1

    def test_completion_after_multiple_transient_pulls(self) -> None:
        """TRANSIENT pulls during the queued-execution window are retried."""
        fake = FakeGuest(transient_done_pulls=4)
        result = transport(fake).run("exit 5\n", timeout=120)
        assert result.outcome is ManagementOutcome.COMPLETED
        assert result.exit_code == 5
        _assert_submission_profile(fake)

    def test_permanently_non_executing_request_times_out_without_retry(self) -> None:
        """A cleanly accepted request that never executes times out once.

        Clean code-0 submission queues the guest action; if it never runs,
        the transport polls its authoritative signal to the deadline and
        reports TIMEOUT without any duplicate submission.
        """
        fake = FakeGuest(never_execute=True)
        result = transport(fake).run("exit 0\n", timeout=10)
        assert result.outcome is ManagementOutcome.TIMEOUT
        assert result.exit_code is None
        # The warmup probe is the cleanly submitted request that never
        # executes; bootstrap is never reached and nothing is resubmitted.
        warmup_execs = [
            path for path in fake.exec_targets if "rf-warmup" in path
        ]
        assert len(warmup_execs) == 1
        assert not any(
            path.endswith("rf-bootstrap.ps1") for path in fake.exec_targets
        )
        assert not any(
            path.endswith(".body.ps1") for path, _ in fake.uploads
        )

    def test_unknown_exec_stderr_fails_closed_after_single_exec(self) -> None:
        """Ambiguous code-0 stderr fails closed after exactly one exec."""
        fake = FakeGuest(unknown_exec_stderr=True)
        result = transport(fake).run("exit 0\n", timeout=30)
        assert result.outcome is ManagementOutcome.TRANSPORT_FAILURE
        assert result.detail == "Management channel warmup launch failed."
        assert len(fake.exec_targets) == 1
        assert fake.exec_targets[0].endswith("rf-warmup.ps1")

    def test_local_invocation_failure_fails_fast_without_retry(self) -> None:
        """A runner-synthetic local failure (code 125) fails fast."""
        fake = FakeGuest(local_exec_failure=True)
        result = transport(fake).run("exit 0\n", timeout=30)
        assert result.outcome is ManagementOutcome.TRANSPORT_FAILURE
        assert result.detail == "Management channel warmup launch failed."
        # Exactly one exec attempt was made; nothing was scheduled or run.
        assert len(fake.exec_targets) == 1
        assert fake.exec_targets[0].endswith("rf-warmup.ps1")

    def test_probe_timeout_is_bounded_for_delayed_execution(self) -> None:
        """One bounded total budget covers all readiness operations."""
        import rangeforge.runtime.management as management_module

        assert management_module._PROBE_TOTAL_BUDGET == 300.0

    def test_transient_verification_pulls_retry_without_repush(self) -> None:
        """Cold-QGA locked read-backs retry the pull, never the push."""
        fake = FakeGuest(transient_pulls_remaining=2)
        result = transport(fake).run("exit 0\n", timeout=60)
        assert result.outcome is ManagementOutcome.COMPLETED
        assert result.exit_code == 0
        bootstrap_pushes = [
            path
            for path, _ in fake.uploads
            if path.endswith("rf-bootstrap.ps1")
        ]
        # Exactly one push survived the two transient verification pulls.
        assert len(bootstrap_pushes) == 1
        assert len(bootstrap_pushes) == len(set(bootstrap_pushes))

    def test_late_visibility_verification_is_patient(self) -> None:
        """Cold-boot pull visibility beyond any fixed budget still succeeds.

        Real evidence: the first pulls after a successful push can stay
        locked well past a quick attempt budget. Verification must remain
        patient to the deadline and succeed with exactly one bootstrap push.
        """
        fake = FakeGuest(transient_pulls_remaining=6)
        result = transport(fake).run("exit 0\n", timeout=120)
        assert result.outcome is ManagementOutcome.COMPLETED
        assert result.exit_code == 0
        bootstrap_pushes = [
            path
            for path, _ in fake.uploads
            if path.endswith("rf-bootstrap.ps1")
        ]
        assert len(bootstrap_pushes) == 1

    def test_poisoned_bootstrap_escalates_to_fresh_name(self) -> None:
        """A locked push over our own stale artifact escalates the name.

        Real evidence: a bootstrap file whose exec landed inside the cold-
        boot RPC wedge stays permanently guest-side locked; freshly named
        scripts work on the same booted state. The transport must never
        re-push or execute the poisoned inode — it escalates to the bounded
        deterministic ``-r1`` name and completes there.
        """
        import rangeforge.runtime.management as management_module

        expected = management_module._bootstrap_script()
        fake = FakeGuest(locked_push_paths={BOOTSTRAP_PATH})
        fake.files[BOOTSTRAP_PATH] = expected.encode("utf-8-sig")
        result = transport(fake).run("exit 0\n", timeout=120)
        assert result.outcome is ManagementOutcome.COMPLETED
        assert result.exit_code == 0
        # The original poisoned name was never successfully pushed...
        assert not any(path == BOOTSTRAP_PATH for path, _ in fake.uploads)
        # ...and never submitted; the escalated -r1 name carried the run.
        assert not any(
            path == BOOTSTRAP_PATH for path in fake.exec_targets
        )
        escalated_uploads = [
            path
            for path, _ in fake.uploads
            if path.endswith("rf-bootstrap-r1.ps1")
        ]
        assert len(escalated_uploads) == 1
        escalated_execs = [
            path
            for path in fake.exec_targets
            if path.endswith("rf-bootstrap-r1.ps1")
        ]
        assert len(escalated_execs) == 1

    def test_resident_foreign_bootstrap_fails_closed_without_escalation(self) -> None:
        """Foreign resident content at the locked name never escalates."""
        fake = FakeGuest(locked_push_paths={BOOTSTRAP_PATH})
        fake.files[BOOTSTRAP_PATH] = b"\xef\xbb\xbfWrite-Output 'not rangeforge'\n"
        result = transport(fake).run("exit 0\n", timeout=30)
        assert result.outcome is ManagementOutcome.TRANSPORT_FAILURE
        assert result.detail == (
            "Management root bootstrap upload could not be verified."
        )
        assert not any(
            "rf-bootstrap" in path for path in fake.exec_targets
        )
        assert not any(
            "rf-bootstrap-r" in path for path, _ in fake.uploads
        )

    def test_all_generations_poisoned_fail_closed_bounded(self) -> None:
        """Escalation is bounded: three names, then typed failure each time."""
        locked = {
            BOOTSTRAP_PATH,
            "C:\\Windows\\Temp\\rf-bootstrap-r1.ps1",
            "C:\\Windows\\Temp\\rf-bootstrap-r2.ps1",
        }
        import rangeforge.runtime.management as management_module

        content = management_module._bootstrap_script().encode("utf-8-sig")
        fake = FakeGuest(locked_push_paths=locked)
        for path in locked:
            fake.files[path] = content
        manager = transport(fake)
        for _ in range(3):
            result = manager.run("exit 0\n", timeout=30)
            assert result.outcome is ManagementOutcome.TRANSPORT_FAILURE
            assert "bootstrap" in (result.detail or "")
        # Every generation was tried exactly once; the cap holds afterwards.
        assert manager._generations[BOOTSTRAP_PATH] == 2
        fourth = manager.run("exit 0\n", timeout=30)
        assert fourth.outcome is ManagementOutcome.TRANSPORT_FAILURE
        assert manager._generations[BOOTSTRAP_PATH] == 2
        assert not any(
            "rf-bootstrap" in path for path in fake.exec_targets
        )
        assert not any(
            path.endswith("rf-bootstrap.ps1") or "rf-bootstrap-r" in path
            for path, _ in fake.uploads
        )

    def test_wildcard_cleanup_removes_generation_variants(self) -> None:
        """The cleanup glob removes escalated ``-rN`` variants too."""
        digest = digest_of("exit 0\n")
        stale_variants = {
            f"{ROOT}\\rf-{digest}-r1.out": b"x",
            f"{ROOT}\\rf-{digest}-r2.done": b"RF_MGMT_COMPLETE:0:x\n",
        }
        fake = FakeGuest()
        fake.files.update(stale_variants)
        result = transport(fake).run("exit 0\n", timeout=120)
        assert result.outcome is ManagementOutcome.COMPLETED
        for variant in stale_variants:
            assert variant not in fake.files

    def test_stale_root_residue_is_swept_during_bootstrap(self) -> None:
        """Damaged-clone recovery: stale rf-* residue is swept at bootstrap."""
        stale = {
            f"{ROOT}\\rf-olddeadbeefdead.done": b"RF_MGMT_COMPLETE:0:x\n",
            f"{ROOT}\\rf-0123456789abcdef-r1.out": b"stale output\n",
        }
        fake = FakeGuest()
        fake.files.update(stale)
        result = transport(fake).run("exit 0\n", timeout=120)
        assert result.outcome is ManagementOutcome.COMPLETED
        assert result.exit_code == 0
        for variant in stale:
            assert variant not in fake.files
        assert fake.residue() == set()

    def test_sweep_failure_fails_closed_and_root_not_ready(self) -> None:
        """An unverifiable sweep leaves the root not ready; nothing runs."""
        fake = FakeGuest(fail_sweep=True)
        manager = transport(fake)
        result = manager.run("exit 0\n", timeout=10)
        assert result.outcome in (
            ManagementOutcome.TIMEOUT,
            ManagementOutcome.TRANSPORT_FAILURE,
        )
        assert manager._channel_warm is True
        assert manager._root_ready is False
        assert manager._swept is False
        assert not any(path.endswith(".body.ps1") for path, _ in fake.uploads)

    def test_sweep_never_touches_non_rf_files(self) -> None:
        """The sweep is scoped strictly to RangeForge rf-* root entries."""
        fake = FakeGuest()
        foreign = f"{ROOT}\\operator-notes.txt"
        fake.files[foreign] = b"keep me"
        result = transport(fake).run("exit 0\n", timeout=120)
        assert result.outcome is ManagementOutcome.COMPLETED
        assert fake.files.get(foreign) == b"keep me"

    def test_poisoned_generation_zero_clean_uses_escalated_name(self) -> None:
        """Mixed-generation regression: a permanently locked gen-0 clean
        file never fails the operation.

        The gen-0 clean name is QGA-locked (pushes and pulls both report the
        locked diagnostic), so pre-clean escalates to ``-r1``; absence
        verification resolves only current-generation paths, so the poisoned
        gen-0 file is ignored and the operation completes.
        """
        import rangeforge.runtime.management as management_module

        digest = digest_of("exit 0\n")
        gen0_clean = f"{ROOT}\\rf-{digest}.clean.ps1"
        fake = FakeGuest(
            locked_push_paths={gen0_clean},
            locked_pull_paths={gen0_clean},
        )
        # The poisoned inode is resident from an earlier wedged attempt.
        fake.files[gen0_clean] = management_module._cleanup_script(digest).encode(
            "utf-8-sig"
        )
        manager = transport(fake)
        result = manager.run("exit 0\n", timeout=120)
        assert result.outcome is ManagementOutcome.COMPLETED
        assert result.exit_code == 0
        escalated_execs = [
            path
            for path in fake.exec_targets
            if path.endswith(f"rf-{digest}-r1.clean.ps1")
        ]
        # Submitted twice by design: mandatory pre-clean and verified
        # success cleanup share the escalated name.
        assert len(escalated_execs) == 2
        assert not any(path == gen0_clean for path in fake.exec_targets)
        # The undeletable gen-0 inode stays resident but is ignored.
        assert gen0_clean in fake.files

    def test_launch_retries_never_repush_any_script(self) -> None:
        """RPC-timeout resubmission never re-uploads anything.

        The same-digest cleanup script legitimately uploads twice per run
        (pre-clean and final cleanup), but no barrier may ever re-push its
        own file: no two consecutive uploads may share a path, and the
        bootstrap/body/frame scripts upload exactly once each — even when
        bootstrap submissions are rejected with RPC timeouts and retried.
        """
        fake = FakeGuest(exec_rpc_stderr=2)
        manager = transport(fake)
        result = manager.run("exit 0\n", timeout=120)
        assert result.outcome is ManagementOutcome.COMPLETED
        uploaded_paths = [path for path, _ in fake.uploads]
        consecutive_duplicates = [
            first
            for first, second in itertools.pairwise(uploaded_paths)
            if first == second
        ]
        assert consecutive_duplicates == []
        for suffix in ("rf-bootstrap.ps1", ".body.ps1", ".frame.ps1"):
            matching = [path for path in uploaded_paths if path.endswith(suffix)]
            assert len(matching) == 1, suffix
        _assert_submission_profile(fake, bootstrap_execs=1, warmup_execs=3)

    def test_upload_pause_is_clamped_to_the_deadline(self) -> None:
        """The inter-attempt pause never exceeds the remaining budget."""
        fake = FakeGuest()
        manager = transport(fake)
        sleeps: list[float] = []
        manager.sleeper = sleeps.append
        expired = 1000.0
        manager.clock = lambda: expired
        manager._upload_pause(expired)
        assert sleeps == []
        manager.clock = lambda: expired - 0.3
        manager._upload_pause(expired)
        assert sleeps[-1] == pytest.approx(0.3)
        manager.clock = lambda: expired - 100.0
        manager._upload_pause(expired)
        assert sleeps[-1] == 1.0


class TestStageRestrictions:
    @pytest.mark.parametrize(
        "name",
        [
            "..\\evil.txt",
            "..",
            "dir\\evil.txt",
            "dir/evil.txt",
            "C:\\absolute.txt",
            "\\\\host\\share\\file.txt",
            "\\\\.\\device.txt",
            "\\\\?\\device.txt",
            "file.txt:stream",
            "C:hidden.txt",
            "con.txt",
            "CON",
            "nul.zip",
            "com1.log",
            "lpt9.log",
            "trailing.",
            "space name.txt",
            "control\x01name.txt",
            "uni\u00e9code.txt",
            "",
            "a" * 65,
            "-leading.txt",
        ],
    )
    def test_unsafe_names_are_rejected(self, name: str) -> None:
        with pytest.raises(ManagementTransportError):
            safe_stage_name(name)

    def test_safe_names_are_accepted(self) -> None:
        assert safe_stage_name("apache-activemq-5.18.2-bin.tar.gz") == (
            "apache-activemq-5.18.2-bin.tar.gz"
        )
        assert safe_stage_name("RF_probe.file-v2.txt") == "RF_probe.file-v2.txt"

    def test_stage_round_trip_targets_fixed_root_only(self, tmp_path: Path) -> None:
        source = tmp_path / "payload.bin"
        payload = bytes(range(256))
        source.write_bytes(payload)
        fake = FakeGuest()
        result = transport(fake).stage(source, "payload.bin", timeout=60)
        assert result.outcome is ManagementOutcome.COMPLETED
        assert result.exit_code == 0
        staged_paths = [
            command[-1]
            for command in fake.commands
            if command[1:3] == ("file", "push")
        ]
        # The disposable warmup, bootstrap, and rf-* sweep land first; the
        # artifact goes only to the fixed transport root.
        assert staged_paths[0] == "C:\\Windows\\Temp\\rf-warmup.ps1"
        assert staged_paths[1] == "C:\\Windows\\Temp\\rf-bootstrap.ps1"
        assert staged_paths[2] == "C:\\Windows\\Temp\\rf-sweep.ps1"
        assert staged_paths[3] == f"{ROOT}\\payload.bin"
        verification_body = next(
            content.decode("utf-8-sig")
            for path, content in fake.uploads
            if path.endswith(".body.ps1")
        )
        assert f"'{ROOT}\\payload.bin'" in verification_body

    def test_stage_verification_failure_is_transport_failure(self, tmp_path: Path) -> None:
        source = tmp_path / "payload.bin"
        source.write_bytes(b"payload")

        fake = FakeGuest()
        fake.forced_stage_output = "RF_STAGED:0:" + "d" * 64
        result = transport(fake).stage(source, "payload.bin", timeout=60)
        assert result.outcome is ManagementOutcome.TRANSPORT_FAILURE
        assert result.detail == "Staged artifact verification failed."


class TestProbeIntegration:
    def test_real_transport_and_probe_leave_the_workspace_clean(self) -> None:
        """Faithful end-to-end probe over the real transport and fake QGA.

        The real ``_WindowsPowerShellTransport`` drives the real fixed probe
        against the filesystem-faithful ``FakeGuest``. Every operation must
        clean its own files so the final workspace check observes zero
        residuals (excluding only the check's own in-flight digest files).
        """
        fake = FakeGuest()
        probe = _run_readiness_probe(
            transport(fake), expected_architecture=Architecture.ARM64
        )
        failed = [(c.name, c.passed) for c in probe.checks if not c.passed]
        assert probe.ok, f"failed checks: {failed}"
        assert {name for name, _ in failed} == set()
        assert fake.residue() == set()

    def test_probe_detects_residual_files_from_prior_operations(self) -> None:
        """Residuals that do not belong to the check's own digest are caught."""
        import rangeforge.runtime.management as management_module

        fake = FakeGuest()
        manager = transport(fake)
        # Warm the channel and run bootstrap+sweep on a clean root first.
        warmup = manager.run("exit 0\n", timeout=120)
        assert warmup.outcome is ManagementOutcome.COMPLETED
        # Simulate a leftover from an earlier operation that never cleaned up;
        # the one-shot sweep has already run, so this residue stays.
        stale_path = f"{ROOT}\\rf-deadbeefdeadbeef.done"
        fake.files[stale_path] = b"RF_MGMT_COMPLETE:0:deadbeefdeadbeef\n"
        result = manager.run(management_module._PROBE_CLEAN_SCRIPT, timeout=60)
        assert result.stdout.strip() == "RF_CLEAN:1"

    def test_workspace_script_excludes_only_its_own_digest(self) -> None:
        """The fixed script derives its digest from $PSCommandPath, not hashing."""
        import rangeforge.runtime.management as management_module

        script = management_module._PROBE_CLEAN_SCRIPT
        assert "$PSCommandPath" in script
        assert "$rfOwnPattern" in script
        assert "-notmatch $rfOwnPattern" in script
        assert ROOT in script
        # No circular self-hashing: the script never computes a hash of itself.
        assert "hash" not in script.lower()


class TestOwnershipGate:
    def _validated_transport(
        self,
        scenario: Scenario,
        scenario_path: Path,
        *,
        utm: RecordingUTM | None = None,
        vagrant: RecordingVagrant | None = None,
        language: ExecutionLanguage = ExecutionLanguage.POWERSHELL,
        template_manager: StubTemplates | object | None = None,
    ) -> object:
        try:
            persisted = RuntimeMetadataStore(scenario_path).load()
        except Exception:
            persisted = None
        manager = template_manager or _stub_templates(persisted)
        return _owned_management_transport(
            scenario,
            scenario_path,
            host=HOST,
            utm=utm or RecordingUTM({}),  # type: ignore[arg-type]
            vagrant=vagrant or RecordingVagrant(False),  # type: ignore[arg-type]
            language=language,
            template_manager=manager,  # type: ignore[arg-type]
        )

    def test_public_factories_require_trusted_template_manager(
        self, windows_scenario: Scenario, tmp_path: Path
    ) -> None:
        scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
        metadata = _persisted(scenario_path, _metadata(windows_scenario))
        utm = RecordingUTM({metadata.vm.name: VMState.RUNNING})
        with pytest.raises(TypeError):
            _owned_management_transport(  # type: ignore[call-arg]
                windows_scenario,
                scenario_path,
                host=HOST,
                utm=utm,  # type: ignore[arg-type]
                vagrant=RecordingVagrant(False),  # type: ignore[arg-type]
                language=ExecutionLanguage.POWERSHELL,
            )
        with pytest.raises(TypeError):
            owned_guest_transport(  # type: ignore[call-arg]
                windows_scenario,
                scenario_path,
                host=HOST,
                utm=utm,  # type: ignore[arg-type]
                vagrant=RecordingVagrant(False),  # type: ignore[arg-type]
            )
        assert utm.calls == []

    def test_missing_metadata_rejected_before_runner_calls(
        self, windows_scenario: Scenario, tmp_path: Path
    ) -> None:
        scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
        utm = RecordingUTM({})
        with pytest.raises(ManagementTransportError, match="No persisted"):
            self._validated_transport(windows_scenario, scenario_path, utm=utm)
        assert utm.calls == []

    def test_tampered_managed_id_rejected_before_runner_calls(
        self, windows_scenario: Scenario, tmp_path: Path
    ) -> None:
        scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
        metadata = _metadata(windows_scenario)
        tampered = metadata.model_copy(
            update={
                "vm": metadata.vm.model_copy(update={"managed_id": "f" * 64}),
            }
        )
        _persisted(scenario_path, tampered)
        utm = RecordingUTM({tampered.vm.name: VMState.RUNNING})
        with pytest.raises(ManagementTransportError, match="identity"):
            self._validated_transport(windows_scenario, scenario_path, utm=utm)
        assert utm.calls == []

    def test_deterministic_name_mismatch_rejected_before_runner_calls(
        self, windows_scenario: Scenario, tmp_path: Path
    ) -> None:
        scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
        metadata = _metadata(windows_scenario, vm_name="rf-not-the-deterministic-name")
        _persisted(scenario_path, metadata)
        utm = RecordingUTM({"rf-not-the-deterministic-name": VMState.RUNNING})
        with pytest.raises(ManagementTransportError, match=r"identity|VM"):
            self._validated_transport(windows_scenario, scenario_path, utm=utm)
        assert utm.calls == []

    def test_base_template_target_rejected_before_runner_calls(
        self, windows_scenario: Scenario, tmp_path: Path
    ) -> None:
        scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
        deterministic_name = scenario_vm_name(windows_scenario)
        metadata = _metadata(windows_scenario).model_copy(
            update={
                "template": _template_reference().model_copy(update={"name": deterministic_name})
            }
        )
        _persisted(scenario_path, metadata)
        utm = RecordingUTM({deterministic_name: VMState.RUNNING})
        with pytest.raises(ManagementTransportError, match="template"):
            self._validated_transport(windows_scenario, scenario_path, utm=utm)
        assert utm.calls == []
        assert utm.vms[deterministic_name] is VMState.RUNNING

    def test_wrong_platform_request_rejected_before_runner_calls(
        self, scenario: Scenario, tmp_path: Path
    ) -> None:
        scenario_path = ScenarioYamlSerializer().dump(scenario, tmp_path)
        _persisted(
            scenario_path,
            _metadata(
                scenario,
                platform=GuestPlatform.LINUX,
                language=ExecutionLanguage.SHELL,
            ),
        )
        utm = RecordingUTM({scenario_vm_name(scenario): VMState.RUNNING})
        with pytest.raises(ManagementTransportError, match="requested 'windows'"):
            validate_management_target(
                scenario,
                scenario_path,
                host=HOST,
                utm=utm,  # type: ignore[arg-type]
                vagrant=RecordingVagrant(False),  # type: ignore[arg-type]
                language=ExecutionLanguage.POWERSHELL,
                platform=GuestPlatform.WINDOWS,
            )
        assert utm.calls == []

    def test_legacy_metadata_is_never_windows_capable(
        self, scenario: Scenario, tmp_path: Path
    ) -> None:
        scenario_path = ScenarioYamlSerializer().dump(scenario, tmp_path)
        legacy = _metadata(
            scenario,
            platform=None,
            language=None,
            kind=None,
            management=ManagementState.READY,
            metadata_version=2,
        )
        _persisted(scenario_path, legacy)
        utm = RecordingUTM({legacy.vm.name: VMState.RUNNING})
        with pytest.raises(ManagementTransportError, match="not allowlisted"):
            self._validated_transport(scenario, scenario_path, utm=utm)
        assert utm.calls == []
        assert effective_guest_platform(legacy) is GuestPlatform.LINUX

    def test_legacy_metadata_still_supports_linux_shell_transport(
        self, scenario: Scenario, tmp_path: Path
    ) -> None:
        scenario_path = ScenarioYamlSerializer().dump(scenario, tmp_path)
        legacy = _metadata(
            scenario,
            platform=None,
            language=None,
            kind=None,
            management=ManagementState.READY,
            metadata_version=2,
        )
        _persisted(scenario_path, legacy)
        utm = RecordingUTM({legacy.vm.name: VMState.RUNNING})
        resolved = owned_guest_transport(
            scenario,
            scenario_path,
            host=HOST,
            utm=utm,  # type: ignore[arg-type]
            vagrant=RecordingVagrant(False),  # type: ignore[arg-type]
            template_manager=_stub_templates(legacy),  # type: ignore[arg-type]
        )
        assert isinstance(resolved, UTMGuestTransport)
        assert resolved.vm_name == legacy.vm.name
        assert utm.calls != []

    def test_windows_vagrant_rejected_before_runner_calls(
        self, windows_scenario: Scenario, tmp_path: Path
    ) -> None:
        scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
        metadata = _metadata(
            windows_scenario,
            backend=VMBackend.VAGRANT,
            kind=ManagementTransportKind.VAGRANT_SSH,
        )
        _persisted(scenario_path, metadata)
        vagrant = RecordingVagrant(True)
        with pytest.raises(ManagementTransportError, match="Windows Vagrant management"):
            self._validated_transport(
                windows_scenario, scenario_path, vagrant=vagrant
            )
        assert vagrant.calls == []

    def test_wrong_execution_language_rejected_before_runner_calls(
        self, windows_scenario: Scenario, tmp_path: Path
    ) -> None:
        scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
        metadata = _metadata(
            windows_scenario, language=ExecutionLanguage.SHELL
        )
        _persisted(scenario_path, metadata)
        utm = RecordingUTM({metadata.vm.name: VMState.RUNNING})
        with pytest.raises(ManagementTransportError, match="execution language"):
            self._validated_transport(windows_scenario, scenario_path, utm=utm)
        assert utm.calls == []

    def test_powershell_request_rejects_linux_metadata_before_runner_calls(
        self, scenario: Scenario, tmp_path: Path
    ) -> None:
        scenario_path = ScenarioYamlSerializer().dump(scenario, tmp_path)
        _persisted(
            scenario_path,
            _metadata(
                scenario,
                platform=GuestPlatform.LINUX,
                language=ExecutionLanguage.SHELL,
            ),
        )
        utm = RecordingUTM({scenario_vm_name(scenario): VMState.RUNNING})
        with pytest.raises(ManagementTransportError, match="execution language"):
            self._validated_transport(scenario, scenario_path, utm=utm)
        assert utm.calls == []

    def test_architecture_mismatch_rejected_before_runner_calls(
        self, windows_scenario: Scenario, tmp_path: Path
    ) -> None:
        scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
        metadata = _metadata(windows_scenario, architecture=Architecture.AMD64)
        _persisted(scenario_path, metadata)
        utm = RecordingUTM({metadata.vm.name: VMState.RUNNING})
        with pytest.raises(ManagementTransportError, match="architecture"):
            self._validated_transport(windows_scenario, scenario_path, utm=utm)
        assert utm.calls == []

    def test_backend_host_policy_mismatch_rejected_before_runner_calls(
        self, windows_scenario: Scenario, tmp_path: Path
    ) -> None:
        scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
        metadata = _metadata(
            windows_scenario,
            backend=VMBackend.VAGRANT,
            kind=ManagementTransportKind.VAGRANT_SSH,
        )
        _persisted(scenario_path, metadata)
        utm = RecordingUTM({metadata.vm.name: VMState.RUNNING})
        with pytest.raises(ManagementTransportError, match="Windows Vagrant management"):
            self._validated_transport(windows_scenario, scenario_path, utm=utm)
        assert utm.calls == []

    def test_linux_vagrant_metadata_rejected_on_utm_host_before_runner_calls(
        self, scenario: Scenario, tmp_path: Path
    ) -> None:
        scenario_path = ScenarioYamlSerializer().dump(scenario, tmp_path)
        metadata = _metadata(
            scenario,
            platform=GuestPlatform.LINUX,
            backend=VMBackend.VAGRANT,
            kind=ManagementTransportKind.VAGRANT_SSH,
            language=ExecutionLanguage.SHELL,
        )
        _persisted(scenario_path, metadata)
        vagrant = RecordingVagrant(True)
        with pytest.raises(ManagementTransportError, match="host platform"):
            validate_management_target(
                scenario,
                scenario_path,
                host=HOST,
                utm=RecordingUTM({}),  # type: ignore[arg-type]
                vagrant=vagrant,  # type: ignore[arg-type]
                language=ExecutionLanguage.SHELL,
            )
        assert vagrant.calls == []

    def test_not_running_vm_rejected_after_existence_check(
        self, windows_scenario: Scenario, tmp_path: Path
    ) -> None:
        scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
        metadata = _persisted(scenario_path, _metadata(windows_scenario))
        utm = RecordingUTM({metadata.vm.name: VMState.STOPPED})
        with pytest.raises(ManagementTransportError, match="not running"):
            self._validated_transport(windows_scenario, scenario_path, utm=utm)
        assert utm.calls == ["find_by_uuid"]

    def test_missing_vm_resource_rejected(
        self, windows_scenario: Scenario, tmp_path: Path
    ) -> None:
        scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
        _persisted(scenario_path, _metadata(windows_scenario))
        utm = RecordingUTM({})
        with pytest.raises(ManagementTransportError, match="missing"):
            self._validated_transport(windows_scenario, scenario_path, utm=utm)
        assert utm.calls == ["find_by_uuid"]

    def test_template_registry_identity_mismatch_rejected_before_runner_calls(
        self, windows_scenario: Scenario, tmp_path: Path
    ) -> None:
        scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
        metadata = _persisted(scenario_path, _metadata(windows_scenario))
        stale = BaseTemplate(
            id="rf-base-windows-11-arm64",
            image_id="windows-11-arm64",
            backend=VMBackend.UTM,
            architecture=Architecture.ARM64,
            reference=TEMPLATE_NAME,
            status=TemplateState.READY,
            source_checksum="0" * 64,
            created_by_version="test",
            fingerprint="b" * 64,
        )
        utm = RecordingUTM({metadata.vm.name: VMState.RUNNING})
        with pytest.raises(ManagementTransportError, match="trusted template registry"):
            self._validated_transport(
                windows_scenario,
                scenario_path,
                utm=utm,
                template_manager=StubTemplates(stale),
            )
        assert utm.calls == []

    def test_validated_transport_is_windows_powershell_strategy(
        self, windows_scenario: Scenario, tmp_path: Path
    ) -> None:
        scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
        metadata = _persisted(scenario_path, _metadata(windows_scenario))
        resolved = self._validated_transport(
            windows_scenario,
            scenario_path,
            utm=RecordingUTM({metadata.vm.name: VMState.RUNNING}),
        )
        assert isinstance(resolved, _WindowsPowerShellTransport)
        assert resolved.language is ExecutionLanguage.POWERSHELL
        assert resolved.vm_name == metadata.vm.name
        assert resolved.guest_root == ROOT

    def test_source_and_base_survive_failed_operations(
        self, windows_scenario: Scenario, tmp_path: Path
    ) -> None:
        scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
        metadata = _persisted(scenario_path, _metadata(windows_scenario))
        vms = {metadata.vm.name: VMState.STOPPED, TEMPLATE_NAME: VMState.STOPPED}
        utm = RecordingUTM(vms)
        with pytest.raises(ManagementTransportError):
            self._validated_transport(windows_scenario, scenario_path, utm=utm)
        assert vms[TEMPLATE_NAME] is VMState.STOPPED
        assert TEMPLATE_NAME in utm.vms

    def test_corrupted_persisted_metadata_fails_closed(
        self, windows_scenario: Scenario, tmp_path: Path
    ) -> None:
        scenario_path = ScenarioYamlSerializer().dump(windows_scenario, tmp_path)
        runtime_yaml = scenario_path.parent / "runtime" / "runtime.yaml"
        runtime_yaml.parent.mkdir(parents=True, exist_ok=True)
        runtime_yaml.write_text("{ not: [valid: yaml", encoding="utf-8")
        utm = RecordingUTM({})
        with pytest.raises(ManagementTransportError):
            self._validated_transport(windows_scenario, scenario_path, utm=utm)
        assert utm.calls == []


class TestGuestCommandRunnerDecoding:
    def test_invalid_guest_bytes_decode_with_replacement(self, monkeypatch) -> None:
        """Arbitrary guest output must never raise UnicodeDecodeError."""
        import subprocess

        import rangeforge.runtime_primitives.transport as transport_module

        class FakeCompleted:
            returncode = 7
            stdout = b"\xff\xfe binary \x80 output"
            stderr = b"\xc3\x28 invalid stderr"

        def fake_run(*args: object, **kwargs: object) -> FakeCompleted:
            assert "text" not in kwargs or kwargs["text"] is None
            return FakeCompleted()

        monkeypatch.setattr(transport_module.subprocess, "run", fake_run)
        result = transport_module.run_guest_command(("utmctl", "list"), "", 5)
        assert result.returncode == 7
        assert "\ufffd" in result.stdout
        assert "\ufffd" in result.stderr
        assert subprocess  # imported for clarity of what is patched


class TestPolicyHelpers:
    def test_transport_kind_mapping(self) -> None:
        assert (
            management_transport_kind(VMBackend.UTM)
            is ManagementTransportKind.QEMU_GUEST_AGENT
        )
        assert (
            management_transport_kind(VMBackend.VAGRANT)
            is ManagementTransportKind.VAGRANT_SSH
        )

    def test_language_matrix(self) -> None:
        assert (
            management_language(GuestPlatform.WINDOWS, VMBackend.UTM)
            is ExecutionLanguage.POWERSHELL
        )
        assert (
            management_language(GuestPlatform.LINUX, VMBackend.UTM)
            is ExecutionLanguage.SHELL
        )
        assert management_language(GuestPlatform.WINDOWS, VMBackend.VAGRANT) is None


class TestReadinessProbe:
    class FakeWindowsTransport:
        language = ExecutionLanguage.POWERSHELL

        def __init__(
            self,
            *,
            identity: str = "RF_PROBE ps=5 arch=ARM64",
            roundtrip: bool = True,
            removed: bool = True,
            clean_count: int = 0,
            exit_code: int = 42,
            outcome: ManagementOutcome = ManagementOutcome.COMPLETED,
        ) -> None:
            self.identity = identity
            self.roundtrip = roundtrip
            self.removed = removed
            self.clean_count = clean_count
            self.exit_code = exit_code
            self.outcome = outcome
            self.staged: dict[str, bytes] = {}

        def _completed(self, stdout: str = "", exit_code: int = 0) -> ManagementResult:
            return ManagementResult(
                outcome=self.outcome,
                exit_code=exit_code,
                stdout=stdout,
                marker_verified=self.outcome is ManagementOutcome.COMPLETED,
            )

        def run(self, script: str, *, timeout: float = 120) -> ManagementResult:
            if self.outcome is not ManagementOutcome.COMPLETED:
                return ManagementResult(outcome=self.outcome, detail="probe failure")
            if "RF_PROBE" in script:
                return self._completed(self.identity)
            if "RF_READ" in script:
                if not self.roundtrip:
                    return self._completed("RF_READ:mismatched")
                content = next(iter(self.staged.values()), b"").decode("ascii")
                return self._completed(f"RF_READ:{content}")
            if "RF_GONE" in script:
                self.staged.clear()
                return self._completed(f"RF_GONE:{1 if self.removed else 0}")
            if "RF_CLEAN" in script:
                return self._completed(f"RF_CLEAN:{self.clean_count}")
            if script.strip() == f"exit {42}":
                return self._completed("", exit_code=self.exit_code)
            return self._completed()

        def stage(self, source: Path, name: str, *, timeout: float = 300) -> ManagementResult:
            self.staged[name] = source.read_bytes()
            return ManagementResult(outcome=ManagementOutcome.COMPLETED, exit_code=0)

    def test_probe_passes_on_healthy_arm64_clone(self) -> None:
        probe = _run_readiness_probe(
            self.FakeWindowsTransport(), expected_architecture=Architecture.ARM64
        )
        assert probe.ok is True
        names = {check.name for check in probe.checks}
        assert {
            "qga_execution",
            "powershell_version",
            "guest_architecture",
            "marker_integrity",
            "file_round_trip",
            "staged_cleanup",
            "exit_code_propagation",
            "workspace_clean",
        } <= names

    def test_probe_fails_closed_on_each_degraded_signal(self) -> None:
        cases = {
            "qga_execution": dict(outcome=ManagementOutcome.TIMEOUT),
            "powershell_version": dict(identity="RF_PROBE ps=4 arch=ARM64"),
            "guest_architecture": dict(identity="RF_PROBE ps=5 arch=AMD64"),
            "file_round_trip": dict(roundtrip=False),
            "staged_cleanup": dict(removed=False),
            "workspace_clean": dict(clean_count=2),
            "exit_code_propagation": dict(exit_code=0),
        }
        for expected_failure, kwargs in cases.items():
            probe = _run_readiness_probe(
                self.FakeWindowsTransport(**kwargs),
                expected_architecture=Architecture.ARM64,
            )
            assert probe.ok is False, expected_failure
            failed = {check.name for check in probe.checks if not check.passed}
            assert expected_failure in failed

    def test_probe_scripts_create_no_credentials_flags_or_services(self) -> None:
        import rangeforge.runtime.management as management_module

        scripts = [
            value
            for name, value in vars(management_module).items()
            if name.startswith("_PROBE") and isinstance(value, str)
        ]
        for script in scripts:
            lowered = script.lower()
            for forbidden in ("password", "flag", "user ", "net user", "service install"):
                assert forbidden not in lowered


class TestProbeBudget:
    """One bounded monotonic budget governs every readiness operation."""

    class _RecordingTransport:
        language = ExecutionLanguage.POWERSHELL

        def __init__(self) -> None:
            self.timeouts: list[float] = []
            self.run_calls = 0
            self.stage_calls = 0
            self.staged: dict[str, bytes] = {}

        @staticmethod
        def _completed(stdout: str = "", exit_code: int = 0) -> ManagementResult:
            return ManagementResult(
                outcome=ManagementOutcome.COMPLETED,
                exit_code=exit_code,
                stdout=stdout,
                marker_verified=True,
            )

        def run(self, script: str, *, timeout: float = 120) -> ManagementResult:
            self.timeouts.append(timeout)
            self.run_calls += 1
            if "RF_PROBE" in script:
                return self._completed("RF_PROBE ps=5 arch=ARM64")
            if "RF_READ:" in script:
                content = next(iter(self.staged.values()), b"").decode("ascii")
                return self._completed(f"RF_READ:{content}")
            if "RF_GONE" in script:
                self.staged.clear()
                return self._completed("RF_GONE:1")
            if "RF_CLEAN" in script:
                return self._completed("RF_CLEAN:0")
            if script.strip() == "exit 42":
                return ManagementResult(
                    outcome=ManagementOutcome.COMPLETED,
                    exit_code=42,
                    marker_verified=True,
                )
            return self._completed()

        def stage(self, source: Path, name: str, *, timeout: float = 300) -> ManagementResult:
            self.timeouts.append(timeout)
            self.stage_calls += 1
            self.staged[name] = source.read_bytes()
            return ManagementResult(outcome=ManagementOutcome.COMPLETED, exit_code=0)

    class _SteppingClock:
        def __init__(self, step: float) -> None:
            self.value = 0.0
            self.step = step

        def __call__(self) -> float:
            self.value += self.step
            return self.value

    def test_probe_timeouts_are_non_increasing_and_bounded(self) -> None:
        transport = self._RecordingTransport()
        clock = self._SteppingClock(7.0)
        probe = _run_readiness_probe(
            transport, expected_architecture=Architecture.ARM64, clock=clock
        )
        assert probe.ok is True
        assert transport.timeouts
        assert all(t <= 300.0 for t in transport.timeouts)
        assert all(
            first >= second
            for first, second in itertools.pairwise(transport.timeouts)
        )

    def test_probe_exhaustion_records_remaining_checks_failed(self) -> None:
        transport = self._RecordingTransport()

        readings = iter([0.0, 1.0, 500.0, 600.0, 700.0, 800.0, 900.0])

        def clock() -> float:
            value = next(readings, 1000.0)
            return value

        probe = _run_readiness_probe(
            transport, expected_architecture=Architecture.ARM64, clock=clock
        )
        # Only the identity operation ran before the budget expired.
        assert transport.run_calls == 1
        assert transport.stage_calls == 0
        passed = {check.name for check in probe.checks if check.passed}
        failed = {check.name for check in probe.checks if not check.passed}
        assert {"qga_execution", "powershell_version", "guest_architecture"} <= passed
        assert {
            "file_round_trip",
            "staged_cleanup",
            "exit_code_propagation",
            "workspace_clean",
        } <= failed
        assert probe.ok is False

    def test_probe_happy_path_unchanged_with_default_clock(self) -> None:
        transport = self._RecordingTransport()
        probe = _run_readiness_probe(
            transport, expected_architecture=Architecture.ARM64
        )
        assert probe.ok is True

    def test_probe_accepts_explicit_total_budget(self) -> None:
        transport = self._RecordingTransport()
        clock = self._SteppingClock(7.0)
        probe = _run_readiness_probe(
            transport,
            expected_architecture=Architecture.ARM64,
            clock=clock,
            total_budget=45.0,
        )
        assert probe.ok is True
        assert transport.timeouts
        assert all(t <= 45.0 for t in transport.timeouts)
        # The default total budget is preserved for direct callers.
        transport2 = self._RecordingTransport()
        _run_readiness_probe(transport2, expected_architecture=Architecture.ARM64)
        assert all(t <= 300.0 for t in transport2.timeouts)

    def test_probe_windows_management_forwards_explicit_budget(
        self, scenario: Scenario, tmp_path: Path
    ) -> None:
        import rangeforge.runtime.management as management_module

        observed: dict[str, object] = {}

        def fake_transport_factory(*args: object, **kwargs: object) -> object:
            return self._RecordingTransport()

        def fake_probe(channel: object, **kwargs: object) -> ManagementProbeResult:
            observed["total_budget"] = kwargs.get("total_budget")
            return ManagementProbeResult(ok=True, checks=())

        with (
            patch.object(
                management_module,
                "_owned_management_transport",
                side_effect=fake_transport_factory,
            ),
            patch.object(
                management_module,
                "_run_readiness_probe",
                side_effect=fake_probe,
            ),
        ):
            management_module.probe_windows_management(
                scenario,
                tmp_path,
                host=HOST,
                utm=RecordingUTM({}),
                vagrant=RecordingVagrant(False),
                template_manager=StubTemplates(None),
                expected_architecture=Architecture.ARM64,
                total_budget=33.0,
            )
        assert observed["total_budget"] == 33.0


class TestAbsoluteDeadlineUnderLockContention:
    """The bounded deadline is absolute: a contended per-VM lock cannot extend it."""

    def test_expired_deadline_after_lock_wait_fails_closed_without_guest_calls(
        self,
    ) -> None:
        """Waits: when the lock is held past the deadline, no guest call runs."""
        import threading

        import rangeforge.runtime.management as management_module

        fake = FakeGuest()
        manager = _WindowsPowerShellTransport(
            executable=UTMCTL,
            vm_name="rf-lock-deadline",
            runner=fake.run,
            file_runner=fake.file_run,
            sleeper=fake.sleeper,
        )
        # Pre-acquire the per-VM lock so the transport blocks waiting for it.
        lock = management_module._vm_lock("rf-lock-deadline")
        lock.acquire()

        def release_later() -> None:
            lock.release()

        release = threading.Timer(0.05, release_later)
        release.start()
        try:
            result = manager.run("exit 0\n", timeout=0.01)
        finally:
            # Never leak the global per-VM lock into later tests, even when an
            # assertion or transport call fails.
            release.join(timeout=1.0)
            if lock.locked():
                lock.release()
        # The deadline expired before the lock became available: fail closed
        # and never issue a guest command.
        assert result.outcome is ManagementOutcome.TIMEOUT
        assert fake.commands == []
        assert fake.uploads == []
        assert not lock.locked()

    def test_healthy_run_still_completes_within_budget(self) -> None:
        """A normal run without contention completes unchanged."""
        fake = FakeGuest()
        manager = transport(fake)
        result = manager.run("exit 0\n", timeout=120)
        assert result.outcome is ManagementOutcome.COMPLETED

    def test_stage_lock_wait_is_bounded_and_released(
        self, tmp_path: Path
    ) -> None:
        import threading

        import rangeforge.runtime.management as management_module

        source = tmp_path / "payload.bin"
        source.write_bytes(b"payload")
        fake = FakeGuest()
        vm_name = "rf-stage-lock-deadline"
        manager = _WindowsPowerShellTransport(
            executable=UTMCTL,
            vm_name=vm_name,
            runner=fake.run,
            file_runner=fake.file_run,
            sleeper=fake.sleeper,
        )
        lock = management_module._vm_lock(vm_name)
        lock.acquire()
        release = threading.Timer(0.05, lock.release)
        release.start()
        try:
            result = manager.stage(source, "payload.bin", timeout=0.01)
        finally:
            release.join(timeout=1.0)
            if lock.locked():
                lock.release()
        assert result.outcome is ManagementOutcome.TIMEOUT
        assert fake.commands == []
        assert fake.uploads == []
        assert not lock.locked()


class TestEscalatedWorkspaceClean:
    """The workspace check excludes its own escalated -rN body files."""

    def test_escalated_workspace_clean_script_reports_clean(self) -> None:
        """An escalated clean body derives the same digest prefix as gen zero.

        Regression: an escalated body name such as ``rf-<digest>-r1.body.ps1``
        must still exclude its own in-flight files so the workspace check
        reports RF_CLEAN:0 instead of counting its own files as residue.
        """
        import rangeforge.runtime.management as management_module

        script = management_module._PROBE_CLEAN_SCRIPT
        digest = digest_of(script)
        body_zero = f"{ROOT}\\rf-{digest}.body.ps1"
        fake = FakeGuest(
            locked_push_paths={body_zero},
            locked_pull_paths={body_zero},
        )
        fake.directories.add(ROOT)
        # A resident file that exactly matches the script is our own stale
        # artifact, so the push over the locked gen-zero name escalates.
        fake.files[body_zero] = script.encode("utf-8-sig")
        manager = transport(fake)
        result = manager.run(script, timeout=120)
        assert result.outcome is ManagementOutcome.COMPLETED
        assert result.exit_code == 0
        assert result.stdout.strip() == "RF_CLEAN:0"

    def test_near_prefix_foreign_residue_is_not_excluded(self) -> None:
        import rangeforge.runtime.management as management_module

        script = management_module._PROBE_CLEAN_SCRIPT
        digest = digest_of(script)
        fake = FakeGuest()
        manager = transport(fake)
        assert manager.run("exit 0\n", timeout=120).outcome is ManagementOutcome.COMPLETED
        foreign = f"{ROOT}\\rf-{digest}-rogue.bin"
        fake.files[foreign] = b"foreign"
        fake.locked_pull_paths.add(foreign)
        result = manager.run(script, timeout=120)
        assert result.outcome is ManagementOutcome.COMPLETED
        assert result.stdout.strip() == "RF_CLEAN:1"


class TestUnverifiedUploadNeverSubmits:
    """BLOCKER 1 regression: tuple-truthiness must never launch unverified."""

    def test_sweep_push_failure_never_submits_exec(self) -> None:
        """A failed sweep push over foreign content never submits an exec."""
        fake = FakeGuest(locked_push_paths={SWEEP_PATH})
        fake.files[SWEEP_PATH] = b"\xef\xbb\xbfWrite-Output 'foreign'\n"
        manager = transport(fake)
        result = manager.run("exit 0\n", timeout=30)
        assert result.outcome is ManagementOutcome.TRANSPORT_FAILURE
        assert "sweep" in (result.detail or "")
        assert not any("rf-sweep" in path for path in fake.exec_targets)
        assert manager._root_ready is False
        assert manager._swept is False

    def test_sweep_unreadable_resident_escalates_original_never_execs(self) -> None:
        import rangeforge.runtime.management as management_module

        content = management_module._sweep_script().encode("utf-8-sig")
        fake = FakeGuest(
            locked_push_paths={SWEEP_PATH},
            locked_pull_paths={SWEEP_PATH},
        )
        fake.files[SWEEP_PATH] = content
        result = transport(fake).run("exit 0\n", timeout=120)
        assert result.outcome is ManagementOutcome.COMPLETED
        escalated = [
            path for path in fake.exec_targets if path.endswith("rf-sweep-r1.ps1")
        ]
        assert len(escalated) == 1
        assert not any(path == SWEEP_PATH for path in fake.exec_targets)

    def test_best_effort_cleanup_skips_exec_when_upload_unverified(self) -> None:
        """Unverified best-effort uploads never submit an exec."""
        import rangeforge.runtime.management as management_module

        digest = digest_of("exit 0\n")
        clean_logical = f"{ROOT}\\rf-{digest}.clean.ps1"
        script_text = management_module._cleanup_script(digest)

        # Expired budget: prompt return, no commands at all.
        fake = FakeGuest()
        manager = transport(fake)
        expired = manager.clock()
        before = len(fake.commands)
        manager._best_effort_cleanup(digest, deadline=expired)
        assert len(fake.commands) == before

        # Foreign resident behind a locked push: classification fails
        # closed, so the unverified script is never launched.
        fake2 = FakeGuest(locked_push_paths={clean_logical})
        fake2.files[clean_logical] = (
            script_text.replace("RangeForge", "Foreign")
        ).encode("utf-8-sig")
        manager2 = transport(fake2)
        manager2._best_effort_cleanup(digest, deadline=manager2.clock() + 30.0)
        assert not any(
            path.endswith(".clean.ps1") for path in fake2.exec_targets
        )

    def test_best_effort_cleanup_unreadable_resident_escalates(self) -> None:
        digest = digest_of("exit 0\n")
        clean_logical = f"{ROOT}\\rf-{digest}.clean.ps1"
        import rangeforge.runtime.management as management_module

        content = management_module._cleanup_script(digest).encode("utf-8-sig")
        fake = FakeGuest(
            mutate_body_pulls=True,
            locked_push_paths={clean_logical},
            locked_pull_paths={clean_logical},
        )
        fake.files[clean_logical] = content
        manager = transport(fake)
        result = manager.run("exit 0\n", timeout=30)
        assert result.outcome is ManagementOutcome.TIMEOUT
        original_execs = [
            path for path in fake.exec_targets if path == clean_logical
        ]
        assert original_execs == []
        fake.drain()
        escalated = [
            path
            for path in fake.exec_targets
            if path.endswith(f"rf-{digest}-r1.clean.ps1")
        ]
        assert len(escalated) == 1

    def test_best_effort_remove_skips_exec_when_upload_unverified(self) -> None:
        """Foreign resident behind a locked push: no exec, fail closed."""
        target = f"{ROOT}\\stale-payload.bin"
        token = __import__("hashlib").sha256(target.encode()).hexdigest()[:16]
        clean_logical = f"{ROOT}\\rf-{token}.clean.ps1"
        fake = FakeGuest(locked_push_paths={clean_logical})
        fake.files[clean_logical] = b"\xef\xbb\xbfWrite-Output 'foreign'\n"
        manager = transport(fake)
        before = len(fake.exec_targets)
        manager._best_effort_remove(target, deadline=manager.clock() + 30.0)
        assert len(fake.exec_targets) == before


class TestManagedNamespaceEscalation:
    """BLOCKER 5: unreadable residents in our rf-* namespace escalate."""

    @pytest.mark.parametrize(
        ("locked_path", "label"),
        [
            (BOOTSTRAP_PATH, "bootstrap"),
            (WARMUP_PATH, "warmup"),
            (SWEEP_PATH, "sweep"),
        ],
    )
    def test_permanently_locked_fixed_name_escalates_to_r1(
        self, locked_path: str, label: str
    ) -> None:
        import rangeforge.runtime.management as management_module

        builders = {
            BOOTSTRAP_PATH: management_module._bootstrap_script,
            WARMUP_PATH: management_module._warmup_script,
            SWEEP_PATH: management_module._sweep_script,
        }
        content = builders[locked_path]().encode("utf-8-sig")
        fake = FakeGuest(
            locked_push_paths={locked_path},
            locked_pull_paths={locked_path},
        )
        fake.files[locked_path] = content
        result = transport(fake).run("exit 0\n", timeout=120)
        assert result.outcome is ManagementOutcome.COMPLETED, label
        escalated_suffix = locked_path.rsplit("\\", 1)[-1].replace(
            ".ps1", "-r1.ps1"
        )
        escalated_execs = [
            path for path in fake.exec_targets if path.endswith(escalated_suffix)
        ]
        assert len(escalated_execs) == 1, label
        assert not any(path == locked_path for path in fake.exec_targets)

    def test_readable_foreign_resident_still_fails_closed(self) -> None:
        fake = FakeGuest(locked_push_paths={WARMUP_PATH})
        fake.files[WARMUP_PATH] = b"\xef\xbb\xbfWrite-Output 'foreign'\n"
        result = transport(fake).run("exit 0\n", timeout=30)
        assert result.outcome is ManagementOutcome.TRANSPORT_FAILURE
        assert "warmup" in (result.detail or "")
        assert not any("rf-warmup" in path for path in fake.exec_targets)


class TestProbeIdentityArchitectureGate:
    """BLOCKER 6: unknown CIM architecture fails closed without fallback."""

    def test_unknown_architecture_fails_guest_check_only(self) -> None:
        class UnknownArchTransport(TestReadinessProbe.FakeWindowsTransport):
            def __init__(self) -> None:
                super().__init__(identity="RF_PROBE ps=5 arch=UNKNOWN")

        probe = _run_readiness_probe(
            UnknownArchTransport(), expected_architecture=Architecture.ARM64
        )
        by_name = {check.name: check.passed for check in probe.checks}
        assert by_name["guest_architecture"] is False
        assert by_name["qga_execution"] is True
        assert by_name["powershell_version"] is True
        assert probe.ok is False

    def test_identity_script_has_no_environment_architecture_fallback(self) -> None:
        import rangeforge.runtime.management as management_module

        script = management_module._PROBE_IDENTITY_SCRIPT
        assert "PROCESSOR_ARCHITECTURE" not in script
        assert "$env:" not in script
        assert "'UNKNOWN'" in script


class TestGenerationCoherentFrame:
    """BLOCKER 3: the frame executes the verified body generation."""

    def test_forced_body_escalation_flows_into_frame_and_polls(self) -> None:
        """Locked gen-0 body push escalates; the frame embeds ``-r1``."""
        script = "#FAKE:OUTPUT:escalated\nexit 0\n"
        digest = digest_of(script)
        body_logical = f"{ROOT}\\rf-{digest}.body.ps1"

        # The stale gen-0 body is resident AND permanently QGA-locked:
        # pushes over it report code-0+locked stderr, pulls report the
        # locked diagnostic (TRANSIENT), and the pre-clean wildcard cannot
        # delete it. Only managed-namespace escalation escapes this.
        fake = FakeGuest(
            locked_push_paths={body_logical},
            locked_pull_paths={body_logical},
        )
        fake.files[body_logical] = script.encode("utf-8-sig")
        manager = transport(fake)
        result = manager.run(script, timeout=120)
        assert result.outcome is ManagementOutcome.COMPLETED
        assert result.exit_code == 0
        assert result.stdout == "escalated"

        # The uploaded frame embeds the escalated body literal plus the
        # exact result/done literals the host polls.
        frame_upload = next(
            content.decode("utf-8-sig")
            for path, content in fake.uploads
            if path.endswith(".frame.ps1")
        )
        assert f"$rfBodyPath = '{ROOT}\\rf-{digest}-r1.body.ps1'" in frame_upload
        assert f"$rfResultPath = '{ROOT}\\rf-{digest}.out'" in frame_upload
        assert f"$rfDonePath = '{ROOT}\\rf-{digest}.done'" in frame_upload

        # The fake executed the literals the frame embedded: its derived
        # body path is exactly the escalated concrete name.
        assert fake.last_frame_paths is not None
        assert fake.last_frame_paths[0] == f"{ROOT}\\rf-{digest}-r1.body.ps1"
        assert fake.last_frame_paths[1] == f"{ROOT}\\rf-{digest}.out"
        assert fake.last_frame_paths[2] == f"{ROOT}\\rf-{digest}.done"

        # The frame submitted is exactly the escalated-name frame; the
        # poisoned gen-0 body was never executed by anything.
        frame_execs = [
            path for path in fake.exec_targets if path.endswith(".frame.ps1")
        ]
        assert len(frame_execs) == 1
        assert not any(path == body_logical for path in fake.exec_targets)

        # Marker/result polls used the same current-generation names the
        # frame wrote (gen-0 for out/done: RangeForge never pushes them).
        done_pulls = [
            command[-1]
            for command in fake.commands
            if command[1:3] == ("file", "pull") and command[-1].endswith(".done")
        ]
        assert done_pulls[-1] == f"{ROOT}\\rf-{digest}.done"


class TestManagedPathPolicy:
    """ITEM 3: only exact managed names may escalate on TRANSIENT."""

    @pytest.mark.parametrize(
        "foreign_path",
        [
            "C:\\Windows\\Temp\\rf-foreign.ps1",
            f"{ROOT}\\rf-foreign.body.ps1",
        ],
    )
    def test_foreign_locked_resident_fails_closed_without_escalation(
        self, foreign_path: str
    ) -> None:

        script = "exit 0\n"
        fake = FakeGuest(
            locked_push_paths={foreign_path},
            locked_pull_paths={foreign_path},
        )
        # A permanently locked resident RangeForge never wrote: unreadable,
        # so ownership of the inode cannot be proven.
        fake.files[foreign_path] = b"\xef\xbb\xbfWrite-Output 'alien'\n"
        manager = transport(fake)
        uploaded, concrete = manager._upload_verified(
            foreign_path, script, manager.clock() + 30.0
        )
        assert uploaded is False
        assert concrete == foreign_path
        # No generation was consumed and no exec was submitted anywhere.
        assert manager._generations == {}
        assert fake.exec_targets == []
