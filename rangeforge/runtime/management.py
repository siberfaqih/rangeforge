"""Owned-scenario management transport control plane.

Management transports are infrastructure control channels for RangeForge-owned
scenario clones. They are never attack-graph data, never accept arbitrary
targets, and resolve every parameter from ``scenario.yaml`` plus persisted
RangeForge-owned runtime metadata. Every construction validates ownership,
guest platform, architecture, host/backend policy, trusted template identity,
and an allowlisted platform/backend/transport/language tuple before any
backend runner invocation.
"""

from __future__ import annotations

import contextlib
import hashlib
import re
import tempfile
import threading
import time
from collections.abc import Callable
from enum import StrEnum
from pathlib import Path
from typing import Final, Protocol

from rangeforge.host.models import Architecture, HostInfo
from rangeforge.images.manager import ImageManagerError
from rangeforge.images.templates import TemplateManager
from rangeforge.models import Scenario, StrictModel
from rangeforge.runtime.backends.base import CommandResult
from rangeforge.runtime.backends.utm import UTMBackend
from rangeforge.runtime.backends.vagrant import VagrantBackend
from rangeforge.runtime.metadata import RuntimeMetadataError, RuntimeMetadataStore
from rangeforge.runtime.models import (
    ExecutionLanguage,
    GuestPlatform,
    ManagementOutcome,
    ManagementResult,
    ManagementTransportKind,
    RuntimeMetadata,
    VMBackend,
    VMState,
)
from rangeforge.runtime.resolver import VM_HOST_BACKENDS
from rangeforge.runtime_primitives.transport import (
    GuestCommandRunner,
    GuestFileRunner,
    GuestTransport,
    UTMGuestTransport,
    VagrantGuestTransport,
    run_guest_command,
    run_guest_file,
)

__all__ = [
    "ManagementCheck",
    "ManagementProbeResult",
    "ManagementTransportError",
    "effective_guest_platform",
    "management_language",
    "management_transport_kind",
    "owned_guest_transport",
    "probe_windows_management",
    "safe_stage_name",
    "validate_management_target",
]


class ManagementTransportError(ValueError):
    """Raised when a management transport cannot be used safely."""


_MANAGEMENT_TRANSPORT_MATRIX: Final = (
    (
        GuestPlatform.LINUX,
        VMBackend.UTM,
        ManagementTransportKind.QEMU_GUEST_AGENT,
        ExecutionLanguage.SHELL,
    ),
    (
        GuestPlatform.LINUX,
        VMBackend.VAGRANT,
        ManagementTransportKind.VAGRANT_SSH,
        ExecutionLanguage.SHELL,
    ),
    (
        GuestPlatform.WINDOWS,
        VMBackend.UTM,
        ManagementTransportKind.QEMU_GUEST_AGENT,
        ExecutionLanguage.POWERSHELL,
    ),
)

_FINGERPRINT_CHARS = frozenset("0123456789abcdef")


def management_transport_kind(backend: VMBackend) -> ManagementTransportKind:
    """Map a VM backend onto its single infrastructure control channel."""
    if backend is VMBackend.UTM:
        return ManagementTransportKind.QEMU_GUEST_AGENT
    return ManagementTransportKind.VAGRANT_SSH


def management_language(
    platform: GuestPlatform, backend: VMBackend
) -> ExecutionLanguage | None:
    """Return the allowlisted execution language for a platform/backend pair."""
    for entry_platform, entry_backend, _, language in _MANAGEMENT_TRANSPORT_MATRIX:
        if entry_platform is platform and entry_backend is backend:
            return language
    return None


def effective_guest_platform(metadata: RuntimeMetadata) -> GuestPlatform:
    """Resolve the guest platform of persisted metadata.

    Metadata written before platform-aware builds carries no platform. Such
    legacy metadata describes the original Linux-only builds and is therefore
    only ever read back as Linux; it can never be inferred as Windows-capable.
    """
    return metadata.guest.platform or GuestPlatform.LINUX


def _scenario_platform(scenario: Scenario) -> GuestPlatform | None:
    normalized = scenario.scenario.platform.strip().lower()
    for platform in GuestPlatform:
        if platform.value == normalized:
            return platform
    return None


def validate_management_target(
    scenario: Scenario,
    scenario_path: Path,
    *,
    host: HostInfo,
    utm: UTMBackend,
    vagrant: VagrantBackend,
    language: ExecutionLanguage,
    platform: GuestPlatform | None = None,
    template_manager: TemplateManager | None = None,
) -> RuntimeMetadata:
    """Load and fully validate persisted metadata before any runner call.

    All persisted-metadata checks (ownership, template identity, platform,
    backend policy, architecture, and the allowlisted transport tuple) run
    before any backend command. Only then are local resource existence and
    running-state checks performed.

    ``template_manager`` is optional only so focused unit tests can exercise
    this low-level gate directly. The public factories
    (:func:`probe_windows_management` and :func:`owned_guest_transport`)
    require it, so every production transport construction performs trusted
    template reconciliation.
    """
    store = RuntimeMetadataStore(scenario_path)
    try:
        metadata = store.load()
    except RuntimeMetadataError as exc:
        # Corrupted or tampered persisted metadata must fail closed as a
        # transport error, never escape as an unexpected exception.
        raise ManagementTransportError(str(exc)) from exc
    if metadata is None:
        raise ManagementTransportError(
            "No persisted RangeForge runtime metadata was found beside scenario.yaml."
        )
    try:
        store.validate_ownership(scenario, metadata)
    except RuntimeMetadataError as exc:
        raise ManagementTransportError(str(exc)) from exc

    template = metadata.template
    if not (
        template.image_id and template.template_id and template.name and template.fingerprint
    ):
        raise ManagementTransportError("Persisted base-template identity is incomplete.")
    if len(template.fingerprint) != 64 or set(template.fingerprint) - _FINGERPRINT_CHARS:
        raise ManagementTransportError(
            "Persisted base-template fingerprint failed integrity verification."
        )

    effective_platform = effective_guest_platform(metadata)
    scenario_platform = _scenario_platform(scenario)
    if scenario_platform is not None and scenario_platform is not effective_platform:
        raise ManagementTransportError(
            "Persisted guest platform does not match the scenario platform."
        )
    if platform is not None and effective_platform is not platform:
        raise ManagementTransportError(
            f"Persisted guest platform '{effective_platform.value}' does not match the "
            f"requested '{platform.value}' management transport."
        )

    kind = management_transport_kind(metadata.backend)
    if (
        metadata.guest.management_transport is not None
        and metadata.guest.management_transport is not kind
    ):
        raise ManagementTransportError(
            "Persisted management transport does not match the persisted backend."
        )
    if (
        metadata.guest.execution_language is not None
        and metadata.guest.execution_language is not language
    ):
        raise ManagementTransportError(
            "Persisted execution language does not match the requested management language."
        )
    if (
        effective_platform,
        metadata.backend,
        kind,
        language,
    ) not in _MANAGEMENT_TRANSPORT_MATRIX:
        if effective_platform is GuestPlatform.WINDOWS and metadata.backend is VMBackend.VAGRANT:
            raise ManagementTransportError(
                "Windows Vagrant management is unsupported; Windows management requires "
                "UTM with the QEMU Guest Agent."
            )
        raise ManagementTransportError(
            f"The '{effective_platform.value}/{metadata.backend.value}/{kind.value}/"
            f"{language.value}' management combination is not allowlisted."
        )

    expected_backend = VM_HOST_BACKENDS.get((host.os, host.architecture))
    if expected_backend is None or metadata.backend is not expected_backend:
        raise ManagementTransportError(
            "The persisted VM backend is not valid for this host platform."
        )
    if metadata.guest.architecture is not host.architecture:
        raise ManagementTransportError(
            "Guest architecture does not match the host architecture; silent "
            "cross-architecture management is not permitted."
        )

    if template_manager is not None:
        try:
            prepared = template_manager.require_ready(template.image_id, metadata.backend)
        except ImageManagerError as exc:
            raise ManagementTransportError(str(exc)) from exc
        if (
            prepared.id,
            prepared.reference,
            prepared.fingerprint,
        ) != (template.template_id, template.name, template.fingerprint):
            raise ManagementTransportError(
                "Persisted base-template identity does not match the trusted template registry."
            )

    if metadata.backend is VMBackend.UTM:
        if utm.executable is None:
            raise ManagementTransportError("Owned UTM scenario VM is unavailable.")
        if not utm.vm_exists(metadata.vm.name):
            raise ManagementTransportError("Owned UTM scenario VM is missing.")
        if utm.vm_state(metadata.vm.name) is not VMState.RUNNING:
            raise ManagementTransportError("Owned UTM scenario VM is not running.")
    else:
        if vagrant.executable is None:
            raise ManagementTransportError("Owned Vagrant scenario environment is unavailable.")
        if not vagrant.environment_exists(store.vagrant_directory):
            raise ManagementTransportError("Owned Vagrant scenario environment is missing.")
        if vagrant.vm_state(store.vagrant_directory) is not VMState.RUNNING:
            raise ManagementTransportError("Owned Vagrant scenario environment is not running.")
    return metadata


class _ManagementChannel(Protocol):
    """Typed infrastructure control channel for one owned scenario VM.

    Private by design: guest commands are only ever built internally from
    verified uploads, so no arbitrary-command surface is exposed.
    """

    language: ExecutionLanguage

    def run(self, script: str, *, timeout: float = 120) -> ManagementResult: ...

    def stage(self, source: Path, name: str, *, timeout: float = 300) -> ManagementResult: ...


_STAGE_NAME_PATTERN = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_RESERVED_DEVICE_NAMES = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *(f"COM{number}" for number in range(1, 10)),
        *(f"LPT{number}" for number in range(1, 10)),
    }
)


def safe_stage_name(name: str) -> str:
    """Validate a filename for guest staging under the fixed transport root.

    The strict ASCII allowlist rejects traversal, absolute caller paths, UNC
    and device paths, drive changes, alternate data streams, mixed separators,
    control characters, and Unicode look-alikes by construction. Reserved
    Windows device names and trailing dots are rejected explicitly.
    """
    if not isinstance(name, str) or not _STAGE_NAME_PATTERN.fullmatch(name):
        raise ManagementTransportError(
            "Staged filename is outside the RangeForge safe-name policy."
        )
    if name.split(".", 1)[0].upper() in _RESERVED_DEVICE_NAMES:
        raise ManagementTransportError("Staged filename uses a reserved Windows device name.")
    if name.endswith("."):
        raise ManagementTransportError("Staged filename must not end with a dot.")
    return name


_MAX_SCRIPT_BYTES: Final = 256_000
_MAX_OUTPUT_CHARS: Final = 100_000
_MAX_DIAGNOSTIC_CHARS: Final = 400
_CLEANUP_TIMEOUT: Final = 10.0
_MARKER_PATTERN: Final = re.compile(r"^RF_MGMT_COMPLETE:(-?\d+):([0-9a-f]{16})$", re.MULTILINE)
_WINDOWS_TRANSPORT_ROOT: Final = "C:\\ProgramData\\RangeForge\\Transport"
# Fixed existing Windows path used only to deliver the one-shot bootstrap
# script; the QEMU Guest Agent file push cannot create parent directories.
_BOOTSTRAP_GUEST_PATH: Final = "C:\\Windows\\Temp\\rf-bootstrap.ps1"
# Fixed absolute built-in Windows PowerShell executable. Real UTM 4.7.5 QGA
# requires the full path; a bare interpreter token is never used.
_POWERSHELL_EXECUTABLE: Final = (
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
)
_POWERSHELL_ARGUMENTS: Final = (
    "-NoLogo",
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy",
    "Bypass",
)

_LOCK_GUARD = threading.Lock()
_VM_LOCKS: dict[str, threading.Lock] = {}


def _vm_lock(vm_name: str) -> threading.Lock:
    """Serialize transport operations targeting the same scenario VM."""
    with _LOCK_GUARD:
        lock = _VM_LOCKS.get(vm_name)
        if lock is None:
            lock = threading.Lock()
            _VM_LOCKS[vm_name] = lock
        return lock


def _bounded(text: str, limit: int = _MAX_DIAGNOSTIC_CHARS) -> str:
    return " ".join(text.split())[:limit]


def _transport_failure(detail: str, *, stderr: str = "") -> ManagementResult:
    return ManagementResult(
        outcome=ManagementOutcome.TRANSPORT_FAILURE,
        detail=_bounded(detail),
        stderr=_bounded(stderr),
    )


def _timeout_result() -> ManagementResult:
    return ManagementResult(
        outcome=ManagementOutcome.TIMEOUT,
        detail="Management operation exceeded its single bounded deadline.",
    )


class _GuestFileState(StrEnum):
    """Explicit QGA guest-file transfer state for one ``utmctl file pull``.

    Real UTM 4.7.5 reports host code 0 for missing and locked files and
    distinguishes them only through stderr diagnostics, so return codes alone
    can never classify a pull.
    """

    AVAILABLE = "available"
    MISSING = "missing"
    TRANSIENT = "transient"


class _LaunchOutcome(StrEnum):
    """Typed result of one ``_launch_script`` call.

    ``SUBMITTED`` means the host accepted the request; guest completion is
    still unknown and governed by markers/self-deletion. Every other outcome
    fails closed: ``LOCAL_FAILURE`` is a definite local invocation error,
    ``UNDELIVERED_EXHAUSTED`` means every submission was provably rejected
    with the RPC-timeout diagnostic (or the deadline expired mid-retry), and
    ``AMBIGUOUS`` covers results whose delivery state cannot be proven —
    resubmitting those could duplicate execution.
    """

    SUBMITTED = "submitted"
    LOCAL_FAILURE = "local_failure"
    UNDELIVERED_EXHAUSTED = "undelivered_exhausted"
    AMBIGUOUS = "ambiguous"


# Conservative lowercase diagnostics that uniquely identify a missing guest
# file. Anything else — locked/in-use text, unknown errors, or nonzero host
# codes — is TRANSIENT/ERROR and must never be treated as absence.
_MISSING_PULL_DIAGNOSTICS: Final = (
    "cannot find the file specified",
    "no such file",
)

# The only exec diagnostic that provably means the request was not
# delivered; it is the sole retry-eligible launch outcome.
_LAUNCH_RETRY_DIAGNOSTIC: Final = "timed out waiting for rpc"

# Bounded deterministic name escalation: at most three total attempts
# (generation 0 plus suffixes -r1 and -r2) per logical guest path, used to
# escape guest-side poisoned/locked artifacts without re-using the inode.
_MAX_GENERATIONS: Final = 3

# Bounded resubmission of a provably undelivered (RPC-timeout) exec within
# one launch call before failing closed.
_LAUNCH_RPC_ATTEMPTS: Final = 3

# Disposable channel-warmup probe. It lives in the fixed existing Temp
# directory so a file poisoned by the cold-boot exec wedge never pollutes
# the Transport root, and it self-deletes so successful warmup leaves no
# residue.
_WARMUP_GUEST_PATH: Final = "C:\\Windows\\Temp\\rf-warmup.ps1"

# One-shot recovery sweep for clones damaged by earlier interrupted
# operations. Lives in the fixed existing Temp directory; the script removes
# every rf-* entry inside ONLY the fixed Transport root and deletes itself.
_SWEEP_GUEST_PATH: Final = "C:\\Windows\\Temp\\rf-sweep.ps1"


def _classify_guest_pull(result: CommandResult) -> _GuestFileState:
    """Classify one raw ``utmctl file pull`` result.

    * code 0 + empty stderr => AVAILABLE, even when stdout is empty (a valid
      guest script may produce an empty ``.out``).
    * code 0 + a known missing-file diagnostic => MISSING.
    * locked/in-use stderr, unknown stderr, or nonzero codes => TRANSIENT.
    """
    if result.returncode == 0 and not result.stderr:
        return _GuestFileState.AVAILABLE
    if result.returncode == 0:
        stderr = result.stderr.lower()
        if any(diagnostic in stderr for diagnostic in _MISSING_PULL_DIAGNOSTICS):
            return _GuestFileState.MISSING
    return _GuestFileState.TRANSIENT


def _semantic_success(result: CommandResult) -> bool:
    """Semantic host-call success for QGA pushes and launches.

    Real UTM 4.7.5 reports host code 0 with diagnostics on stderr for
    transfers that did not land and launches that did not start (for example
    ``Timed out waiting for RPC`` or ``Invalid parameter type ...``), so a
    call counts as successful only when the code is 0 AND stderr is empty.
    """
    return result.returncode == 0 and not result.stderr


class _WindowsPowerShellTransport:
    """Manage an owned Windows ARM64 UTM clone through QGA and PowerShell.

    Private by design: instances are handed out only through
    :func:`_owned_management_transport` after full ownership validation, and
    every guest command is built internally — there is no public API that
    accepts an arbitrary guest command.

    The executable and argv are fixed: ``utmctl exec`` invokes the absolute
    built-in Windows PowerShell interpreter with ``-NoLogo -NoProfile
    -NonInteractive -ExecutionPolicy Bypass -File`` and never a
    caller-supplied command. Scripts are uploaded with UTF-8 BOM encoding
    (Windows PowerShell 5.1 compatible), executed from deterministic
    content-derived paths under the fixed guest root, and results are pulled
    and decoded explicitly. A content/hash-bound completion marker preserves
    the guest exit status, one bounded deadline governs the whole operation,
    output is size-bounded, and cleanup is verified on the success path and
    best-effort on error paths.

    Real UTM 4.7.5 QGA semantics are modeled explicitly: ``utmctl exec``
    returns immediately while the guest process continues asynchronously,
    and ``utmctl file pull`` reports host code 0 for missing and locked
    files, distinguished only through stderr diagnostics. Pulls are
    classified into explicit AVAILABLE / MISSING / TRANSIENT states — code 0
    alone is never success, an empty ``.out`` is a valid empty result, and
    only a non-empty well-formed marker is accepted.     Pushes are validated
    the same way: code 0 with any stderr means the transfer did not land and
    fails closed — unless the resident file at that exact name is our own
    stale artifact, in which case the bounded deterministic generation
    escalates to a fresh suffixed name (at most three attempts per logical
    name) instead of re-pushing over a guest-side poisoned inode or
    executing unverified resident files. Every script upload passes a
    deterministic barrier — validated push, then read-back verification
    patient to the operation deadline — before exec submission. Before any
    of that, a disposable self-deleting warmup probe in the fixed Temp
    directory absorbs the cold-boot exec wedge: a submission inside the
    wedge permanently locks its target file on the guest, so the probe keeps
    that poisoning away from Transport-root work files, and the channel is
    gated on the probe's observed execution. After bootstrap readiness, a
    one-shot fixed sweep removes every ``rf-*`` entry inside only the fixed
    Transport root — recovering clones damaged by earlier interrupted
    operations whose files stayed QGA-locked until the channel was healthy —
    and the root is not marked ready until the sweep is verified. A clean
    code-0 exec submission is asynchronous: the guest command executes
    later (delays up to tens of seconds observed), so only the hash-bound
    completion marker or observed self-deletion is authoritative. Code 0
    with ``Timed out waiting for RPC`` provably means the request was not
    delivered; it is retried with presence-guarded bounded backoff and is
    the only retryable diagnostic — anything else fails closed. Every
    submission is followed by
    bounded polling for observable completion, and digest-scoped absence
    verification always resolves the current generation only, computed after
    all escalation decisions of the operation. Before each body upload a
    mandatory digest-scoped pre-clean removes and verifies absence of any
    stale same-digest files (including escalated name variants) so repeated
    identical scripts can never replay an old marker or output. Script
    content, encoded payloads, credentials, and secret canaries never appear
    in errors, logs, or metadata.
    """

    language = ExecutionLanguage.POWERSHELL

    def __init__(
        self,
        *,
        executable: Path,
        vm_name: str,
        runner: GuestCommandRunner = run_guest_command,
        file_runner: GuestFileRunner = run_guest_file,
        sleeper: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.executable = executable
        self.vm_name = vm_name
        self.runner = runner
        self.file_runner = file_runner
        self.sleeper = sleeper
        self.clock = clock
        # Deterministic name-escalation generations per logical guest path.
        # Mutated only under the per-VM operation lock.
        self._generations: dict[str, int] = {}
        # Set once the fixed guest root has been bootstrapped on this owned
        # clone. All mutations happen under the per-VM operation lock.
        self._root_ready = False
        # Set once the disposable warmup probe has executed successfully,
        # proving the exec channel is past any cold-boot wedge window.
        self._channel_warm = False
        # Set once the one-shot rf-* root sweep has executed successfully
        # after bootstrap readiness (recovers previously damaged clones).
        self._swept = False

    @property
    def guest_root(self) -> str:
        return _WINDOWS_TRANSPORT_ROOT

    def _push_argv(self, guest_path: str) -> tuple[str, ...]:
        return (str(self.executable), "file", "push", self.vm_name, guest_path)

    def _concrete_path(self, logical_path: str) -> str:
        """Resolve a logical guest path onto its current generation.

        Generation 0 returns the path unchanged; generation N (1-based
        suffix ``-rN``) inserts the suffix after the file stem so role tags
        stay terminal: ``rf-bootstrap.ps1`` → ``rf-bootstrap-r2.ps1``,
        ``rf-<digest>.body.ps1`` → ``rf-<digest>-r2.body.ps1``.
        """
        generation = self._generations.get(logical_path, 0)
        if generation <= 0:
            return logical_path
        parent, separator, name = logical_path.rpartition("\\")
        stem, _, rest = name.partition(".")
        escalated_name = f"{stem}-r{generation}.{rest}"
        return f"{parent}{separator}{escalated_name}"

    def _escalate_generation(self, logical_path: str) -> bool:
        """Escalate the deterministic name for one logical path.

        Bounded at ``_MAX_GENERATIONS`` total attempts per logical name;
        False means every deterministic name has been exhausted and the
        caller must fail closed.
        """
        current = self._generations.get(logical_path, 0)
        if current + 1 >= _MAX_GENERATIONS:
            return False
        self._generations[logical_path] = current + 1
        return True

    def _validated_push(
        self, guest_path: str, content: bytes, deadline: float
    ) -> tuple[bool, CommandResult]:
        """Push a guest file and judge success semantically.

        A push counts as landed only when the host code is 0 AND stderr is
        empty; real UTM 4.7.5 reports code 0 with a locked-file diagnostic
        when the transfer did not land. Callers must fail closed on False and
        never launch the target script or claim staging success.
        """
        pushed = self.file_runner(self._push_argv(guest_path), content, self._remaining(deadline))
        return _semantic_success(pushed), pushed

    def _pull_argv(self, guest_path: str) -> tuple[str, ...]:
        return (str(self.executable), "file", "pull", self.vm_name, guest_path)

    def _exec_argv(self, guest_script_path: str) -> tuple[str, ...]:
        return (
            str(self.executable),
            "exec",
            self.vm_name,
            "--cmd",
            _POWERSHELL_EXECUTABLE,
            *_POWERSHELL_ARGUMENTS,
            "-File",
            guest_script_path,
        )

    def run(self, script: str, *, timeout: float = 120) -> ManagementResult:
        if timeout <= 0:
            return _transport_failure("Management timeout must be positive.")
        # The absolute deadline is captured BEFORE the per-VM lock wait so a
        # contended lock can never extend the caller's bounded budget.
        deadline = self.clock() + timeout
        lock = _vm_lock(self.vm_name)
        remaining = self._remaining(deadline)
        if remaining <= 0 or not lock.acquire(timeout=remaining):
            return _timeout_result()
        try:
            return self._execute_script(script, _deadline=deadline)
        finally:
            lock.release()

    def stage(self, source: Path, name: str, *, timeout: float = 300) -> ManagementResult:
        safe_name = safe_stage_name(name)
        if timeout <= 0:
            return _transport_failure("Management timeout must be positive.")
        # The source read and the per-VM lock wait both consume the same
        # absolute staging budget.
        deadline = self.clock() + timeout
        try:
            content = source.read_bytes()
        except OSError as exc:
            return _transport_failure("Staged artifact could not be read.", stderr=str(exc))
        destination = f"{_WINDOWS_TRANSPORT_ROOT}\\{safe_name}"
        lock = _vm_lock(self.vm_name)
        remaining = self._remaining(deadline)
        if remaining <= 0 or not lock.acquire(timeout=remaining):
            return _timeout_result()
        try:
            bootstrap = self._ensure_guest_root(deadline)
            if bootstrap is not None:
                return bootstrap
            pushed_ok, pushed = self._validated_push(destination, content, deadline)
            if not pushed_ok:
                return _transport_failure(
                    "Staged artifact upload failed.", stderr=pushed.stderr
                )
            expected = (
                f"RF_STAGED:{len(content)}:{hashlib.sha256(content).hexdigest()}"
            )
            verification = self._execute_script(
                _verification_script(destination, expected),
                _deadline=deadline,
                _bootstrap=False,
            )
            if (
                verification.outcome is not ManagementOutcome.COMPLETED
                or verification.exit_code != 0
                or verification.stdout.strip() != expected
            ):
                self._best_effort_remove(destination, deadline=deadline)
                return _transport_failure("Staged artifact verification failed.")
            return ManagementResult(
                outcome=ManagementOutcome.COMPLETED,
                exit_code=0,
                stdout="",
                marker_verified=True,
            )
        finally:
            lock.release()

    def _remaining(self, deadline: float) -> float:
        """Remaining budget of the current operation; never negative."""
        return max(deadline - self.clock(), 0.0)

    def _pull_state(
        self, guest_path: str, deadline: float
    ) -> tuple[_GuestFileState, CommandResult]:
        """Pull a guest file and classify the transfer semantically."""
        result = self.runner(self._pull_argv(guest_path), "", self._remaining(deadline))
        return _classify_guest_pull(result), result

    def _sleep_slice(self, deadline: float) -> bool:
        """Sleep one bounded poll slice; False when the deadline has expired."""
        remaining = self._remaining(deadline)
        if remaining <= 0:
            return False
        self.sleeper(min(1.0, max(remaining, 0.01)))
        return True

    def _upload_pause(self, deadline: float) -> bool:
        """Pause between upload attempts, clamped to the remaining budget.

        The pause never exceeds the remaining operation deadline; False means
        the deadline expired and the caller must fail closed.
        """
        remaining = self._remaining(deadline)
        if remaining <= 0:
            return False
        self.sleeper(min(1.0, remaining))
        return True

    def _await_upload_visible(
        self, guest_path: str, script: str, deadline: float
    ) -> bool:
        """Patiently poll until the pushed file reads back exactly ``script``.

        Cold-boot pull visibility can take far longer than warm transfers, so
        verification is bounded only by the caller's single deadline:
        MISSING/TRANSIENT/mismatched pulls wait and retry; only expiry
        returns False.
        """
        expected = script.strip()
        while self._remaining(deadline) > 0:
            if not self._sleep_slice(deadline):
                break
            state, pulled = self._pull_state(guest_path, deadline)
            if (
                state is _GuestFileState.AVAILABLE
                and _decode_pull(pulled.stdout) == expected
            ):
                return True
        return False

    def _managed_namespace_path(self, guest_path: str) -> bool:
        """True for guest paths inside RangeForge's managed namespace.

        Exact policy — anything else (for example ``rf-foreign.ps1``) is NOT
        managed, so a locked push over it fails closed with no escalation:

        * Temp managed: basename ``rf-(warmup|bootstrap|sweep)(-r\\d+)?\\.ps1``
          inside the fixed existing Temp directory.
        * Transport-root managed: basename
          ``rf-[0-9a-f]{16}(-r\\d+)?\\.(body|frame|clean)\\.ps1`` inside the
          fixed Transport root.
        """
        parent, _, name = guest_path.rpartition("\\")
        if parent == "C:\\Windows\\Temp":
            return (
                re.fullmatch(r"rf-(warmup|bootstrap|sweep)(-r\d+)?\.ps1", name)
                is not None
            )
        if parent == _WINDOWS_TRANSPORT_ROOT:
            return (
                re.fullmatch(
                    r"rf-[0-9a-f]{16}(-r\d+)?\.(body|frame|clean)\.ps1", name
                )
                is not None
            )
        return False

    def _upload_verified(
        self, logical_path: str, script: str, deadline: float
    ) -> tuple[bool, str]:
        """Deterministic upload barrier before any PowerShell launch.

        Mirrors the proven Linux UTM transport behavior for UTM 4.7.5. The
        concrete script is pushed exactly once per deterministic name: a
        semantic validated push (code 0, no stderr) that fails — including
        the real code-0-with-locked-stderr case — triggers exactly one
        semantic pull of that concrete path. Only our own stale artifact
        (AVAILABLE with exact decoded content, or — for names inside our
        managed ``rf-*`` namespace — an unreadable TRANSIENT resident)
        escalates the bounded deterministic generation for the logical name
        and retries the push once under the fresh name; anything else fails
        closed immediately. Escalation never consumes a generation after the
        caller's deadline has expired. After the accepted push, verification
        is patient and bounded only by the caller's single deadline.
        Returns ``(False, concrete_path)`` when the caller must not launch;
        ``(True, concrete_path)`` with the concrete path that was verified
        otherwise.
        """
        encoded = script.encode("utf-8-sig")
        guest_path = self._concrete_path(logical_path)
        pushed_ok, _ = self._validated_push(guest_path, encoded, deadline)
        if not pushed_ok:
            state, pulled = self._pull_state(guest_path, deadline)
            # An unreadable TRANSIENT resident inside our managed rf-*
            # namespace is treated as our stale poisoned artifact and
            # escalated, because it can never be content-verified while
            # locked. Readable residents must match exactly.
            own_stale = (
                state is _GuestFileState.AVAILABLE
                and _decode_pull(pulled.stdout) == script.strip()
            )
            transient_managed = (
                state is _GuestFileState.TRANSIENT
                and self._managed_namespace_path(guest_path)
            )
            may_escalate = self._remaining(deadline) > 0
            if (
                (own_stale or transient_managed)
                and may_escalate
                and self._escalate_generation(logical_path)
            ):
                # Our own stale poisoned artifact: escape to a fresh name.
                guest_path = self._concrete_path(logical_path)
                pushed_ok, _ = self._validated_push(guest_path, encoded, deadline)
                if not pushed_ok:
                    return False, guest_path
            else:
                return False, guest_path
        return self._await_upload_visible(guest_path, script, deadline), guest_path

    def _launch_script(
        self, guest_path: str, deadline: float
    ) -> _LaunchOutcome:
        """Submit exec attempts until UTM accepts one; never duplicate.

        Definitive owned-clone traces prove two distinct host behaviors:

        * code 0 with empty stderr: the request was accepted and the guest
          command executes asynchronously — observed delays up to ~30
          seconds. The host result is never guest completion; callers keep
          polling their authoritative signal (hash-bound marker or observed
          self-deletion) to the deadline.
        * code 0 with ``Timed out waiting for RPC``: the request was
          provably NOT delivered and waiting is futile. This is the only
          diagnostic eligible for resubmission: before each retry the
          verified target script must still be AVAILABLE — if it has become
          MISSING the script already ran and ``SUBMITTED`` is returned —
          with one bounded sleep slice between attempts, capped at
          ``_LAUNCH_RPC_ATTEMPTS`` rejections before reporting
          ``UNDELIVERED_EXHAUSTED``. The script is never re-uploaded.

        Anything else fails closed as ``LOCAL_FAILURE`` or ``AMBIGUOUS``
        without retry:

        * runner-synthetic local failure (code 125 / OSError / unavailable
          executable): definite local invocation failure.
        * nonzero codes, host timeout code 124, or any other stderr:
          ambiguous — the request may have been delivered, so retrying
          risks duplicate execution.

        argv and script content are never surfaced in diagnostics.
        """
        # Resolve through the current generation so a previously escalated
        # logical name submits its fresh concrete file.
        guest_path = self._concrete_path(guest_path)
        rejected = 0
        while self._remaining(deadline) > 0:
            result = self.runner(
                self._exec_argv(guest_path), "", self._remaining(deadline)
            )
            if _semantic_success(result):
                return _LaunchOutcome.SUBMITTED
            if result.returncode == 125:
                # Runner-synthetic OSError: utmctl could not be invoked.
                return _LaunchOutcome.LOCAL_FAILURE
            stderr = result.stderr.lower()
            if not (
                result.returncode == 0
                and _LAUNCH_RETRY_DIAGNOSTIC in stderr
            ):
                # Ambiguous delivery: fail closed instead of risking a
                # duplicate execution.
                return _LaunchOutcome.AMBIGUOUS
            state, _ = self._pull_state(guest_path, deadline)
            if state is _GuestFileState.MISSING:
                # The script already executed despite the RPC diagnostic.
                return _LaunchOutcome.SUBMITTED
            if state is not _GuestFileState.AVAILABLE:
                # Presence can no longer be proven: unsafe to resubmit.
                return _LaunchOutcome.AMBIGUOUS
            rejected += 1
            if rejected >= _LAUNCH_RPC_ATTEMPTS:
                return _LaunchOutcome.UNDELIVERED_EXHAUSTED
            if not self._sleep_slice(deadline):
                break
        return _LaunchOutcome.UNDELIVERED_EXHAUSTED

    def _await_file_absent(self, guest_path: str, deadline: float) -> bool:
        """Poll until a guest file is observably MISSING.

        Accepts logical or concrete paths and resolves through the current
        generation. The caller has just successfully pushed the file, which
        proves it was present; no presence pull is required. Only the
        explicit MISSING state counts as gone: locked or otherwise transient
        pulls keep being retried within the remaining budget.
        """
        guest_path = self._concrete_path(guest_path)
        while self._remaining(deadline) > 0:
            state, _ = self._pull_state(guest_path, deadline)
            if state is _GuestFileState.MISSING:
                return True
            if not self._sleep_slice(deadline):
                break
        return False

    def _await_files_absent(self, guest_paths: tuple[str, ...], deadline: float) -> bool:
        for guest_path in guest_paths:
            state, _ = self._pull_state(guest_path, deadline)
            if state is not _GuestFileState.MISSING:
                return False
        return True

    def _digest_logical_paths(self, digest: str) -> tuple[str, str, str, str, str]:
        """Logical (generation-zero) names for one digest-scoped operation."""
        root = _WINDOWS_TRANSPORT_ROOT
        return (
            f"{root}\\rf-{digest}.body.ps1",
            f"{root}\\rf-{digest}.frame.ps1",
            f"{root}\\rf-{digest}.out",
            f"{root}\\rf-{digest}.done",
            f"{root}\\rf-{digest}.clean.ps1",
        )

    def _current_digest_paths(self, digest: str) -> tuple[str, str, str, str, str]:
        """Current-generation concrete paths for the five logical names.

        Callers must resolve at use time — after every escalation decision
        of the enclosing operation — so absence verification never mixes
        generations.
        """
        concrete = [self._concrete_path(path) for path in self._digest_logical_paths(digest)]
        return (
            concrete[0],
            concrete[1],
            concrete[2],
            concrete[3],
            concrete[4],
        )

    def _run_digest_cleanup(self, digest: str, deadline: float) -> bool:
        """Launch the digest-scoped cleanup script and verify completion.

        The cleanup script is pushed through the escalation-aware barrier,
        submitted once, and polled until its own concrete path is absent.
        Absence is then verified for the replay-critical current-generation
        result/done pair only: stale body/frame/clean residents cannot
        replay a marker (this operation overwrites or escalates them), and
        a permanently QGA-locked older name must not fail the check. No
        call exceeds the remaining budget.
        """
        if self._remaining(deadline) <= 0:
            return False
        clean_logical = self._digest_logical_paths(digest)[4]
        clean_ok, clean_concrete = self._upload_verified(
            clean_logical, _cleanup_script(digest), deadline
        )
        if not clean_ok:
            return False
        if self._launch_script(clean_concrete, deadline) is not _LaunchOutcome.SUBMITTED:
            return False
        if not self._await_file_absent(clean_concrete, deadline):
            return False
        _, _, result_concrete, done_concrete, _ = self._current_digest_paths(digest)
        return self._await_files_absent(
            (result_concrete, done_concrete), deadline
        )

    def _pre_clean(self, digest: str, deadline: float) -> ManagementResult | None:
        """Mandatory digest-scoped cleanup before any body/frame upload.

        Repeated identical scripts reuse deterministic content-derived names;
        without this step an old asynchronous ``.done``/``.out`` could be
        replayed as the new result. Failure to verify the pre-clean within
        the deadline fails closed: the new body is never executed.
        """
        if self._run_digest_cleanup(digest, deadline):
            return None
        if self._remaining(deadline) <= 0:
            return _timeout_result()
        return _transport_failure(
            "Digest-scoped pre-execution cleanup could not be verified."
        )

    def _warm_channel(self, deadline: float) -> ManagementResult | None:
        """Gate all real work behind one disposable warmup execution.

        Cold-boot exec submissions that land inside the RPC wedge window
        permanently lock the targeted file on the guest. Running the fixed
        self-deleting warmup probe first keeps any such poisoning on a
        disposable Temp file; only after the warmup has been observably
        executed (self-deleted) does bootstrap touch Transport-root paths.
        Uses the standard barrier (push-once validated, patient
        verification, generation escalation bounded at three for the warmup
        name) and the standard single-acceptance exec policy (clean code 0
        accepted; RPC-timeout resubmitted with presence guard). Cached per
        transport instance. Returns ``None`` when the channel is warm,
        otherwise a typed failure or timeout result.
        """
        if self._channel_warm:
            return None
        last_generation = self._generations.get(_WARMUP_GUEST_PATH, 0)
        while self._remaining(deadline) > 0:
            uploaded, _ = self._upload_verified(
                _WARMUP_GUEST_PATH, _warmup_script(), deadline
            )
            if not uploaded:
                if self._generations.get(_WARMUP_GUEST_PATH, 0) > last_generation:
                    last_generation = self._generations[_WARMUP_GUEST_PATH]
                    continue
                if self._remaining(deadline) <= 0:
                    return _timeout_result()
                return _transport_failure(
                    "Management channel warmup could not be verified."
                )
            outcome = self._launch_script(_WARMUP_GUEST_PATH, deadline)
            if outcome is _LaunchOutcome.SUBMITTED:
                if self._await_file_absent(_WARMUP_GUEST_PATH, deadline):
                    self._channel_warm = True
                    return None
                if self._remaining(deadline) <= 0:
                    return _timeout_result()
                return _transport_failure(
                    "Management channel warmup could not be verified."
                )
            if (
                outcome is _LaunchOutcome.UNDELIVERED_EXHAUSTED
                and self._generations.get(_WARMUP_GUEST_PATH, 0) > last_generation
            ):
                last_generation = self._generations[_WARMUP_GUEST_PATH]
                continue
            return self._launch_failure_result(
                outcome, "Management channel warmup launch failed.", deadline
            )
        return _timeout_result()

    def _sweep_root(self, deadline: float) -> ManagementResult | None:
        """One-shot sweep of RangeForge-owned ``rf-*`` root artifacts.

        Runs once per transport instance, right after bootstrap readiness
        proves the channel healthy: clones damaged by earlier interrupted
        operations hold permanently QGA-locked ``rf-*`` files that only
        become deletable once execution works again. The fixed sweep script
        is pushed through the standard barrier (push-once validated, patient
        verification, generation escalation bounded at three for the sweep
        name), submitted with the single-submission exec policy, and polled
        until observed self-deleted. It touches only ``rf-*`` names inside
        the fixed Transport root on this owned clone. Returns ``None`` when
        the sweep is verified, otherwise a typed failure or timeout result;
        the root is not marked ready until this succeeds.
        """
        if self._swept:
            return None
        if self._remaining(deadline) <= 0:
            return _timeout_result()
        uploaded, sweep_concrete = self._upload_verified(
            _SWEEP_GUEST_PATH, _sweep_script(), deadline
        )
        if not uploaded:
            if self._remaining(deadline) <= 0:
                return _timeout_result()
            return _transport_failure(
                "Management root sweep upload could not be verified."
            )
        outcome = self._launch_script(sweep_concrete, deadline)
        if outcome is not _LaunchOutcome.SUBMITTED:
            return self._launch_failure_result(
                outcome, "Management root sweep launch failed.", deadline
            )
        if not self._await_file_absent(_SWEEP_GUEST_PATH, deadline):
            if self._remaining(deadline) <= 0:
                return _timeout_result()
            return _transport_failure(
                "Management root sweep could not be verified."
            )
        self._swept = True
        return None

    def _ensure_guest_root(self, deadline: float) -> ManagementResult | None:
        """Bootstrap the fixed guest root once per transport instance.

        A clean Windows clone does not ship ``C:\\ProgramData\\RangeForge\\Transport``
        and the QEMU Guest Agent file push does not create parent directories.
        The fixed idempotent bootstrap script (``New-Item -Force`` plus
        self-delete) is uploaded to the fixed existing Windows path
        ``C:\\Windows\\Temp`` through the shared upload barrier — including
        bounded deterministic name escalation when a prior wedged boot left
        the previous name guest-side locked — and launched through the
        standard fixed PowerShell argv. Because ``utmctl exec`` is
        asynchronous, the root is marked ready only after the script is
        observed absent within the remaining budget. Runs under the caller's
        per-VM lock. Returns ``None`` when the root is ready, otherwise a
        typed failure or timeout result.
        """
        if self._root_ready:
            return None
        if self._remaining(deadline) <= 0:
            return _timeout_result()
        # Disposable warmup first: absorb any cold-boot exec wedge on a
        # Temp file so Transport-root work files are never its victim.
        warm = self._warm_channel(deadline)
        if warm is not None:
            return warm
        bootstrap_uploaded, _ = self._upload_verified(
            _BOOTSTRAP_GUEST_PATH, _bootstrap_script(), deadline
        )
        if not bootstrap_uploaded:
            if self._remaining(deadline) <= 0:
                return _timeout_result()
            return _transport_failure(
                "Management root bootstrap upload could not be verified."
            )
        launch_outcome = self._launch_script(_BOOTSTRAP_GUEST_PATH, deadline)
        if launch_outcome is not _LaunchOutcome.SUBMITTED:
            return self._launch_failure_result(
                launch_outcome,
                "Management root bootstrap launch failed.",
                deadline,
            )
        if not self._await_file_absent(_BOOTSTRAP_GUEST_PATH, deadline):
            if self._remaining(deadline) <= 0:
                return _timeout_result()
            return _transport_failure("Management root bootstrap could not be verified.")
        # Channel proven healthy and root present: sweep stale rf-* residue
        # left by earlier interrupted operations (one-shot, per instance).
        sweep = self._sweep_root(deadline)
        if sweep is not None:
            return sweep
        self._root_ready = True
        return None

    def _execute_script(
        self, script: str, *, _deadline: float, _bootstrap: bool = True
    ) -> ManagementResult:
        # The caller's bounded budget may have expired before entry (for
        # example while waiting for the per-VM lock): fail closed without
        # issuing any guest call.
        if self._remaining(_deadline) <= 0:
            return _timeout_result()
        encoded = script.encode("utf-8")
        if len(encoded) > _MAX_SCRIPT_BYTES:
            return _transport_failure(
                f"Script exceeds the {_MAX_SCRIPT_BYTES}-byte transport bound."
            )
        digest = hashlib.sha256(encoded).hexdigest()[:16]
        body_logical, frame_logical = self._digest_logical_paths(digest)[:2]
        deadline = _deadline

        if _bootstrap:
            bootstrap = self._ensure_guest_root(deadline)
            if bootstrap is not None:
                return bootstrap

        # Mandatory stale-replay prevention before any upload of this digest.
        pre_clean = self._pre_clean(digest, deadline)
        if pre_clean is not None:
            return pre_clean

        body_ok, body_concrete = self._upload_verified(body_logical, script, deadline)
        if not body_ok:
            self._best_effort_cleanup(digest, deadline=deadline)
            if self._remaining(deadline) <= 0:
                return _timeout_result()
            return _transport_failure("Guest script upload could not be verified.")

        # The body's escalation decision is final; resolve result/done now so
        # the frame embeds the exact current-generation literals it will
        # write and the host will poll.
        _, _, result_concrete, done_concrete, _ = self._current_digest_paths(digest)

        frame_ok, frame_concrete = self._upload_verified(
            frame_logical,
            _frame_script(body_concrete, result_concrete, done_concrete, digest),
            deadline,
        )
        if not frame_ok:
            self._best_effort_cleanup(digest, deadline=deadline)
            if self._remaining(deadline) <= 0:
                return _timeout_result()
            return _transport_failure(
                "Management frame upload could not be verified."
            )

        # utmctl exec returns immediately and a cold QGA channel can reject
        # the submission outright; the framed child writes a hash-bound
        # completion marker asynchronously. The host exec result itself is
        # never trusted for output or exit status, and transient missing or
        # locked pulls are never classified as integrity failures.
        launch_outcome = self._launch_script(frame_concrete, deadline)
        if launch_outcome is not _LaunchOutcome.SUBMITTED:
            self._best_effort_cleanup(digest, deadline=deadline)
            return self._launch_failure_result(
                launch_outcome, "Management frame launch failed.", deadline
            )

        exit_code: int | None = None
        while self._remaining(deadline) > 0:
            self._sleep_slice(deadline)
            state, pulled_done = self._pull_state(done_concrete, deadline)
            if state is not _GuestFileState.AVAILABLE:
                # MISSING and TRANSIENT (locked/unknown) are retried until
                # the single deadline expires.
                continue
            if not pulled_done.stdout:
                # An empty marker file is never a valid completion signal.
                continue
            match = _MARKER_PATTERN.search(pulled_done.stdout)
            if match is None or match.group(2) != digest:
                self._best_effort_cleanup(digest, deadline=deadline)
                return _transport_failure(
                    "Completion marker failed integrity verification."
                )
            exit_code = int(match.group(1))
            break
        if exit_code is None:
            self._best_effort_cleanup(digest, deadline=deadline)
            return _timeout_result()

        output: str | None = None
        while self._remaining(deadline) > 0:
            self._sleep_slice(deadline)
            state, pulled_result = self._pull_state(result_concrete, deadline)
            if state is not _GuestFileState.AVAILABLE:
                continue
            # AVAILABLE with empty stdout is a valid empty guest output.
            output = _decode_pull(pulled_result.stdout)
            break
        if output is None:
            self._best_effort_cleanup(digest, deadline=deadline)
            return _transport_failure("Guest result could not be retrieved.")
        if len(output) > _MAX_OUTPUT_CHARS:
            self._best_effort_cleanup(digest, deadline=deadline)
            return _transport_failure(
                f"Guest output exceeded the {_MAX_OUTPUT_CHARS}-character bound."
            )
        # Preserve the returned output and exit code, then remove and verify
        # absence of every file this operation created so the next probe or
        # workspace check can never race asynchronous cleanup. An unverifiable
        # cleanup is a typed transport failure, never a false success.
        if not self._run_digest_cleanup(digest, deadline):
            if self._remaining(deadline) <= 0:
                return _timeout_result()
            return _transport_failure(
                "Management operation cleanup could not be verified."
            )
        return ManagementResult(
            outcome=ManagementOutcome.COMPLETED,
            exit_code=exit_code,
            stdout=output,
            marker_verified=True,
        )

    def _cleanup_budget(self, deadline: float) -> float:
        """Best-effort cleanup may use only the remaining operation budget."""
        return min(_CLEANUP_TIMEOUT, self._remaining(deadline))

    def _launch_failure_result(
        self, outcome: _LaunchOutcome, message: str, deadline: float
    ) -> ManagementResult:
        """Map a non-submitted launch outcome onto a typed result."""
        if outcome is _LaunchOutcome.UNDELIVERED_EXHAUSTED and (
            self._remaining(deadline) <= 0
        ):
            return _timeout_result()
        return _transport_failure(message)

    def _best_effort_cleanup(self, digest: str, *, deadline: float) -> None:
        """Attempt bounded fire-and-forget removal for error paths."""
        budget = self._cleanup_budget(deadline)
        if budget <= 0:
            # No budget remains: return promptly instead of overrunning the
            # single bounded deadline.
            return
        with contextlib.suppress(Exception):
            cleanup_logical = f"{_WINDOWS_TRANSPORT_ROOT}\\rf-{digest}.clean.ps1"
            uploaded, cleanup_concrete = self._upload_verified(
                cleanup_logical, _cleanup_script(digest), deadline
            )
            if not uploaded:
                return
            self._launch_script(cleanup_concrete, deadline)

    def _best_effort_remove(self, guest_path: str, *, deadline: float) -> None:
        """Attempt bounded fire-and-forget removal of one staged guest file."""
        budget = self._cleanup_budget(deadline)
        if budget <= 0:
            return
        with contextlib.suppress(Exception):
            token = hashlib.sha256(guest_path.encode("utf-8")).hexdigest()[:16]
            cleanup_logical = f"{_WINDOWS_TRANSPORT_ROOT}\\rf-{token}.clean.ps1"
            script = (
                "$ErrorActionPreference = 'SilentlyContinue'\n"
                f"Remove-Item -LiteralPath '{guest_path}' -Force\n"
                "Remove-Item -LiteralPath $PSCommandPath -Force\n"
            )
            uploaded, cleanup_concrete = self._upload_verified(
                cleanup_logical, script, deadline
            )
            if not uploaded:
                return
            self._launch_script(cleanup_concrete, deadline)


def _decode_pull(text: str) -> str:
    """Decode pulled guest text, stripping the UTF-8 BOM when present."""
    if text.startswith("\ufeff"):
        text = text[1:]
    return text.strip()


def _frame_script(
    body_concrete: str, result_concrete: str, done_concrete: str, digest: str
) -> str:
    """Build the fixed PowerShell 5.1-compatible execution frame.

    Body, result, and done paths are the exact current-generation concrete
    literals resolved by the caller after all escalation decisions, so the
    frame always executes the verified body and writes the files the host
    polls — never a stale generation-zero name. The marker digest stays the
    content digest.
    """
    return (
        "$ErrorActionPreference = 'Continue'\n"
        f"$rfBodyPath = '{body_concrete}'\n"
        f"$rfResultPath = '{result_concrete}'\n"
        f"$rfDonePath = '{done_concrete}'\n"
        "Remove-Item -LiteralPath @($rfResultPath, $rfDonePath) -Force "
        "-ErrorAction SilentlyContinue\n"
        f"& '{_POWERSHELL_EXECUTABLE}' -NoLogo -NoProfile -NonInteractive "
        "-ExecutionPolicy Bypass -File $rfBodyPath 2>&1 |\n"
        "    ForEach-Object { $_.ToString() } |\n"
        "    Out-File -LiteralPath $rfResultPath -Encoding UTF8\n"
        "$rfCode = $LASTEXITCODE\n"
        "if ($null -eq $rfCode) { $rfCode = 1 }\n"
        "Set-Content -LiteralPath $rfDonePath "
        f"-Value ('RF_MGMT_COMPLETE:{{0}}:{{1}}' -f $rfCode, '{digest}') "
        "-Encoding Ascii\n"
        "Remove-Item -LiteralPath @($rfBodyPath, $PSCommandPath) -Force "
        "-ErrorAction SilentlyContinue\n"
        "exit $rfCode\n"
    )


def _cleanup_script(digest: str) -> str:
    return (
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        f"$rfRoot = '{_WINDOWS_TRANSPORT_ROOT}'\n"
        f"$rfDigest = '{digest}'\n"
        "Remove-Item -Path (Join-Path $rfRoot ('rf-' + $rfDigest + '*')) -Force\n"
        "Remove-Item -LiteralPath $PSCommandPath -Force\n"
    )


def _bootstrap_script() -> str:
    """Fixed one-shot creation of the fixed transport root.

    The script contains only the fixed root path, creates nothing else, and
    deletes itself from the fixed existing temp directory.
    """
    return (
        "$ErrorActionPreference = 'Stop'\n"
        f"New-Item -Path '{_WINDOWS_TRANSPORT_ROOT}' -ItemType Directory -Force "
        "| Out-Null\n"
        "Remove-Item -LiteralPath $PSCommandPath -Force\n"
        "exit 0\n"
    )


def _warmup_script() -> str:
    """Fixed disposable channel-warmup probe.

    The script does nothing except delete itself; its purpose is to absorb
    any cold-boot exec wedge on a disposable Temp file so real Transport-
    root work files are never the first submission inside the wedge window
    (a wedged execution permanently locks that file on the guest).
    """
    return (
        "$ErrorActionPreference = 'Stop'\n"
        "Remove-Item -LiteralPath $PSCommandPath -Force\n"
        "exit 0\n"
    )


def _sweep_script() -> str:
    """Fixed one-shot sweep of RangeForge-owned root artifacts.

    Removes every ``rf-*`` entry inside ONLY the fixed Transport root —
    recovering clones damaged by earlier interrupted operations whose files
    stayed QGA-locked until the channel was healthy — then deletes itself.
    Never touches any path outside that root.
    """
    return (
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        f"Get-ChildItem -LiteralPath '{_WINDOWS_TRANSPORT_ROOT}' -Filter 'rf-*' "
        "-Force | Remove-Item -Force\n"
        "Remove-Item -LiteralPath $PSCommandPath -Force\n"
        "exit 0\n"
    )


def _verification_script(destination: str, expected: str) -> str:
    return (
        f"$rfItem = Get-Item -LiteralPath '{destination}' -ErrorAction Stop\n"
        f"$rfHash = Get-FileHash -LiteralPath '{destination}' -Algorithm SHA256\n"
        f"if (('RF_STAGED:' + $rfItem.Length + ':' + $rfHash.Hash.ToLower()) -ne '{expected}') "
        "{ exit 3 }\n"
        "Write-Output ('RF_STAGED:' + $rfItem.Length + ':' + $rfHash.Hash.ToLower())\n"
        "exit 0\n"
    )


def _owned_management_transport(
    scenario: Scenario,
    scenario_path: Path,
    *,
    host: HostInfo,
    utm: UTMBackend,
    vagrant: VagrantBackend,
    language: ExecutionLanguage,
    template_manager: TemplateManager,
) -> _WindowsPowerShellTransport:
    """Resolve the Windows management transport after full ownership validation.

    Trusted template reconciliation is mandatory: the persisted template
    identity must match a READY entry in the trusted template registry before
    any transport is constructed. Linux scenarios never use this factory;
    they keep using :func:`owned_guest_transport`.
    """
    metadata = validate_management_target(
        scenario,
        scenario_path,
        host=host,
        utm=utm,
        vagrant=vagrant,
        language=language,
        template_manager=template_manager,
    )
    if effective_guest_platform(metadata) is not GuestPlatform.WINDOWS:
        raise ManagementTransportError(
            "The Windows management transport only serves owned Windows clones; "
            "Linux scenarios use the shell provisioning transport."
        )
    if metadata.backend is not VMBackend.UTM:
        # Validated above as unsupported; kept as an explicit guard.
        raise ManagementTransportError(  # pragma: no cover - validated above
            "Windows Vagrant management is unsupported."
        )
    if utm.executable is None:  # pragma: no cover - validated above
        raise ManagementTransportError("Owned UTM scenario VM is unavailable.")
    return _WindowsPowerShellTransport(executable=utm.executable, vm_name=metadata.vm.name)


def owned_guest_transport(
    scenario: Scenario,
    scenario_path: Path,
    *,
    host: HostInfo,
    utm: UTMBackend,
    vagrant: VagrantBackend,
    template_manager: TemplateManager,
) -> GuestTransport:
    """Resolve the Linux shell provisioning transport after ownership validation.

    Metadata is always loaded from the scenario's persisted runtime store;
    caller-supplied metadata objects are never trusted. Trusted template
    reconciliation is mandatory.
    """
    metadata = validate_management_target(
        scenario,
        scenario_path,
        host=host,
        utm=utm,
        vagrant=vagrant,
        language=ExecutionLanguage.SHELL,
        platform=GuestPlatform.LINUX,
        template_manager=template_manager,
    )
    if metadata.backend is VMBackend.UTM:
        if utm.executable is None:  # pragma: no cover - validated above
            raise ManagementTransportError("Owned UTM scenario VM is unavailable.")
        return UTMGuestTransport(utm.executable, metadata.vm.name)
    if vagrant.executable is None:  # pragma: no cover - validated above
        raise ManagementTransportError("Owned Vagrant scenario environment is unavailable.")
    return VagrantGuestTransport(
        vagrant.executable, RuntimeMetadataStore(scenario_path).vagrant_directory
    )


class ManagementCheck(StrictModel):
    name: str
    passed: bool


class ManagementProbeResult(StrictModel):
    ok: bool
    checks: tuple[ManagementCheck, ...] = ()


_PROBE_IDENTITY_SCRIPT: Final = (
    "$rfPs = $PSVersionTable.PSVersion.Major\n"
    "# Win32_Processor.Architecture queries real hardware, which matters\n"
    "# because Windows on ARM64 can run this interpreter as an emulated x64\n"
    "# process whose environment view disagrees with the machine.\n"
    "# 12=ARM64, 9=x64, 5=ARM, 0=x86; anything else is UNKNOWN and the\n"
    "# guest_architecture readiness check fails closed.\n"
    "$rfWmi = $null\n"
    "try { $rfWmi = (Get-CimInstance -ClassName Win32_Processor "
    "| Select-Object -First 1).Architecture } catch { }\n"
    "$rfArch = switch ($rfWmi) {\n"
    "    12 { 'ARM64' }\n"
    "    9 { 'AMD64' }\n"
    "    5 { 'ARM' }\n"
    "    0 { 'X86' }\n"
    "    default { 'UNKNOWN' }\n"
    "}\n"
    "Write-Output ('RF_PROBE ps=' + $rfPs + ' arch=' + $rfArch)\n"
    "exit 0\n"
)
_PROBE_IDENTITY_PATTERN: Final = re.compile(r"RF_PROBE ps=(\d+) arch=([A-Za-z0-9_]+)")
_PROBE_ARCHITECTURE_TOKENS: Final[dict[Architecture, str]] = {
    Architecture.ARM64: "ARM64",
    Architecture.AMD64: "AMD64",
}
_PROBE_CONTENT: Final = b"rangeforge-management-probe"
_PROBE_EXIT_CODE: Final = 42
# Bounded per-operation budget for every probe step. Real cold clones have
# shown ~30-second delayed execs, and the first operation also pays the
# warmup, bootstrap, sweep, and cleanup execs. The readiness probe spends
# one bounded total budget across all of its operations instead of a
# per-operation timeout.
_PROBE_TOTAL_BUDGET: Final = 300.0

# The workspace check runs through the transport itself, so its own
# content-derived body/frame/out/done/cleanup files are in flight while it
# executes. The digest is derived from $PSCommandPath (never by hashing the
# script, which would be circular) and only files sharing that digest prefix
# are excluded; every residual file from prior operations and every staged
# artifact is still detected.
_PROBE_CLEAN_SCRIPT: Final = (
    "$rfRoot = '" + _WINDOWS_TRANSPORT_ROOT + "'\n"
    "$rfOwnPattern = ''\n"
    "if ($PSCommandPath) {\n"
    "    $rfStem = [System.IO.Path]::GetFileNameWithoutExtension($PSCommandPath)\n"
    # Strip the generation suffix too: an escalated body name such as
    # rf-<digest>-r1.body derives the same digest prefix as generation zero,
    # so the check never counts its own in-flight files as residue.
    "    $rfDigest = $rfStem -replace '^rf-' , '' -replace '(-r\\d+)?\\.body$' , ''\n"
    "    if ($rfDigest -match '^[0-9a-f]{16}$') { "
    "$rfOwnPattern = '^rf-' + $rfDigest + '(-r\\d+)?\\.' }\n"
    "}\n"
    # The escalated -rN variants of this operation's own files (for example
    # rf-<digest>-r1.body.ps1) also carry the digest and are excluded by the
    # same prefix pattern, so an escalated workspace check never counts its
    # own in-flight files as residue.
    "if ($rfOwnPattern) {\n"
    "    $rfCount = @(Get-ChildItem -LiteralPath $rfRoot -Force | "
    "Where-Object { $_.Name -notmatch $rfOwnPattern }).Count\n"
    "} else {\n"
    "    $rfCount = @(Get-ChildItem -LiteralPath $rfRoot -Force).Count\n"
    "}\n"
    "Write-Output ('RF_CLEAN:' + $rfCount)\n"
    "exit 0\n"
)


def _run_readiness_probe(
    channel: _ManagementChannel,
    *,
    expected_architecture: Architecture,
    clock: Callable[[], float] = time.monotonic,
) -> ManagementProbeResult:
    """Run the fixed internal Windows management readiness probe.

    Private: the only public entry point is :func:`probe_windows_management`,
    which constructs the channel through mandatory ownership validation. The
    probe verifies QGA execution, the expected built-in PowerShell major
    version and guest CPU architecture, file staging round-trip, guest exit
    code propagation, completion-marker integrity, and workspace cleanup. It
    creates no vulnerability, student account, flag, credential, or persistent
    service, and it never targets a shared base template (transports can only
    be constructed for owned scenario clones).

    All operations share one monotonic total budget of ``_PROBE_TOTAL_BUDGET``
    seconds: every operation receives exactly the remaining budget, and once
    it is exhausted no further operations are issued — each remaining check
    is recorded as failed in deterministic order.
    """
    deadline = clock() + _PROBE_TOTAL_BUDGET
    checks: list[ManagementCheck] = []

    def record(name: str, passed: bool) -> None:
        checks.append(ManagementCheck(name=name, passed=passed))

    def budget_slice() -> float | None:
        remaining = deadline - clock()
        if remaining <= 0:
            return None
        return remaining

    def run_op(script: str) -> ManagementResult | None:
        timeout = budget_slice()
        if timeout is None:
            return None
        return channel.run(script, timeout=timeout)

    identity = run_op(_PROBE_IDENTITY_SCRIPT)
    if identity is None:
        record("qga_execution", False)
        record("powershell_version", False)
        record("guest_architecture", False)
        record("marker_integrity", False)
    else:
        record("qga_execution", identity.outcome is ManagementOutcome.COMPLETED)
        match = _PROBE_IDENTITY_PATTERN.search(identity.stdout)
        record("powershell_version", match is not None and int(match.group(1)) >= 5)
        expected_token = _PROBE_ARCHITECTURE_TOKENS.get(expected_architecture)
        record(
            "guest_architecture",
            match is not None
            and expected_token is not None
            and match.group(2) == expected_token,
        )
        record("marker_integrity", bool(identity.marker_verified))

    roundtrip_passed = False
    cleanup_passed = False
    with tempfile.NamedTemporaryFile(prefix="rf-probe-", suffix=".txt") as handle:
        handle.write(_PROBE_CONTENT)
        handle.flush()
        source = Path(handle.name)
        staged_name = (
            "rf-probe-" + hashlib.sha256(_PROBE_CONTENT).hexdigest()[:16] + ".txt"
        )
        staged_path = f"{_WINDOWS_TRANSPORT_ROOT}\\{staged_name}"
        staged_timeout = budget_slice()
        staged = (
            None
            if staged_timeout is None
            else channel.stage(source, staged_name, timeout=staged_timeout)
        )
        if (
            staged is not None
            and staged.outcome is ManagementOutcome.COMPLETED
            and staged.exit_code == 0
        ):
            expected_text = _PROBE_CONTENT.decode("ascii")
            read_back = run_op(
                f"Write-Output ('RF_READ:' + (Get-Content -Raw -LiteralPath "
                f"'{staged_path}'))\nexit 0\n"
            )
            roundtrip_passed = (
                read_back is not None
                and read_back.outcome is ManagementOutcome.COMPLETED
                and read_back.exit_code == 0
                and read_back.marker_verified
                and read_back.stdout.strip() == f"RF_READ:{expected_text}"
            )
        removed_timeout = budget_slice()
        removed = (
            None
            if removed_timeout is None
            else channel.run(
                f"Remove-Item -LiteralPath '{staged_path}' -Force "
                "-ErrorAction SilentlyContinue\n"
                "if (Test-Path -LiteralPath "
                f"'{staged_path}') {{ Write-Output 'RF_GONE:0' }} "
                "else { Write-Output 'RF_GONE:1' }\n"
                "exit 0\n",
                timeout=removed_timeout,
            )
        )
        cleanup_passed = (
            removed is not None
            and removed.outcome is ManagementOutcome.COMPLETED
            and removed.exit_code == 0
            and removed.marker_verified
            and removed.stdout.strip() == "RF_GONE:1"
        )
    record("file_round_trip", roundtrip_passed)
    record("staged_cleanup", cleanup_passed)

    exit_propagation = run_op(f"exit {_PROBE_EXIT_CODE}\n")
    if exit_propagation is None:
        record("exit_code_propagation", False)
        record("marker_integrity_probe", False)
    else:
        record(
            "exit_code_propagation",
            exit_propagation.outcome is ManagementOutcome.COMPLETED
            and exit_propagation.exit_code == _PROBE_EXIT_CODE,
        )
        record("marker_integrity_probe", bool(exit_propagation.marker_verified))

    workspace = run_op(_PROBE_CLEAN_SCRIPT)
    record(
        "workspace_clean",
        workspace is not None
        and workspace.outcome is ManagementOutcome.COMPLETED
        and workspace.stdout.strip() == "RF_CLEAN:0",
    )

    return ManagementProbeResult(
        ok=all(check.passed for check in checks), checks=tuple(checks)
    )


def probe_windows_management(
    scenario: Scenario,
    scenario_path: Path,
    *,
    host: HostInfo,
    utm: UTMBackend,
    vagrant: VagrantBackend,
    template_manager: TemplateManager,
    expected_architecture: Architecture,
    clock: Callable[[], float] = time.monotonic,
) -> ManagementProbeResult:
    """Public readiness-probe entry point for an owned Windows clone.

    Constructs the management channel through mandatory ownership and
    trusted-template validation, then runs the fixed internal probe under
    one bounded total budget. There is no public path to an arbitrary
    guest-command executor.
    """
    channel = _owned_management_transport(
        scenario,
        scenario_path,
        host=host,
        utm=utm,
        vagrant=vagrant,
        language=ExecutionLanguage.POWERSHELL,
        template_manager=template_manager,
    )
    return _run_readiness_probe(
        channel, expected_architecture=expected_architecture, clock=clock
    )
