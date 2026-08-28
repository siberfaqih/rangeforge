# Phase 5.4: Windows Runtime Lifecycle Architecture

Status: **PROPOSED**  
Roadmap: `docs/roadmap/phase-5.md`  
Scope: Phase 5.4 only  
Supported production path: Windows 11 ARM64 on Apple Silicon using UTM directly  
Last reviewed: 2026-08-27

This document defines the implementation architecture for Phase 5.4. The
roadmap remains the source of truth for task scope, status, dependencies, and
completion. This document is the technical contract for implementing and
reviewing the task.

The design extends the existing generic VM lifecycle. It does not create a
Windows-specific planner, image lifecycle, ownership system, or orchestration
stack.

## 1. Current Architecture Assessment

### Existing architecture

RangeForge already separates deterministic scenario generation from runtime
deployment. Runtime state is not stored in the attack graph, and runtime
availability does not participate in scenario generation.

The current runtime architecture has the following properties:

- `rangeforge/runtime/resolver.py` owns host-to-backend policy through
  `VM_HOST_BACKENDS` and `RuntimeResolver`.
- macOS ARM64 resolves directly to UTM.
- supported AMD64 hosts resolve to Vagrant.
- `rangeforge/runtime/guest.py` owns guest compatibility through
  `check_guest_compatibility()`.
- Cross-architecture execution is rejected rather than silently emulated.
- Windows with Vagrant is currently rejected because RangeForge has no reviewed
  Windows management transport for that backend.
- `rangeforge/images/definitions/windows.yaml` defines Windows images using the
  generic `ImageManifest` model.
- Windows 11 ARM64 is modeled as a manually acquired, checksum-reviewed UTM
  source image.
- Windows 11 AMD64 has an image identity but no currently deployable Windows
  Vagrant path.
- Source image artifacts, prepared templates, and scenario runtime metadata are
  separate resources.
- Source artifacts are stored under the image cache download hierarchy.
- Template metadata is stored under the backend and image-specific template
  hierarchy.
- Scenario runtime metadata is stored beside the scenario under
  `runtime/runtime.yaml`.
- `rangeforge/images/templates.py` deterministically derives template identity
  using `rf-base-<image-id>` and fingerprints the image, source checksum,
  backend, and template schema.
- `rangeforge/runtime/metadata.py` deterministically derives scenario VM names
  using `scenario_vm_name()`. A simple scenario ID such as `5004` becomes
  `rf-5004`.
- `rangeforge/runtime/lifecycle.py` contains one generic `ScenarioLifecycle`
  implementing `build`, `up`, `status`, and `destroy` for VM backends.
- `rangeforge/runtime/backends/utm.py` supports clone, start, stop, delete,
  state inspection, and IP inspection.
- `rangeforge/runtime/backends/vagrant.py` supports scenario-local environment
  creation, `up`, `halt`, `destroy`, state inspection, and address inspection.
- `rangeforge/runtime/management.py` owns Windows management readiness through
  `probe_windows_management()` and the Phase 5.3 Windows PowerShell transport.
- The Windows readiness probe verifies ownership, platform, architecture,
  backend policy, template identity, VM existence, VM state, QEMU Guest Agent
  execution, PowerShell behavior, hardware architecture, file transfer,
  command exit behavior, and cleanup.
- Windows readiness does not use IP discovery as proof of management readiness.
- CLI runtime planning, build, and up create a runtime plan before lifecycle
  mutation. Status and destroy operate from persisted runtime identity without
  requiring a new plan.
- Runtime metadata already stores scenario identity, profile, backend, managed
  VM identity, template identity, guest platform and architecture, management
  transport and language, management state, provisioning state, and validation
  state.

### Existing strengths

- Windows support has not introduced a second graph engine, planner, image
  manager, or lifecycle orchestrator.
- Host/backend and guest compatibility decisions are centralized and
  deterministic.
- The clean shared base template is distinct from scenario-owned clones.
- UTM build currently clones without unnecessarily booting the clone.
- Existing lifecycle behavior refuses to adopt a matching `rf-*` VM when
  scenario runtime metadata is absent.
- Existing Linux UTM tests cover clone reuse, startup, status, destruction, and
  preservation of source and template metadata.
- Phase 5.3 provides a reviewed Windows readiness authority that Phase 5.4 can
  reuse.

### Gaps Phase 5.4 must close

- There is no generic lifecycle `stop()` operation or CLI `stop` command.
- UTM inventory parsing does not retain VM UUIDs. Lifecycle mutation therefore
  targets a VM primarily by name.
- The persisted managed ID proves that metadata belongs to the scenario, but it
  does not prove that the current backend object with that name is the same
  object RangeForge created.
- Existing build idempotency does not fully reconcile persisted metadata with
  the current scenario, plan, host, backend policy, architecture, image, and
  prepared template before returning unchanged.
- A READY template metadata record is not sufficient proof that the referenced
  backend template object still exists.
- Status does not consistently reprobe management for every running Windows VM.
  A persisted non-ready state may therefore fail to recover through status.
- A Windows management failure during up can leave a truthful running VM but
  does not currently provide sufficiently explicit lifecycle failure behavior.
- Startup polling and the Windows management probe do not share one overall
  lifecycle deadline.
- UTM backend state `stopping` is not represented as a distinct lifecycle state.
- Destroy can continue after a stop wait without first proving that the VM has
  reached the stopped state.
- Status output does not include all required guest and ownership information.
- The production training profile remains Linux-only. Lifecycle commands need a
  narrowly scoped validation path for a standalone Windows runtime without
  enabling Windows generation, provisioning, primitives, or curriculum policy.

These gaps are generic lifecycle and ownership gaps. They should be fixed in
the generic runtime architecture and covered by Linux regression tests rather
than hidden inside Windows-specific orchestration.

## 2. Phase 5.4 Architecture

Phase 5.4 extends `ScenarioLifecycle`. It must not add a `WindowsLifecycle` or a
parallel Windows orchestration service.

The target flow is:

```text
existing scenario representation
        |
runtime-lifecycle structural validation
        |
RuntimePlanner
        |
authoritative compatibility result
        |
READY source artifact and READY clean base template
        |
ScenarioLifecycle.build()
        |
scenario-owned clone plus backend-native identity
        |
ScenarioLifecycle.up()
        |
backend RUNNING
        |
Phase 5.3 Windows management readiness probe
        |
management READY or explicit lifecycle failure
        |
status / stop / up / destroy
```

The architecture has five boundaries:

1. The runtime planner remains authoritative for backend, platform, image, and
   architecture compatibility.
2. The template manager remains authoritative for clean base-template identity
   and readiness metadata.
3. The backend remains authoritative for actual VM identity and power state.
4. `ScenarioLifecycle` owns state convergence and safe mutation of the
   scenario-specific clone.
5. The Phase 5.3 transport remains authoritative for Windows management
   readiness.

The lifecycle may verify that these authorities agree. It must not reproduce
their policy decisions.

Standalone Windows lifecycle commands use the existing scenario representation
with a lifecycle-specific validation mode. That mode validates scenario
identity and runtime-relevant structure without requiring Windows curriculum
eligibility or an attack path. It is available only to runtime plan, build, up,
status, stop, and destroy. Generation, provisioning, primitive selection, and
runtime validity continue to use their existing default-deny policy.

No new persisted `runtime_only` scenario flag is required. Command scope selects
the narrower validator, avoiding a second scenario model and preventing a
runtime lifecycle capability from becoming curriculum eligibility.

## 3. Components to Reuse Unchanged

The following components remain authoritative and should be reused without
Windows lifecycle policy duplication:

| Component | Responsibility retained |
|---|---|
| `HostDetector` | Normalize host OS and architecture and detect backend executables. |
| `VM_HOST_BACKENDS` | Select the allowed VM backend for a normalized host. |
| `RuntimeResolver` | Resolve generic runtime and backend availability. |
| `check_guest_compatibility()` | Decide platform, backend, and architecture compatibility. |
| `ImageResolver` | Select an exact trusted image manifest. |
| Windows image manifests | Define reviewed Windows source identities and acquisition policy. |
| `ImageManager` | Acquire and checksum-verify source artifacts. |
| `TemplateManager` identity rules | Derive deterministic template IDs and freshness fingerprints. |
| `scenario_vm_name()` | Derive deterministic scenario VM names. |
| Phase 5.3 Windows transport | Execute the fixed, reviewed QGA and PowerShell readiness protocol. |
| `probe_windows_management()` | Decide Windows management readiness. |
| Attack graph and primitive registries | Continue to model logical transitions independently of runtime. |
| Training-profile policy | Continue to deny Windows curriculum eligibility until later phases. |
| Linux management transports | Retain existing UTM/QGA shell and Vagrant/SSH behavior. |
| Source and shared artifact caches | Remain separate from scenario lifecycle ownership. |

In particular, Phase 5.4 must not add architecture tables, Windows image
selection rules, QGA command framing, or PowerShell commands to
`ScenarioLifecycle`.

## 4. Components Requiring Extension

### Runtime models

`rangeforge/runtime/models.py` requires generic lifecycle model extensions:

- Add explicit `STOPPING` and `MISSING` VM states.
- Preserve an explicit unknown or error state for backend results that cannot be
  safely interpreted.
- Extend VM identity with a backend-native resource reference.
- Persist guest product and version so status can display `Windows 11` without
  consulting mutable registry state.
- Persist a bounded, non-secret lifecycle failure classification and message.
- Increment the runtime metadata schema version.
- Treat legacy metadata without backend identity as insufficient for Windows
  mutation. Do not infer or silently upgrade Windows ownership.

### UTM backend

`rangeforge/runtime/backends/utm.py` requires generic identity support:

- Parse UTM inventory into typed records containing UUID, name, and state.
- Support lookup by UUID and by name.
- Require persisted UUID and expected name to agree before mutation.
- Target start, stop, delete, state, and address operations through the validated
  backend identity.
- Map UTM `stopping` to `STOPPING`, not `STOPPED`.
- Return unknown backend states explicitly rather than guessing.

### Vagrant backend

`rangeforge/runtime/backends/vagrant.py` remains architecturally valid for AMD64
hosts and needs equivalent generic ownership hardening:

- Derive a deterministic environment fingerprint from the canonical scenario
  environment path, expected machine name, generated Vagrantfile, box identity,
  and provider.
- Reject symlink substitution in the scenario runtime environment before
  mutation.
- Persist the Vagrant machine/provider ID after it becomes available.
- Do not boot a VM during build solely to obtain a provider machine ID.

These extensions preserve Linux Vagrant behavior. They do not enable Windows
Vagrant management.

### Runtime metadata

`rangeforge/runtime/metadata.py` requires:

- Validation of backend-native identity and the ownership fingerprint.
- Canonical-path and symlink checks for scenario-owned runtime directories.
- Atomic persistence of the complete identity after clone creation.
- Continued deterministic naming.
- Explicit rejection of name-prefix-only ownership.

### Scenario lifecycle

`rangeforge/runtime/lifecycle.py` requires:

- One shared pre-mutation consistency and ownership gate.
- Generic `stop()` behavior.
- Backend identity reconciliation before build, up, stop, and destroy.
- Explicit stale-state and conflict results.
- A single bounded deadline for VM convergence and Windows readiness.
- Explicit failure when the VM is running but Windows management is unavailable.
- Preservation of existing Linux branches except where generic ownership and
  state handling are strengthened.

### Windows management probe

`rangeforge/runtime/management.py` requires only a lifecycle integration
extension:

- Allow `probe_windows_management()` to accept an explicit remaining timeout or
  deadline.
- Keep the existing default budget for direct callers.
- Keep QGA, PowerShell, command framing, architecture attestation, and cleanup
  logic inside the management abstraction.

### CLI

`rangeforge/cli.py` requires:

- A `stop` command.
- Lifecycle-specific structural validation for standalone Windows runtime
  commands.
- Nonzero failure behavior when up cannot reach Windows management readiness.
- Status rendering for guest OS, guest architecture, backend, ownership,
  management state, VM state, and address.
- No Windows provisioning or runtime-validity eligibility.

### Template readiness

The template path requires one additional build-time check:

- `TemplateManager.require_ready()` continues to validate template metadata and
  fingerprint freshness.
- Before cloning, the selected backend must also confirm that the referenced
  template resource still exists.

This is existence verification, not a second template readiness policy.

## 5. Lifecycle State Machine

VM state and management state are orthogonal. A VM can be running while its
management channel remains unavailable.

| Metadata and backend condition | VM state | Management state | Permitted behavior |
|---|---|---|---|
| No metadata and no expected backend object | `NOT_BUILT` | `NOT_READY` | Build may create the clone. |
| No metadata and expected name already exists | ownership conflict | `UNAVAILABLE` | Refuse adoption and mutation. |
| Valid metadata and matching backend identity is powered off | `STOPPED` | `NOT_READY` | Up or destroy is allowed. |
| Start submitted | `STARTING` | `WAITING` | Poll within the shared deadline. |
| Backend is running and probe is pending | `RUNNING` | `WAITING` | Invoke the Phase 5.3 probe. |
| Backend is running and probe passes | `RUNNING` | `READY` | Normal running state. |
| Backend is running and probe fails or times out | `RUNNING` | `UNAVAILABLE` | Retain VM; retry up or status. |
| Stop submitted | `STOPPING` | `NOT_READY` | Poll until stopped or timeout. |
| Valid metadata but backend identity is absent | `MISSING` | `NOT_READY` | Status reports stale state; destroy may clear metadata safely. |
| Expected name exists with a different backend identity | ownership conflict | `UNAVAILABLE` | Never adopt, start, stop, or delete. |
| Backend reports an unknown state | `UNKNOWN` | `UNAVAILABLE` | Fail closed; do not infer power state. |
| Backend operation fails | truthful observed state or `ERROR` | `NOT_READY` or `UNAVAILABLE` | Retain identity and permit safe retry. |
| Delete is confirmed and metadata is removed | no runtime | not applicable | Repeated destroy is unchanged. |

State transition rules:

- `RUNNING` never implies `READY`.
- Only the Phase 5.3 probe can transition Windows management to `READY`.
- A stopped or missing VM cannot retain Windows management `READY`.
- A timeout does not trigger an automatic rebuild or destroy.
- A retry reconciles actual backend state before issuing another mutation.
- Metadata is removed only after deletion or confirmed stale absence is safe.

## 6. Ownership Model

RangeForge owns a scenario VM only when all required evidence agrees.

### Required metadata evidence

- The metadata schema is supported.
- `scenario_id` and profile match the loaded scenario.
- The runtime type is VM.
- The backend matches persisted metadata.
- The VM name equals `scenario_vm_name(scenario)`.
- The managed ID equals the deterministic scenario managed ID.
- Guest platform and architecture match the scenario runtime identity.
- Template image ID, template ID, backend reference, and fingerprint are
  complete.
- The scenario VM reference differs from the clean template reference.
- The ownership fingerprint validates.

### Required backend evidence

For UTM:

- Persist the UTM VM UUID immediately after cloning.
- Inventory lookup by UUID must return exactly one resource.
- The resource name must equal the persisted expected name.
- A name lookup must not reveal another resource that conflicts with the
  persisted UUID.

For Vagrant:

- The canonical scenario environment path must match metadata.
- The environment and generated Vagrantfile fingerprint must match metadata.
- The provider machine ID must match when it exists.
- The scenario environment hierarchy must not be replaced by symlinks.

### Ownership fingerprint

The ownership fingerprint binds at least:

```text
metadata schema
scenario managed ID
backend
backend-native resource identity
expected VM name
template identity and fingerprint
guest platform and architecture
```

The fingerprint is deterministic integrity evidence, not a credential or
security secret. The backend-native UUID or environment identity is the
evidence that prevents a foreign same-name VM from being mutated.

### Ownership rules

- An `rf-*` prefix is never sufficient evidence.
- Missing metadata means RangeForge cannot claim an existing resource.
- Incomplete metadata must not be completed by inspecting and adopting an
  existing VM.
- A changed UUID under the same name is an ownership conflict.
- Every mutation uses the persisted backend-native identity and checks the name
  as an additional invariant.
- Destroy must not require the shared template to remain present. Once clone
  ownership is proven, the clone can be safely destroyed after a template is
  retired.
- Shared template metadata is provenance, not scenario ownership.

## 7. Build Behavior

`rangeforge build <scenario>` uses the generic lifecycle and performs the
following sequence.

### Preconditions

1. Load the scenario through lifecycle-specific structural validation.
2. Require a compatible and deployable `RuntimePlan`.
3. Verify the plan belongs to the same scenario and detected host.
4. Verify the resolved backend matches host/backend policy.
5. Verify scenario, guest plan, image manifest, and template platform and
   architecture identities agree.
6. Verify the plan image ID equals the prepared template image ID.
7. Require READY template metadata and a current template fingerprint.
8. Confirm that the referenced backend template object exists.

These checks verify consistency with planner output. They do not independently
decide that a Windows architecture or backend is compatible.

### New build

1. Derive the deterministic scenario VM name.
2. Confirm that no backend resource already uses that expected name.
3. Clone the configured clean base template exactly once.
4. Do not boot the clone.
5. Inspect the newly created backend resource and obtain its backend-native
   identity.
6. Confirm its name, UUID or environment identity, expected stopped state, and
   separation from the shared template.
7. Atomically persist scenario ownership, backend identity, template
   provenance, Windows product/version, architecture, management transport,
   management language, and initial lifecycle state.
8. Return a successful changed result with VM `STOPPED` and management
   `NOT_READY`.

For the current Windows ARM64 image, the default clean-template identity is
`rf-base-windows-11-arm64`. A simple scenario ID `5004` produces scenario clone
`rf-5004`.

### Idempotent build

When metadata already exists, build returns unchanged only if:

- Scenario ownership validates.
- The current plan matches persisted host, backend, image, platform, and
  architecture identity.
- Template provenance and fingerprint match the current selected template.
- The backend-native scenario resource exists.
- Backend UUID or environment identity and expected name both match.
- The resource is not the shared template.

Build must not create a replacement when metadata references a missing resource.
That condition is stale state requiring explicit reconciliation or destroy.

### Build failures

- A same-name backend object without matching complete metadata is a conflict.
- An incompatible architecture, backend, image, or template fails before clone.
- A missing backend template fails before clone.
- If cloning succeeds but backend identity cannot be uniquely established or
  metadata cannot be persisted, report an orphan conflict. Do not adopt or
  delete the resource on a later invocation based only on its name.
- Build never modifies or boots the source artifact or clean template.

## 8. Up Behavior

`rangeforge up <scenario>` continues to use generic build reconciliation before
starting a VM.

### Sequence

1. Obtain and validate the current runtime plan.
2. Call generic build reconciliation.
3. Validate complete ownership and backend identity.
4. Establish one operation deadline covering VM convergence and management
   readiness.
5. Reconcile actual backend state.
6. If stopped, persist `STARTING` and management `WAITING`, then start the exact
   owned resource.
7. If already starting, continue polling without issuing a duplicate start.
8. If already running, do not call backend start.
9. Wait for backend `RUNNING` within the remaining deadline.
10. Refresh the available IP or address independently from readiness.
11. Invoke `probe_windows_management()` with the remaining deadline.
12. Persist management `READY` only if the complete Phase 5.3 probe succeeds.

### Idempotency and readiness

- Repeated up against an already running Windows VM does not start it again.
- Repeated up always revalidates Windows management, including a persisted
  `READY`, `NOT_READY`, or `UNAVAILABLE` state.
- An address can be recorded while management remains `WAITING` or
  `UNAVAILABLE`.
- Generic lifecycle code must not execute QGA commands, PowerShell, WinRM, or
  Windows-specific checks directly.

### Failure behavior

If the backend reaches `RUNNING` but management does not become ready:

- Keep VM state `RUNNING`.
- Persist management `UNAVAILABLE`.
- Persist a bounded non-secret failure classification.
- Return a lifecycle failure and nonzero CLI exit.
- Keep the clone available for diagnosis and retry.
- Do not stop, rebuild, or destroy automatically.

If the backend does not reach `RUNNING` before the deadline:

- Persist the truthful observed backend state.
- Do not invoke the Windows management probe.
- Return a lifecycle failure.
- Retain the clone and ownership metadata for retry.

Existing Linux readiness semantics remain unchanged unless required by generic
state and ownership hardening.

## 9. Status Behavior

Status is non-starting and non-destructive. It may update scenario runtime
metadata to reflect observed backend and management state.

The CLI output must distinguish at least:

```text
Scenario             5004
Runtime              VM
Backend              UTM
VM                   rf-5004
State                RUNNING
Guest OS             Windows 11
Guest architecture   arm64
Management           READY
Ownership            VERIFIED
IP                   192.168.64.9
```

The address line may report unavailable when the backend or guest has not
provided an address.

### Reconciliation rules

- No metadata and no expected backend object reports `NOT_BUILT`.
- No metadata with an existing expected name reports an ownership conflict and
  does not adopt the object.
- Valid metadata with an absent backend UUID reports `MISSING`.
- A same-name resource with a different UUID reports an ownership conflict.
- A stopped VM reports `STOPPED`, clears stale address data, and sets Windows
  management to `NOT_READY`.
- A stopping VM reports `STOPPING` and never reports management `READY`.
- Every running Windows VM is checked through the Phase 5.3 readiness probe,
  regardless of its persisted management state.
- A successful probe records `RUNNING/READY`.
- A failed probe records `RUNNING/UNAVAILABLE`.
- Status never starts, stops, clones, or deletes a VM.
- The lifecycle result indicates whether reconciliation changed persisted
  metadata.

Linux status behavior remains intact, with only generic identity and state
reconciliation changes shared across platforms.

## 10. Destroy Behavior

Destroy targets only a conclusively owned scenario clone.

### Sequence

1. Load scenario runtime metadata.
2. If metadata and backend object are both absent, return unchanged.
3. Validate scenario ownership metadata and backend-native identity.
4. Reconcile actual backend state.
5. If running or starting, invoke the generic bounded stop path.
6. Require confirmed `STOPPED` before deletion.
7. Delete the exact validated backend-native resource.
8. Confirm that exact identity is absent from backend inventory.
9. Remove scenario runtime ownership metadata only after confirmed absence.

### Stale and conflict handling

- If metadata is absent but the expected VM name exists, refuse deletion.
- If metadata references an absent UUID and no same-name resource exists, remove
  stale scenario runtime metadata idempotently.
- If metadata references an absent UUID but the same name belongs to another
  UUID, report an ownership conflict and preserve metadata.
- If stop times out, do not delete.
- If delete fails or absence cannot be confirmed, preserve runtime metadata so
  a retry targets the same owned identity.

### Resources destroy must preserve

- The source image or installation artifact.
- Source artifact metadata and checksum evidence.
- The clean base-template VM.
- Base-template metadata and fingerprint.
- `scenario.yaml`.
- Unrelated VMs, including unrelated `rf-*` VMs.
- Shared image, template, and CVE artifact caches.

Destroy must never select resources by prefix, pattern, image ID, template name,
or scenario VM name alone.

The current policy for scenario-local lock metadata remains unchanged unless a
separate cleanup decision is approved. Phase 5.4 must not accidentally change
Linux cleanup behavior.

## 11. Failure-State Behavior

| Failure or stale condition | Required safe behavior |
|---|---|
| Runtime metadata says the VM exists but backend identity is absent | Status records `MISSING`; build does not silently replace it; destroy may clear metadata only if no conflicting name exists. |
| Backend VM exists but metadata is absent | Report ownership conflict; never adopt, start, stop, or delete it. |
| Runtime metadata is incomplete or invalid | Fail closed before backend mutation. |
| VM is stopped | Up starts it; status reports management `NOT_READY`; stop is unchanged; destroy may delete after ownership validation. |
| VM is already running | Up skips duplicate start and rechecks Windows readiness. |
| Management never becomes ready | Persist `RUNNING/UNAVAILABLE`, return failure, and retain the clone. |
| Start times out | Persist the observed state, return failure, and retain ownership metadata. |
| Stop times out | Retain clone and metadata; never continue to delete. |
| Destroy partially fails | Retain metadata until exact backend absence is confirmed. |
| Duplicate scenario VM name has a foreign UUID | Report conflict for every mutating operation. |
| Template becomes stale before build | Reject before cloning. |
| Shared template is removed after build | Status and stop may inspect the clone; management readiness may be unavailable if provenance validation fails; destroy remains allowed using scenario ownership evidence. |
| Clone succeeds but metadata finalization fails | Report an orphan conflict requiring operator resolution; do not infer ownership on retry. |
| Backend state is unknown | Persist or report unknown/error; do not infer running or stopped. |
| Start or stop is interrupted | The next status, up, stop, or destroy reconciles actual state without cloning or deleting unexpectedly. |
| Persisted management is READY but probe now fails | Downgrade to `UNAVAILABLE`; never trust stale readiness. |

Failures must not expose management credentials, command output containing
secrets, PowerShell scripts, flags, primitive identities, or solution data.

## 12. ARM64/UTM Path

The supported Phase 5.4 production path is:

```text
Apple Silicon host
        |
normalized macOS ARM64
        |
RuntimeResolver selects UTM directly
        |
Phase 5.2 selects compatible windows-11-arm64 image
        |
READY clean UTM base template
        |
scenario-specific ARM64 clone
        |
Phase 5.3 QGA and PowerShell readiness
```

Required identities:

- Host OS: macOS.
- Host architecture: ARM64.
- Backend: UTM directly, never Vagrant.
- Guest: Windows 11 ARM64.
- Image: `windows-11-arm64`.
- Source acquisition: manual and checksum-pinned.
- Default template ID: `rf-base-windows-11-arm64`.
- Scenario clone: deterministic `rf-<scenario-id>` where possible.
- Management: QEMU Guest Agent and built-in Windows PowerShell through Phase
  5.3.

The clean template must already contain and configure the reviewed requirements
for the Phase 5.3 transport. Phase 5.4 does not automate Windows installation,
QGA installation, activation, or source acquisition.

The architecture uses the current manifest-backed image and template identity.
It must not invent an example identity such as
`rf-base-windows11-24h2-arm64` when that product/version string does not match
the reviewed image manifest and existing naming convention.

An ARM64 plan is deployable only when Phase 5.2 reports it compatible and its
source and template lifecycle states are READY.

## 13. AMD64/Vagrant Path

Current backend policy maps supported AMD64 hosts to Vagrant. Current guest
compatibility policy rejects Windows with Vagrant because no reviewed Windows
management transport exists.

Phase 5.4 therefore keeps the path architecturally valid but not deployable for
Windows:

- Preserve the generic Vagrant build, up, stop, status, and destroy interfaces.
- Preserve working Linux AMD64/Vagrant behavior.
- Preserve deterministic Windows AMD64 image identity resolution.
- Continue rejecting Windows AMD64/Vagrant before lifecycle backend mutation.
- Keep Windows AMD64 source media non-ready when required checksum and template
  evidence are absent.
- Add offline tests proving deterministic denial and zero backend mutation.
- Do not claim Windows AMD64 runtime verification from mocked tests.

Windows AMD64/Vagrant support requires a separately reviewed image/template
path and management transport. It is not enabled by changing a lifecycle flag.
Phase 5.4 does not add WinRM, Windows SSH, Vagrant PowerShell execution, or
another Windows management channel.

## 14. Compatibility Assumptions

- `RuntimePlan` is the source of truth for compatibility decisions.
- Lifecycle consistency checks validate supplied decisions; they do not create
  a second compatibility matrix.
- Host and guest architectures must match under current policy.
- Cross-architecture emulation remains unsupported.
- Apple Silicon Windows support is ARM64 through UTM directly.
- Windows Vagrant remains incompatible.
- An image manifest must come from the trusted configured registry.
- A downloaded source becomes READY only after required checksum verification.
- Source readiness does not imply template readiness.
- Template metadata readiness does not replace backend template existence
  verification at build time.
- Manual Windows source acquisition and clean-template preparation are
  acceptable and remain operator responsibilities.
- The clean template remains non-vulnerable and shared.
- Scenario lifecycle mutation targets only scenario-specific clones.
- Runtime-only lifecycle eligibility is separate from training-profile policy.
- The production profile remains default-deny for Windows until the primitive
  and validator phases are complete.
- Scenario generation remains deterministic and independent of backend
  availability.
- Attack graph state transitions remain unchanged.

## 15. Required Unit Tests

### Lifecycle consistency tests

Add or extend tests in `tests/test_lifecycle.py` for:

- A deployable plan for scenario A used with scenario B fails before clone.
- A plan for a different normalized host fails before mutation.
- Scenario, guest plan, image, and template architecture mismatches each fail
  before clone.
- Platform mismatch fails before clone.
- Backend mismatch fails before clone.
- Plan image and template image mismatch fails before clone.
- A READY template record whose backend object is missing fails before clone.
- Scenario `5004` deterministically produces `rf-5004`.
- Repeated ownership fingerprint calculation is byte-identical.
- Complete matching metadata and backend identity make build unchanged.
- Metadata referencing a missing backend identity does not cause replacement.
- A same-name backend object without metadata is never adopted.
- A same-name backend object with another UUID is never adopted.

### Runtime metadata tests

Add or extend metadata tests for:

- The new runtime metadata schema round-trips exactly through YAML.
- Windows guest product and version round-trip.
- UTM UUID round-trips.
- Vagrant environment fingerprint and provider ID round-trip when present.
- Legacy metadata remains valid only for its supported behavior and cannot be
  silently upgraded into Windows ownership.
- Missing backend identity rejects Windows mutation.
- Tampered UUID fails ownership validation.
- Tampered ownership fingerprint fails validation.
- Tampered scenario ID, profile, name, backend, platform, architecture, or
  template identity fails validation.
- Symlinked runtime or Vagrant paths are rejected before mutation.

### Planner and compatibility regressions

Extend `tests/test_guest_platform.py` and `tests/test_runtime_planner.py` for:

- Windows ARM64 on macOS ARM64 deterministically selects UTM when all required
  capabilities are available.
- Cross-architecture Windows plans remain denied.
- Windows with Vagrant remains denied.
- Repeated plan construction and serialization are deterministic.
- Lifecycle extensions do not alter planner compatibility outcomes.

### CLI tests

Extend `tests/test_cli.py` for:

- `stop --help` is available.
- Status renders guest OS, architecture, backend, VM state, management state,
  ownership, and address.
- Up exits nonzero when Windows management remains unavailable.
- Standalone Windows input is accepted only by runtime plan, build, up, status,
  stop, and destroy.
- The same input remains rejected by provisioning, runtime validity, primitive
  selection, and training generation.

## 16. Required Mocked Backend Tests

Use a filesystem-faithful fake UTM inventory containing UUID, name, and state,
plus a mocked Phase 5.3 readiness probe.

### Build tests

- Given compatible Windows ARM64 planning and a READY existing base template,
  build creates exactly one clone.
- Build never starts the new clone.
- Persisted metadata includes UUID, platform, product, architecture, template
  identity, and ownership fingerprint.
- Repeated build does not clone again.
- Failure to establish a unique clone identity reports failure without claiming
  ownership.
- Source and clean-template state remain unchanged.

### Up tests

- Up from stopped issues one start, observes `STARTING`, reaches `RUNNING`, then
  invokes the readiness probe.
- The probe targets only the validated scenario VM identity.
- Successful readiness records `RUNNING/READY`.
- Up against already running and READY does not start again and does reprobe.
- Up against running and UNAVAILABLE can recover to READY without another start.
- Management timeout records `RUNNING/UNAVAILABLE` and returns failure.
- Start timeout does not invoke the readiness probe and retains the clone.
- One operation deadline bounds startup and management readiness together.

### Status tests

- Stopped reports `STOPPED/NOT_READY` without probing management.
- Running and persisted NOT_READY invokes the probe and may become READY.
- Running and persisted READY invokes the probe and may become UNAVAILABLE.
- Missing persisted UUID reports MISSING without mutation.
- Foreign same-name UUID reports ownership conflict.
- Status never starts or stops the VM.

### Stop tests

- Stop from running issues one requested stop and waits for STOPPED.
- Successful stop preserves the clone and records management NOT_READY.
- Repeated stop makes no backend stop call.
- Stop timeout retains metadata and the clone.
- Up after stop issues one new start and performs the complete readiness probe.

### Destroy tests

- Destroy from running stops, confirms STOPPED, deletes the exact UUID, confirms
  absence, and removes scenario runtime metadata.
- Repeated destroy is unchanged and invokes no backend mutation.
- Missing owned resource with no conflicting name clears stale metadata.
- A foreign same-name VM is never stopped or deleted.
- Delete failure retains metadata.
- Retrying after partial failure targets the same persisted UUID.
- Source artifact, source metadata, template metadata, clean-template inventory
  entry, unrelated VMs, and shared caches remain unchanged.

### Regression tests

- Existing Linux UTM build, up, status, stop, and destroy behavior passes with
  UUID-aware identity.
- Existing Linux Vagrant behavior passes with environment ownership hardening.
- Windows Vagrant denial occurs before any fake backend mutation.

## 17. Real-Runtime Acceptance Test

The real-runtime acceptance test is explicitly gated and excluded from normal
offline CI.

### Apple Silicon UTM setup

- Use an authorized isolated Apple Silicon host.
- Confirm UTM is installed and responsive.
- Confirm the reviewed `windows-11-arm64` source is READY.
- Confirm a clean `rf-base-windows-11-arm64` UTM template is READY.
- Use a dedicated standalone Windows scenario, for example scenario `5004`.
- Before testing, record the source checksum and metadata, template UUID and
  state, template fingerprint, unrelated VM inventory, and shared cache state.

### Command sequence

Run the actual CLI equivalents of:

```text
rangeforge runtime plan <scenario>
rangeforge build <scenario>
rangeforge build <scenario>
rangeforge up <scenario>
rangeforge up <scenario>
rangeforge status <scenario>
rangeforge stop <scenario>
rangeforge stop <scenario>
rangeforge up <scenario>
rangeforge destroy <scenario>
rangeforge destroy <scenario>
```

### Required assertions

- Planning selects VM, UTM, Windows 11, ARM64, and `windows-11-arm64`.
- The first build creates exactly one `rf-5004` scenario clone.
- Build leaves the clone stopped.
- The second build does not create another clone.
- Up reaches backend `RUNNING`.
- Up reports management `READY` only after the complete Phase 5.3 probe.
- Repeated up does not issue another start and does revalidate readiness.
- Status reports Windows 11, ARM64, UTM, verified ownership, VM state,
  management state, and address when available.
- Stop leaves the clone present and management not ready.
- Repeated stop is unchanged.
- Up after stop returns the VM to management READY.
- Destroy removes only the captured scenario UUID.
- Repeated destroy is unchanged.
- The source checksum and source metadata are unchanged.
- The clean-template UUID, state, metadata, and fingerprint are unchanged.
- Unrelated VMs and shared caches are unchanged.

The test is successful only when both lifecycle behavior and preservation
evidence pass.

### AMD64/Vagrant verification statement

If no reviewed Windows AMD64 host, template, and management transport exist,
the release evidence must state:

- Windows AMD64 planning denial is verified offline.
- Generic Vagrant lifecycle regressions are verified offline and with Linux
  runtime evidence where available.
- Windows AMD64 lifecycle is not supported and not runtime verified.

Mocked backend tests must never be reported as real Windows AMD64 runtime
verification.

## 18. Definition of Done

Phase 5.4 is complete only when all of the following are true:

- One generic `ScenarioLifecycle` owns Windows and Linux VM lifecycle
  orchestration.
- Generic idempotent stop behavior and a CLI stop command exist.
- Windows ARM64 build, up, status, stop, and destroy follow this state machine.
- Backend-native identity protects all mutating operations.
- A foreign same-name VM cannot be adopted, started, stopped, or deleted.
- Build validates scenario, plan, host, backend, image, architecture, and
  template consistency before backend mutation.
- Build creates one stopped scenario clone and never modifies the clean base.
- Phase 5.3 remains the sole Windows management readiness authority.
- VM running state and management readiness remain distinct.
- Management failure produces a truthful state and explicit command failure.
- Stale metadata and interrupted operations have deterministic safe recovery.
- Destroy preserves source artifacts, clean templates, unrelated VMs, and
  shared caches.
- Existing Linux UTM and Vagrant lifecycle behavior remains green.
- Windows AMD64/Vagrant remains denied and is not described as supported.
- Lifecycle-only Windows eligibility cannot enable generation, provisioning,
  primitives, curriculum policy, or runtime validity.
- Required unit and mocked backend tests cover success, retry, timeout,
  mismatch, stale-state, and ownership transitions.
- The gated Apple Silicon UTM acceptance test passes on a real owned Windows 11
  ARM64 clone.
- Documentation accurately distinguishes supported ARM64/UTM behavior from
  unsupported Windows AMD64/Vagrant behavior.
- `pytest` passes.
- `ruff check .` passes.
- `mypy rangeforge` passes.
- `git diff --check` passes.
- Deterministic planning, naming, and fingerprint tests pass.
- Independent architecture and ownership/security review approves the final
  implementation.
- The implementation is merged to `main` and the roadmap is reconciled with
  actual evidence before Task 5.4 is marked COMPLETE.

This architecture document alone does not make Task 5.4 complete.

## 19. Explicit Out-of-Scope List

Phase 5.4 explicitly excludes:

- Windows vulnerable primitives.
- Windows privilege escalation.
- Windows CVEs or arbitrary CVE selection.
- Active Directory.
- Domain controllers and domain joining.
- Windows Server.
- Multi-machine topology.
- Student network redesign.
- Student users, flags, credentials, or solution artifacts.
- Attacker tooling.
- AI integration or AI-derived validity.
- WinRM.
- Arbitrary PowerShell or arbitrary guest-command CLI surfaces.
- Windows Vagrant management.
- Windows AMD64 deployment.
- AMD64-on-ARM or ARM64-on-AMD64 emulation.
- Automatic Windows installer automation.
- Microsoft media redistribution, licensing, or activation handling.
- Internet scanning or arbitrary target discovery.
- Remote exploitation.
- Malware, persistence, or evasion.
- Attack-graph transition changes.
- Production training-profile Windows eligibility.
- Phase 5.5 Windows primitive provisioning.
- Phase 5.6 Windows runtime validation.

## 20. Recommended Implementation Order

1. Add acceptance tests for the lifecycle state machine and define the
   lifecycle-only Windows validation boundary without weakening the general
   `ScenarioValidator` or profile policy.
2. Extend runtime models and metadata schema with backend-native identity,
   guest product/version, explicit lifecycle states, and bounded failure data.
3. Add typed UTM inventory records, UUID lookup, UUID-targeted validation, and
   correct `STOPPING` handling.
4. Add Vagrant canonical environment identity and symlink protection while
   preserving Linux behavior.
5. Harden runtime metadata ownership and fingerprint validation.
6. Add the shared lifecycle plan-consistency and pre-mutation ownership gate.
7. Harden build reconciliation and backend template existence checks.
8. Add generic bounded `stop()` and the CLI stop command.
9. Refactor destroy to require stop convergence, delete by backend identity, and
   confirm exact absence before removing metadata.
10. Refactor up to use one operation deadline and pass the remaining budget to
    the Phase 5.3 readiness probe.
11. Refactor status to reconcile every backend state and reprobe every running
    Windows clone.
12. Add extended CLI status output and explicit management-failure exit
    behavior.
13. Add the complete unit and mocked backend test matrix, including Linux UTM
    and Vagrant regressions.
14. Run `pytest`, `ruff check .`, `mypy rangeforge`, deterministic checks, and
    `git diff --check`.
15. Conduct an independent ownership and destructive-operation review.
16. Run the gated Apple Silicon UTM real-runtime acceptance test.
17. Update user-facing support documentation and roadmap evidence only after
    the implementation, review, and real-runtime gates pass.
18. Merge only after the architecture owner confirms all Phase 5.4 gates.
