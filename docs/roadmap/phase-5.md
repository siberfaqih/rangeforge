# Phase 5: Windows Runtime Roadmap

This document is the source of truth for Phase 5 scope and status. Code, pull
requests, and agent handoffs must not infer the active task from chat history or
branch names alone.

Last reconciled: 2026-08-27

## Status Summary

| Task | Scope | Status | Evidence |
|---|---|---|---|
| 5.1 | Windows models | COMPLETE | `43eaebe`, merged by PR #2 |
| 5.2 | Windows image compatibility | COMPLETE | `2914cd9`, merged by PR #2 |
| 5.3 | Windows management transport | COMPLETE | `472e959`, `62a3f24`, merged by PR #3 as `b6c9cb2` |
| 5.4 | Windows runtime lifecycle | PLANNING | Branch `phase5.4/windows-runtime-lifecycle` |
| 5.5 | Windows primitive | PLANNED | Depends on Task 5.4 |
| 5.6 | Windows validator | PLANNED | Depends on Task 5.5 |

The active task is **5.4**. Tasks 5.5 and 5.6 must remain default-deny until
their dependencies and acceptance criteria are complete.

## Phase Boundaries

Phase 5 extends the existing generic runtime architecture for Windows. It must
not create a parallel Windows graph engine, planner, image lifecycle, or
ownership model.

The supported Phase 5 production target is Windows 11 ARM64 on an Apple Silicon
host using UTM directly. Windows Vagrant management, Windows AMD64 deployment,
cross-architecture emulation, WinRM, arbitrary PowerShell execution, Active
Directory, and arbitrary CVE selection remain out of scope.

Scenario generation must remain independent from runtime/backend availability.
The production training profile remains default-deny for Windows until the
primitive and validator work in Tasks 5.5 and 5.6 is complete.

## Task 5.1: Windows Models

Status: **COMPLETE**

Delivered:

- Typed guest platform and host/guest architecture identity.
- Generic runtime planning compatibility for Windows guests.
- Explicit Windows default-deny behavior where runtime support is absent.
- No Windows-specific attack-graph engine or certification transitions.

Evidence:

- Commit `43eaebe` (`feat: add guest platform compatibility metadata and Windows default-deny`).
- Merged into `main` through PR #2.

## Task 5.2: Windows Image Compatibility

Status: **COMPLETE**

Delivered:

- Trusted Windows image registry definitions.
- Manual, checksum-pinned Windows 11 ARM64 source acquisition.
- Separate source-image and reusable UTM base-template readiness.
- Native ARM64 host/guest compatibility and deterministic runtime planning.
- Windows AMD64 remains planning-denied without a reviewed deployable path.

Evidence:

- Commit `2914cd9` (`feat: add Windows image compatibility and runtime resolution`).
- Merged into `main` through PR #2.
- Real Windows 11 ARM64 source and reusable UTM template were verified READY.

## Task 5.3: Windows Management Transport

Status: **COMPLETE**

Delivered:

- Ownership-gated UTM/QEMU Guest Agent management transport.
- Built-in Windows PowerShell execution without WinRM or new credentials.
- Typed execution outcomes, bounded deadlines, deterministic staging, and
  output framing.
- Fixed Windows readiness probe with OS and hardware-architecture attestation.
- Lifecycle readiness integration that never treats IP discovery as Windows
  management readiness.
- Default-deny transport language policy for runtime primitives.

Evidence:

- Commits `472e959` and `62a3f24`.
- PR #3 merged into `main` as `b6c9cb2`.
- Offline gate at merge: 317 passed, 3 runtime tests deselected; Ruff and mypy
  passed.
- A gated smoke passed on one real owned Windows 11 ARM64 UTM clone. The clone
  was destroyed and the shared base was preserved.

Task 5.3 intentionally does not enable Windows provisioning, attack primitives,
student users, flags, or runtime validity.

## Task 5.4: Windows Runtime Lifecycle

Status: **PLANNING**

Task 5.4 completes the scenario-owned Windows lifecycle around the Task 5.3
transport. The repository already has generic `build`, `up`, `status`, and
`destroy` operations plus Windows readiness hooks. Those are foundations, not
proof that this task is complete.

### Scope

- Keep one generic `ScenarioLifecycle`; add platform-specific policy only at
  explicit compatibility and readiness boundaries.
- Support Windows 11 ARM64 on UTM only.
- Build scenario clones only from a READY, clean, shared Windows base template.
- Validate scenario, plan, backend, host architecture, guest architecture,
  image identity, template fingerprint, and persisted platform identity before
  mutating a backend resource.
- Persist lifecycle state only in scenario-specific runtime metadata.
- Start an owned clone and converge backend state plus Task 5.3 management
  readiness without using IP discovery as proof.
- Add an explicit non-destructive stop operation and CLI command. Stopping a
  scenario must preserve its clone, source image, shared template, and scenario
  definition.
- Reconcile actual backend state with persisted metadata in `status`, including
  stopped, missing, failed-start, and wedged-management cases.
- Make repeated build, up, stop, status, and destroy operations deterministic
  and idempotent.
- Define deterministic recovery behavior for interrupted operations and stale
  metadata. Never claim or delete an unowned resource as recovery.
- Destroy only the validated scenario-owned clone. Source images and shared
  templates must always survive.
- Preserve existing Linux UTM and Vagrant lifecycle behavior.

### Non-Goals

- Windows primitive selection or provisioning.
- Windows runtime validators, flags, or student artifacts.
- Enabling Windows in the production training profile.
- Modifying the shared Windows base template.
- WinRM, Windows Vagrant management, AMD64-on-ARM emulation, or remote targets.
- Network discovery, internet scanning, public exploit code, or arbitrary
  PowerShell exposed to CLI callers.

### Acceptance Criteria

- A compatible Windows ARM64 plan builds exactly one deterministic owned UTM
  clone from the configured READY template.
- Repeated `build` returns unchanged and never reclones an existing owned VM.
- `build` rejects architecture, platform, backend, image, template, ownership,
  and metadata mismatches before backend mutation.
- `up` starts a stopped owned clone and reports READY only after the complete
  Task 5.3 readiness probe passes.
- Repeated `up` is idempotent and revalidates a persisted Windows READY state.
- A failed or timed-out start persists a truthful non-READY/error state and can
  be retried without deleting the clone.
- `stop` stops only the owned scenario clone, waits within a bounded deadline,
  clears management readiness, and is idempotent when already stopped.
- `status` converges metadata to actual backend and management state without
  mutating or starting the VM.
- Missing-resource and stale-metadata behavior is explicit, deterministic, and
  never adopts an existing unowned VM.
- `destroy` validates RangeForge ownership before stopping or deleting, is
  idempotent, and removes only scenario runtime metadata and the scenario clone.
- Destroy and recovery paths preserve the source artifact, shared base-template
  VM, template metadata, scenario YAML, and unrelated VMs.
- Offline tests cover every transition, retry, mismatch, timeout, stale-state,
  and ownership failure for Windows while retaining Linux regressions.
- `pytest`, `ruff check .`, `mypy rangeforge`, and `git diff --check` pass.
- A gated real-runtime smoke demonstrates build, repeated build, up, repeated
  up, status, stop, repeated stop, up-after-stop, destroy, and repeated destroy
  on one owned Windows 11 ARM64 UTM clone.
- The real smoke verifies that the source image and shared clean base template
  remain present and unchanged after scenario destruction.

Task 5.4 is COMPLETE only after the offline gates, independent review, real
owned-clone evidence, merge to `main`, and this document are all updated.

## Task 5.5: Windows Primitive

Status: **PLANNED**

Planned boundary:

- Add reviewed, data-driven Windows runtime primitive metadata and knowledge.
- Add PowerShell provisioners that target only a validated, owned scenario
  clone through the Task 5.3 transport.
- Keep training-profile eligibility separate from generic graph logic.
- Create deterministic scenario-only users, services, configuration, and flags
  required by the selected primitive.
- Never provision a source image or shared base template.
- Do not enable the primitive in production policy until Task 5.6 validators
  are complete.

The exact primitive chain and curriculum eligibility require a separate design
review before implementation.

## Task 5.6: Windows Validator

Status: **PLANNED**

Planned boundary:

- Add runtime validators for every Windows primitive introduced in Task 5.5.
- Require positive checks for intended runtime conditions and negative checks
  for shortcuts, overbroad privileges, leaked solutions, and management-data
  exposure.
- Verify actual Windows version and architecture, service identity, listeners,
  ACLs, users, flags, and intended state transitions.
- Keep AI out of validity and curriculum decisions.
- Enable Windows profile policy only after complete offline and real-runtime
  validation.
- Demonstrate deterministic provision, validate, destroy, rebuild, reprovision,
  and revalidate behavior on an owned isolated clone.

## Completion and Release

Phase 5 is complete only when Tasks 5.1 through 5.6 are COMPLETE on `main`.
Before creating a Phase 5 release tag:

- Reconcile this roadmap with all merged commits and PRs.
- Run all offline quality gates and the required real-runtime smoke.
- Align `pyproject.toml` and `rangeforge/__init__.py`; both currently report
  version `0.3.0` despite the existing Phase 4 tag.
- Record known platform limitations and real-hardware evidence in the README.
- Create an annotated Phase 5 release tag only from the reviewed `main` commit.

## Working Rules

- One task uses one branch and one pull request.
- Acceptance criteria are written before feature implementation begins.
- The primary agent owns scope, integration, and final verification.
- Subagents may explore or review, but may not redefine task boundaries.
- Every handoff must report the current task, branch, completed criteria,
  remaining criteria, gate results, and real-runtime evidence.
- A commit or passing test does not by itself mark a task COMPLETE; merge and
  roadmap reconciliation are required.
- New work discovered during a task is either required by its acceptance
  criteria or recorded explicitly as a later task. It must not silently expand
  the active task.
