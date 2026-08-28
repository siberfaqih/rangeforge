# Phase 5.4 Windows Runtime Lifecycle Change Impact Map

Scope of this analysis: repository at `/Users/apt-faqih/rangeforge-ox`, branch
`phase5.4/windows-runtime-lifecycle` at commit `4f1fe45` ("docs: define Phase 5 roadmap and lifecycle scope"). Baseline offline gate run
during this reconnaissance: `pytest` reports **317 passed, 3 deselected** (`runtime` marker
deselected by `addopts = "-q -m 'not runtime'"` in `pyproject.toml:49`). The approved target
design is `docs/dev/phase5/phase5.4-architecture.md` (SHA-256
`08f30e82f47c87a13e7c1bf72d65437c7b7c44710b564273454ffd6a7a04a831`, untracked workspace file);
this map treats it as authoritative and does not redesign it. No source, test, config,
roadmap, README, AGENTS.md, or architecture file was modified.

Terminology used below: "current behavior" is code as it exists today; "required" refers to
Phase 5.4 architecture gaps listed in architecture §1 "Gaps" and §§4-11.

---

## A. Current lifecycle flow

### A.1 CLI command definitions and dispatch

All lifecycle-relevant CLI entry points live in `rangeforge/cli.py`:

| CLI command | Handler | Dispatch helper | Context builder | Lifecycle method |
|---|---|---|---|---|
| `rangeforge runtime plan <scenario>` | `runtime_plan()` (`cli.py:728-752`) | `_runtime_context()` returns plan; rendered by `_render_runtime_plan()` (`cli.py:696-725`) | `_runtime_context()` (`cli.py:113-162`) | none (plan only; no `ScenarioLifecycle` method invoked) |
| `rangeforge build <scenario>` | `build()` (`cli.py:838-845`) | `_lifecycle_command("build", ...)` (`cli.py:777-813`) | `_runtime_context()` | `ScenarioLifecycle.build()` (`lifecycle.py:107-198`) |
| `rangeforge up <scenario>` | `up()` (`cli.py:848-855`) | `_lifecycle_command("up", ...)` | `_runtime_context()` | `ScenarioLifecycle.up()` (`lifecycle.py:200-315`) |
| `rangeforge status <scenario>` | `status()` (`cli.py:965-971`) | `_lifecycle_command("status", ...)` | `_lifecycle_only_context()` (`cli.py:165-195`) | `ScenarioLifecycle.status()` (`lifecycle.py:317-371`) |
| `rangeforge destroy <scenario>` | `destroy()` (`cli.py:974-980`) | `_lifecycle_command("destroy", ...)` | `_lifecycle_only_context()` | `ScenarioLifecycle.destroy()` (`lifecycle.py:373-397`) |

There is **no `stop` command** in `cli.py` and no `stop()` method on `ScenarioLifecycle`
(`lifecycle.py:91-477` defines only `build`, `up`, `status`, `destroy`). Roadmap
`docs/roadmap/phase-5.md:120` explicitly adds stop to Task 5.4 scope.

Validation difference between plan/build/up and status/destroy (`cli.py:783-792`):

- `build`/`up` go through `_runtime_context()` which runs **full static validation**
  (`ScenarioValidator.validate()`, `cli.py:122-125`), builds a full `RuntimePlan` via
  `RuntimePlanner.plan()` (`cli.py:139-146`), and for build/up also runs
  `context.primitive_engine.compile_plan(context.scenario, context.plan)` (`cli.py:786`).
- `status`/`destroy` go through `_lifecycle_only_context()` which **also runs full static
  validation** (`cli.py:173-176`) but skips planning and primitive compilation; the lifecycle
  method is invoked as `method(scenario, scenario_path)` with no plan (`cli.py:791-792`).

Key evidence: both context builders call `ScenarioValidator(profile, primitive_registry).validate(scenario)`
and raise `ValueError` on invalid (`cli.py:122-125` and `cli.py:173-176`). The production
profile `rangeforge/profiles/oscp.yaml:3-4` has `allowed_platforms: [linux]` only, and
`ScenarioValidator.validate()` appends a profile violation for any platform not in
`allowed_platforms` (`validation/scenario.py:24-27`). Therefore **any standalone Windows
scenario currently fails CLI-level validation for every lifecycle command**, which is the
architectural gap the architecture's "lifecycle-specific validation mode" (architecture §2,
"Standalone Windows lifecycle commands use the existing scenario representation with a
lifecycle-specific validation mode") addresses.

### A.2 `rangeforge runtime plan <scenario>`

Ordered trace (read-only; never mutates backend, images, or metadata):

1. `cli.py:728 runtime_plan()` → `_runtime_context(scenario_path, runtime, config)` (`cli.py:739`).
2. `_config()` → `ConfigLoader(path).load()` (`cli.py:71-72`).
3. `ScenarioYamlSerializer().load(scenario_path)` loads scenario YAML
   (`serialization/yaml.py:31-32`; strict pydantic validation of `Scenario`).
4. `ProfileLoader().load(scenario.scenario.profile)` (`cli.py:120`).
5. `PrimitiveLoader().load()` (`cli.py:121`).
6. `ScenarioValidator(profile, primitive_registry).validate(scenario)` (`cli.py:122`);
   on failure raises `ValueError("Scenario static validation failed: ...")` (`cli.py:124-125`).
   - For a Windows scenario under the stock `oscp` profile this fails at
     `validation/scenario.py:24-27` (`allowed_platforms` check).
7. Host detection: `HostDetector().detect(...)` (`cli.py:75-76`,
   `host/detector.py:46-67`) normalizes OS/architecture and finds `utmctl`/`vagrant`.
8. Runtime selection: `default_runtime` from `profile.runtime_defaults.get(platform)`
   or `scenario.scenario.target_runtime`, overridden by `--runtime` or config default
   (`cli.py:130-137`). For a Windows platform there is **no** `runtime_defaults["windows"]`
   in `oscp.yaml:39-44`; `requirement` is `None`, so `default_runtime` falls back to
   `"vm"`.
9. `RuntimePlanner(...).plan(scenario, requested_runtime=selected, host=host)`
   (`cli.py:139-146`, `runtime/planner.py:61-186`):
   - `planner.py:70` extracts `guest_architecture` from `scenario.scenario.guest_architecture`.
   - `planner.py:71-76` calls `RuntimeResolver().resolve(...)` → backend from
     `VM_HOST_BACKENDS` (`runtime/resolver.py:13-20`): macOS/ARM64 → UTM; AMD64 hosts →
     Vagrant.
   - `planner.py:84-92`: if `profile.runtime_defaults.get(scenario.scenario.platform)` is
     `None` → `_incomplete_plan()` (this is the Windows-on-oscp denial path:
     `tests/test_runtime_planner.py:437-460` asserts issue
     `"has no guest requirement for platform 'windows'"`).
   - `planner.py:94-101` calls `check_guest_compatibility(...)`
     (`runtime/guest.py:138-260`), which:
     - requires platform==family (`guest.py:167-176`);
     - requires runtime ∈ capabilities.runtimes (`guest.py:190-195`); Windows capabilities
       (`guest.py:86-93`) allow only `RuntimeType.VM`, only `ExecutionLanguage.POWERSHELL`,
       `cross_architecture_emulation=False`;
     - enforces `VM_HOST_BACKENDS` backend match (`guest.py:206-223`);
     - **rejects Windows+Vagrant** at `guest.py:227-231`
       ("Windows Vagrant management is unsupported; Windows scenarios require the UTM
       backend with the QEMU Guest Agent.");
     - rejects cross-architecture at `guest.py:233-242`.
   - `planner.py:104-109` builds the `GuestPlan` (family/distribution/version come from the
     profile runtime requirement; architecture from the scenario).
   - `planner.py:112-132` resolves the image via `ImageResolver.resolve(...)`
     (`images/resolver.py:17-47`) matching family/distribution/version/architecture/runtime/
     backend exactly; e.g. `windows-11-arm64` (`images/definitions/windows.yaml:10-27`).
   - `planner.py:124` `image_manager.inspect(manifest.id)` yields artifact state and
     template states (`images/manager.py:44-64`).
   - `planner.py:141-166` computes `compatible` and `deployable`; `deployable` requires
     `backend_ready` (backend status available), `source_ready` (`ArtifactState.READY`),
     `template_ready` (`TemplateState.READY`), and `cve_artifacts_ready`.
   - `planner.py:288-341` computes `next_action` guidance.
10. `_render_runtime_plan(plan)` prints Host OS, Architecture, Runtime, Backend, Guest,
    Guest architecture, Image, Acquisition, Source status, Template status, Compatible,
    Deployable, Next action (`cli.py:696-725`).

Current behavior note: plan is purely computed; nothing is persisted; no backend mutation.

### A.3 `rangeforge build <scenario>`

Ordered trace:

1. `cli.py:838 build()` → `_lifecycle_command("build", ...)` (`cli.py:845`).
2. `_lifecycle_command` (`cli.py:783-788`): `_runtime_context()` (full validation + plan),
   `primitive_engine.compile_plan(scenario, plan)` (`runtime_primitives/engine.py:105`),
   then `lifecycle.build(scenario, scenario_path, plan)`.
3. `ScenarioLifecycle.build()` (`lifecycle.py:107-198`):
   1. `_require_deployable(plan)` (`lifecycle.py:459-470`): requires `plan.compatible`,
      `plan.deployable`, non-None backend.
   2. `platform = _guest_platform_from_family(plan.guest.family)` (`lifecycle.py:117`,
      `lifecycle.py:52-58`).
   3. **Windows+Vagrant denial guard** at `lifecycle.py:118-124`: raises `LifecycleError`
      before any backend runner call. (Covered by
      `tests/test_lifecycle.py:418-499 test_windows_vagrant_build_rejected_before_backend_calls`,
      asserting `vagrant.prepared_boxes == []`.)
   4. `template = self.template_manager.require_ready(plan.guest.image_id, backend)`
      (`lifecycle.py:125`, `images/templates.py:125-145`): requires READY template metadata,
      fresh fingerprint via `template_fingerprint()` (`images/templates.py:21-34`), and
      source-checksum freshness vs. registry. **Current gap:** `require_ready` validates
      metadata only; it does not verify the backend template object still exists (compare
      `prepare()` which does check `backend_driver.template_exists(...)` at
      `images/templates.py:88,97`). Architecture §4 "Template readiness" requires a
      build-time existence check.
   5. `template.architecture != self.host.architecture` → reject (`lifecycle.py:126-130`);
      regression test `tests/test_lifecycle.py:250-284
      test_architecture_mismatch_is_rejected_before_clone` asserts no clone occurs.
   6. `store = RuntimeMetadataStore(scenario_path)` (`runtime/metadata.py:37-46`); paths:
      `runtime_dir = scenario_path.parent / "runtime"`; `path = runtime_dir / "runtime.yaml"`;
      `vagrant_directory = runtime_dir / "vagrant"` (`metadata.py:39-46`).
   7. Existing-metadata branch (`lifecycle.py:133-146`):
      - `store.validate_ownership(scenario, existing)` (`metadata.py:87-99`)
      - `_reject_cross_platform_metadata(existing, platform)` (`lifecycle.py:70-88`)
      - if `_resource_exists(...)` (`lifecycle.py:431-436`) → return `changed=False`,
        message "Scenario VM already exists."
      - else → `LifecycleError` "Runtime metadata exists but the managed scenario resource
        is missing. Run destroy to clear stale metadata before rebuilding."
   8. New-build branch (`lifecycle.py:148-167`): `name = scenario_vm_name(scenario)`
      (`metadata.py:20-29`; e.g. id `5004` → `rf-5004`, asserted by
      `tests/test_lifecycle.py:174-177` for scenario `1337` → `rf-1337`). For UTM:
      `self.utm.vm_exists(name)` guard at `lifecycle.py:152-155` ("Refusing to claim existing
      UTM VM ..."). Then `self._backend_call(self.utm.clone, template.reference, name)`
      (`lifecycle.py:156`; backend `utm.py:92-93`). For Vagrant:
      `self.vagrant.prepare_environment(store.vagrant_directory, box, name)`
      (`lifecycle.py:166-168`; backend `vagrant.py:79-99`).
   9. Persist metadata (`lifecycle.py:170-193`): builds `RuntimeMetadata` with
      `metadata_version` default 3 (`runtime/models.py:229`), `vm=VMIdentity(name,
      managed_id=scenario_managed_id(scenario), state=VMState.STOPPED)`,
      `template=RuntimeTemplateReference(image_id, template_id, name, fingerprint)`,
      `guest=RuntimeGuestState(architecture, platform, management_transport, execution_language)`;
      `store.save(metadata)` writes atomically via `*.yaml.partial` + `replace`
      (`metadata.py:57-67`) and refuses symlinked `runtime_dir` (`metadata.py:58-59`).
   10. Return `LifecycleResult(changed=True, ...)`.

Backend calls for build: UTM → `utmctl clone <template.reference> --name <name>`;
Vagrant → writes a `Vagrantfile` in `runtime/vagrant/` (no VM boot).

### A.4 `rangeforge up <scenario>`

Ordered trace:

1. `cli.py:848 up()` → `_lifecycle_command("up", ...)` → `_runtime_context()` (full
   validation + plan) → `lifecycle.up(scenario, scenario_path, plan)` (`cli.py:788`).

2. `ScenarioLifecycle.up()` (`lifecycle.py:200-315`):
   1. `built = self.build(scenario, scenario_path, plan)` (`lifecycle.py:208`) — up always
      runs the full build path first (idempotent build/reconciliation).
   2. Loads persisted metadata, `store = RuntimeMetadataStore(scenario_path)`
      (`lifecycle.py:209-211`).
   3. `windows_guest = effective_guest_platform(metadata) is GuestPlatform.WINDOWS`
      (`lifecycle.py:212`; helper `management.py:113-120` maps legacy missing platform to
      LINUX).
   4. `state = self._state(metadata, store)` (`lifecycle.py:213`, backend dispatch at
      `lifecycle.py:438-443`).
   5. **Already-running READY fast path** (`lifecycle.py:215-237`): if RUNNING and persisted
      management READY:
      - Linux: return `changed=False` immediately (`lifecycle.py:216-221`).
      - Windows: sleeps `_WINDOWS_MANAGEMENT_SETTLE_SECONDS = 10.0` (`lifecycle.py:49,227`),
        then `_verify_windows_management(...)` (`lifecycle.py:228-230`,
        `lifecycle.py:399-429`). If still ready → `changed=False`. If wedge detected →
        `wedged_ready_probe = failed_checks` and falls through to converge to
        RUNNING/UNAVAILABLE. (Regression tests:
        `tests/test_management_readiness.py:630-711`.)
   6. Persist STARTING/WAITING (`lifecycle.py:239-247`).
   7. If not already RUNNING, issue start: UTM `self.utm.start(name)` (`lifecycle.py:250`);
      Vagrant `self.vagrant.start(store.vagrant_directory)` (`lifecycle.py:252`).
   8. Poll loop for RUNNING with local `deadline = time.monotonic() + timeout`
      (`lifecycle.py:254-260`; default `timeout=60` at `lifecycle.py:206`).
   9. If not RUNNING by deadline: persist `VMState.ERROR` and raise `LifecycleError`
      "did not reach RUNNING before the timeout" (`lifecycle.py:261-266`).
   10. IP/address discovery `_ip_addresses(...)` (`lifecycle.py:268-271`,
       `lifecycle.py:445-450`): UTM `utmctl ip-address` parsed in `utm.py:117-130`;
       Vagrant `ssh-config` HostName in `vagrant.py:126-131`.
   11. Readiness decision (`lifecycle.py:274-287`):
       - If stale-READY re-probe already failed → `ready=False, failed_checks=wedged_ready_probe`.
       - Else if Windows: sleep settle window (10 s) then `_verify_windows_management`
         (`lifecycle.py:283-284`).
       - Else (Linux): `ready = bool(addresses)` — IP discovery alone is the Linux
         readiness signal (`lifecycle.py:285-287`; regression
         `tests/test_management_readiness.py:458-482,599-627`).
   12. Persist final state `running` with `guest.ip` and
       `management=READY or UNAVAILABLE` (`lifecycle.py:288-303`).
   13. Return `LifecycleResult(changed=True, ...)`. **Current gap:** up returns success even
       when management is UNAVAILABLE; the architecture (§8 "Failure behavior") requires
       lifecycle failure + nonzero CLI exit.

Backend calls for up: `clone` (first time via build), `utmctl start <name>` /
`vagrant --chdir <dir> up`, `utmctl status` polling, `utmctl ip-address` /
`vagrant ssh-config`, and for Windows the Phase 5.3 probe (see §F).

### A.5 `rangeforge status <scenario>`

1. `cli.py:965 status()` → `_lifecycle_command("status", ...)` → `_lifecycle_only_context()`
   (full static validation, **no** plan) → `lifecycle.status(scenario, scenario_path)`.
2. `ScenarioLifecycle.status()` (`lifecycle.py:317-371`):
   1. `store.load()`; if None → `changed=False, "Scenario VM is not built."` (`lifecycle.py:320-321`).
   2. `store.validate_ownership(scenario, metadata)` (`lifecycle.py:322`).
   3. `_reject_cross_platform_metadata(...)` for known scenario platform (`lifecycle.py:323-325`).
   4. `state = self._state(...)`; addresses only if RUNNING (`lifecycle.py:326-327`).
   5. Windows branch (`lifecycle.py:329-351`): if running and persisted READY, re-probe via
      `_verify_windows_management`; READY may be downgraded to UNAVAILABLE. If not running →
      management forced NOT_READY. If running and persisted NOT_READY/WAITING/UNAVAILABLE,
      **no re-probe occurs** (`lifecycle.py:346-351` keeps persisted state). This is the gap
      in architecture §9 "Every running Windows VM is checked through the Phase 5.3
      readiness probe, regardless of its persisted management state." Current evidence:
      `tests/test_management_readiness.py:289-320` (
      `test_windows_status_never_marks_ready_from_ip_alone`) asserts a RUNNING Windows clone
      with persisted NOT_READY is NOT probed and stays NOT_READY — today's status cannot
      recover a false-not-ready state.
   6. Linux branch (`lifecycle.py:352-355`): READY iff addresses non-empty.
   7. Persist updated metadata unconditionally via `store.save(updated)`
      (`lifecycle.py:367`) — note status always persists even when nothing changed, and
      `LifecycleResult.changed` is always False (`lifecycle.py:371`), so the CLI cannot
      distinguish reconciliation changes. Architecture §9 requires "The lifecycle result
      indicates whether reconciliation changed persisted metadata."

Backend calls for status: `utmctl status`, optionally `utmctl ip-address`,
optionally the Windows probe. Never starts/stops/creates/deletes.

### A.6 `rangeforge destroy <scenario>`

1. `cli.py:974 destroy()` → `_lifecycle_command("destroy", ...)` → `_lifecycle_only_context()`
   → `lifecycle.destroy(scenario, scenario_path)`.
2. `ScenarioLifecycle.destroy()` (`lifecycle.py:373-397`):
   1. `store.load()`; if None → `store.remove()` (removes `runtime.yaml` plus
      `provisioning-plan.json`, `instructor.json`, `validation.json`, and empties
      `student/` artifacts; `metadata.py:69-85`) and return `changed=False`
      "already absent."
   2. `store.validate_ownership(scenario, metadata)` (fails closed on mismatch; regression
      `tests/test_lifecycle.py:310-335 test_destroy_rejects_tampered_ownership_metadata`
      asserts the VM survives and raises `RuntimeMetadataError`).
   3. UTM branch (`lifecycle.py:380-391`):
      - if `self.utm.vm_exists(metadata.vm.name)`:
        - `state = self.utm.vm_state(...)`; if RUNNING or STARTING →
          `self.utm.stop(name, force=True)` then poll for STOPPED up to 30 s
          (`lifecycle.py:385-390`). **Gap:** after the wait loop, there is no check that
          state actually reached STOPPED; `_backend_call(self.utm.delete, name)` executes
          regardless (`lifecycle.py:391`). Since `utm.py:114` maps UTM `"stopping"` →
          `VMState.STOPPED`, a still-stopping VM looks stopped and is deleted immediately.
      - then `utmctl delete <name>`; no post-delete absence confirmation.
   4. Vagrant branch (`lifecycle.py:392-395`): if
      `self.vagrant.environment_exists(store.vagrant_directory)` →
      `self.vagrant.delete(directory)` (`vagrant destroy --force`) +
      `_remove_vagrant_directory(store)` (`lifecycle.py:472-477`, which refuses to recurse
      into anything that is a symlink or not under `runtime_dir`). **Gap:** no
      state/ownership inspection of the Vagrant machine before destroy; the only identity
      is the scenario-local directory. Also, destroy with metadata always removes the
      runtime dir even when the backend object is missing (the "stale metadata" cleanup
      path), but there is no distinction between "confirmed absent" and "conflicting
      same-name foreign object."
   5. `store.remove()` (`lifecycle.py:396`) then `changed=True`.

Backend calls for destroy: `utmctl status|stop --force|delete <name>` by **name only**;
Vagrant `destroy --force` by directory.

### A.7 Summary of validation asymmetry

`plan`, `build`, `up` construct a full `RuntimePlan` and compile primitives; `status` and
`destroy` do not plan but still perform full static validation. All five commands currently
require the scenario to pass `ScenarioValidator` against its **profile**, which is the
mechanism that keeps the production `oscp` profile (Linux-only) default-deny for Windows —
and which also currently blocks the standalone Windows lifecycle path the architecture
mandates. The architecture requires a **lifecycle-specific structural validator** selected
by command scope (no new persisted scenario flag; architecture §2, "No new persisted
`runtime_only` scenario flag is required").

---

## B. Reusable components

These are platform-neutral today and must be reused unchanged (or with only generic
extension), per architecture §3.

| Component | File:symbol | Why reusable | Invariant callers must preserve |
|---|---|---|---|
| Host detection | `rangeforge/host/detector.py:HostDetector.detect` (`detector.py:46-67`), `HostDetector.normalize_os/normalize_architecture` (`detector.py:37-44`) | OS/arch normalization and backend discovery are platform-agnostic. | Never widen host→backend inference; detection stays read-only (no mutation). |
| Host→backend policy | `rangeforge/runtime/resolver.py:VM_HOST_BACKENDS` (`resolver.py:13-20`) | macOS ARM64→UTM direct; AMD64 hosts→Vagrant; single authoritative mapping. | Do not route UTM through Vagrant; no new host mappings in Phase 5.4. |
| Runtime resolver | `rangeforge/runtime/resolver.py:RuntimeResolver.resolve` (`resolver.py:24-78`) | Pure, deterministic, already accepts `guest_architecture` without letting it influence backend selection (`resolver.py:40-42`). | Guest architecture must never influence backend choice. |
| Guest compatibility | `rangeforge/runtime/guest.py:check_guest_compatibility` (`guest.py:138-260`), `GUEST_CAPABILITIES` (`guest.py:95-100`) | Data-driven; already models Windows capabilities (`guest.py:86-93`) and Windows-Vagrant denial (`guest.py:227-231`). | Remains the only compatibility matrix; lifecycle validates but must not re-derive policy. |
| Planner | `rangeforge/runtime/planner.py:RuntimePlanner.plan` (`planner.py:61-186`) | Deterministic, side-effect-free, already handles Windows image resolution and non-deployable guidance. | Planning never mutates; planner output remains authoritative for compatibility. |
| Image resolution | `rangeforge/images/resolver.py:ImageResolver.resolve` (`resolver.py:17-47`) | Exact matching against trusted registry; Windows manifests already declared (`images/definitions/windows.yaml`). | Images only from trusted registry; no arbitrary identities. |
| Image acquisition/readiness | `rangeforge/images/manager.py:ImageManager.verify/inspect/import_image/pull` (`manager.py:44-97,99-133,135-207`) | Checksum-before-READY is enforced generically; manual acquisition path is platform-neutral. | Manual Windows media never downloaded; checksum verification mandatory before READY. |
| Template identity/readiness | `rangeforge/images/templates.py:TemplateManager.require_ready` (`templates.py:125-145`), `template_id` (`templates.py:37-38` → `rf-base-<image-id>`), `template_fingerprint` (`templates.py:21-34`) | Deterministic naming + fingerprint of image/checksum/backend/schema; works for `rf-base-windows-11-arm64` (asserted by `tests/test_templates.py:101-104`). | Template metadata readiness alone never deploys; build-time backend existence check is added (§C), not a second policy. |
| Scenario VM naming / managed ID | `rangeforge/runtime/metadata.py:scenario_vm_name` (`metadata.py:20-29`), `scenario_managed_id` (`metadata.py:32-34`) | Deterministic, slug-safe, content-bound managed ID; `rf-5004` example matches architecture §7. | Naming stays derived, never user supplied; VM name ≠ template name (`metadata.py:98-99`). |
| Metadata store | `rangeforge/runtime/metadata.py:RuntimeMetadataStore.load/save/remove/validate_ownership` (`metadata.py:47-99`) | Atomic save via `*.yaml.partial` + `replace` (`metadata.py:61-66`); symlink refusal (`metadata.py:58-59`); deterministic lifecycle-artifact cleanup in `remove`. | Ownership validation is metadata-only today; Phase 5.4 extends it with backend-native identity checks — callers keep calling it before any mutation. |
| Windows management readiness authority | `rangeforge/runtime/management.py:probe_windows_management` (`management.py:1696-1725`), `_run_readiness_probe` (`management.py:1555-1693`), `_owned_management_transport` (`management.py:1401-1439`) | Phase 5.3 reviewed transport: fixed QGA/PowerShell argv, bounded budgets, marker-bound results, ownership-gated. | All QGA/PowerShell command framing, architecture attestation, and cleanup stay inside `management.py`; lifecycle only calls `probe_windows_management`. |
| Linux transports | `rangeforge/runtime_primitives/transport.py:UTMGuestTransport` (`transport.py:93-218`), `VagrantGuestTransport` (`transport.py:221-277`), `owned_guest_transport` (`management.py:1442-1475`) | Existing Linux behavior is preserved per architecture §3. | Phase 5.4 must not alter Linux provisioning semantics except through generic ownership/state hardening. |
| Backend call wrapper | `rangeforge/runtime/lifecycle.py:ScenarioLifecycle._backend_call` (`lifecycle.py:452-457`) | Converts `BackendOperationError` into actionable `LifecycleError` uniformly. | All backend mutations go through this so errors stay typed. |
| Deployability gate | `rangeforge/runtime/lifecycle.py:ScenarioLifecycle._require_deployable` (`lifecycle.py:459-470`) | Single plan-compatibility/deployability gate shared by build and up. | Remains the only plan gate; do not duplicate planner policy. |
| Windows-Vagrant lifecycle denial | `rangeforge/runtime/lifecycle.py:118-124` | Defense-in-depth denial before backend calls even if a caller forces a plan. | Must stay; deny-by-default at planning and lifecycle layers. |
| Cross-platform metadata guard | `rangeforge/runtime/lifecycle.py:_reject_cross_platform_metadata` (`lifecycle.py:70-88`) + `management.effective_guest_platform` (`management.py:113-120`) | Fail-closed handling of pre-platform (v1/v2) metadata; legacy metadata never becomes Windows-capable. Rationale recorded in `git show 62a3f24` ("Fail closed on pre-platform metadata for Windows scenarios ... preserving legacy Linux IP readiness"). | Never silently upgrade legacy metadata to Windows ownership. |
| Deterministic serializer | `rangeforge/serialization/yaml.py:ScenarioYamlSerializer` (`yaml.py:11-33`) | Deterministic dump/load reused by all commands. | N/A. |

---

## C. Components requiring modification

Each entry: exact repository-evidenced reason, minimal change consistent with the approved
architecture, and affected paths/tests.

### C.1 `rangeforge/runtime/models.py` — runtime state and identity models

- Symbols: `VMState` (`models.py:73-79`), `VMIdentity` (`models.py:164-167`),
  `RuntimeGuestState` (`models.py:177-186`), `RuntimeMetadata` (`models.py:219-229`).
- Evidence/reason:
  - `VMState` lacks `STOPPING` and `MISSING`. `utm.py:114` currently maps UTM `"stopping"`
    to `VMState.STOPPED`, and a metadata-recorded-but-backend-absent VM can only surface as
    `NOT_BUILT` from `utm.vm_state` (`utm.py:107`). Architecture §4 requires explicit
    `STOPPING` and `MISSING` and an explicit unknown/error state (UNKNOWN and ERROR already
    exist at `models.py:78-79`).
  - `VMIdentity` carries only `name`, `managed_id`, `state`; there is no backend-native
    resource reference (UTM UUID / Vagrant machine ID). Ownership therefore reduces to name
    matching — see §G.
  - `RuntimeGuestState` has no guest product/version fields; architecture §4 requires
    persisting guest product/version so status can render "Windows 11" without consulting
    mutable registry state. (The data exists at build time as `plan.guest.distribution` /
    `plan.guest.version`, `lifecycle.py:104-109` via planner.)
  - No bounded failure classification/message field exists; architecture §4 requires a
    bounded, non-secret lifecycle failure classification and message.
  - `RuntimeMetadata.metadata_version = 3` (`models.py:229`) needs incrementing per
    architecture §4.
- Minimal change: add `STOPPING` and `MISSING` to `VMState`; add `resource_id` (backend-native
  reference, e.g. UTM UUID or Vagrant machine/provider ID) to `VMIdentity`; add
  `product`/`version` (e.g. "Windows", "11") to `RuntimeGuestState`; add a bounded
  `failure` record (classification + bounded message); add an ownership `fingerprint` field
  (see C.2); bump `metadata_version` to 4. These are new fields/enums on existing models —
  not new subsystems.
- Affected paths/tests: all lifecycle flows; serialization round-trip test
  `tests/test_lifecycle.py:180-194`; metadata fixtures in `tests/test_management_readiness.py:297-315`
  and `tests/test_management_transport.py:572-601` (construct `RuntimeMetadata` literally);
  new schema round-trip tests per architecture §15.

### C.2 `rangeforge/runtime/metadata.py` — ownership and persistence hardening

- Symbols: `RuntimeMetadataStore.validate_ownership` (`metadata.py:87-99`),
  `RuntimeMetadataStore.save` (`metadata.py:57-67`),
  `RuntimeMetadataStore.vagrant_directory` (`metadata.py:43-46`).
- Evidence/reason:
  - `validate_ownership` checks scenario id, profile, name, managed_id, and template-name
    inequality — but not backend-native identity, because none is persisted (see C.1).
    `test_destroy_rejects_tampered_ownership_metadata` (`tests/test_lifecycle.py:310-335`)
    proves tampered `managed_id` is caught, but a foreign VM with the **same name** as the
    scenario VM is indistinguishable today.
  - There is no ownership fingerprint. Architecture §6 "Ownership fingerprint" requires a
    deterministic fingerprint binding schema, managed ID, backend, backend-native identity,
    expected name, template identity+fingerprint, platform, architecture.
  - `save()` guards `runtime_dir` symlink (`metadata.py:58-59`) but the Vagrant
    subdirectory is resolved lazily and `prepare_environment` (`lifecycle.py:166-168`) runs
    before any canonical-path/symlink validation of `scenario_path.parent / "runtime" /
    "vagrant"`; architecture §4 requires canonical-path and symlink checks for
    scenario-owned runtime directories before mutation. Note current destroy-side symlink
    protection exists only in `_remove_vagrant_directory` (`lifecycle.py:472-477`).
- Minimal change: extend `validate_ownership` to validate the new fingerprint and (for
  schema ≥ new) the presence of backend-native identity; add fingerprint computation helper
  (a new helper function, per architecture §6); add canonical path/symlink checks for the
  runtime directory and Vagrant directory used as a pre-mutation gate. Keep
  `scenario_vm_name`/`scenario_managed_id` unchanged.
- Affected paths/tests: build/up/status/destroy; `tests/test_lifecycle.py`,
  `tests/test_management_readiness.py`, `tests/test_management_transport.py
  (TestOwnershipGate at tests/test_management_transport.py:1632)`; new tamper tests per
  architecture §15 ("Tampered UUID fails ownership validation," etc.).

### C.3 `rangeforge/runtime/backends/utm.py` — typed inventory + UUID identity + state mapping

- Symbols: `UTMBackend._names_from_listing` (`utm.py:80-90`), `UTMBackend.list_vms`
  (`utm.py:58-64`), `UTMBackend.vm_exists`/`vm_state`/`ip_addresses`/`start`/`stop`/`delete`
  (`utm.py:74-130`), `UTMBackend.clone` (`utm.py:92-93`).
- Evidence/reason:
  - `_names_from_listing` parses `utmctl list` output of form `UUID STATUS NAME` but
    **discards the UUID** (`parts[2]` only, `utm.py:87-89`). Architecture §1 "Gaps":
    "UTM inventory parsing does not retain VM UUIDs."
  - `vm_state` maps `"stopping"` → `VMState.STOPPED` (`utm.py:114`) — conflates a
    transitional state with stopped; destroy deletes by name without confirming stopped (§A.6).
  - All mutating calls target the VM by name (`utm.py:95-102`).
- Minimal change: parse inventory into typed records (uuid, name, state) — a new typed
  record plus lookup-by-UUID/by-name helpers on `UTMBackend`; map `stopping` → `VMState.STOPPING`;
  return `VMState.UNKNOWN` for unrecognized states (already partially done via `.get(raw,
  VMState.UNKNOWN)` at `utm.py:115`); add a `template_exists`-independent resource-exists
  check keyed on UUID; thread identity-validated targeting into start/stop/delete/state/
  address (architecture §4: "Target start, stop, delete, state, and address operations
  through the validated backend identity"). Whether utmctl supports UUID addressing per
  operation must be confirmed during implementation; if not, the minimal compliant design is
  UUID+name agreement re-validated immediately before each name-addressed call.
- Affected paths/tests: all five lifecycle flows; fakes `FakeUTM` (`tests/test_lifecycle.py:51-86`)
  and `LifecycleUTM` (`tests/test_management_readiness.py:65-99`) and `RecordingUTM`
  (`tests/test_management_transport.py:504-516`) will need UUID-aware extensions; the
  architecture §16 mandates a "filesystem-faithful fake UTM inventory containing UUID, name,
  and state."

### C.4 `rangeforge/runtime/backends/vagrant.py` — environment identity hardening (Linux path preserved)

- Symbols: `VagrantBackend.prepare_environment` (`vagrant.py:79-99`),
  `environment_exists` (`vagrant.py:101-102`), `vm_state` (`vagrant.py:113-124`),
  `ip_addresses` (`vagrant.py:126-131`).
- Evidence/reason:
  - Identity is the scenario-local directory plus `Vagrantfile` existence
    (`vagrant.py:101-102`); no fingerprint of the generated Vagrantfile, box identity, or
    provider; no symlink rejection before `prepare_environment` writes into the directory
    (`vagrant.py:84 mkdir(parents=True, exist_ok=True)` follows symlinks on `directory`
    parents); no provider machine ID persistence.
  - `vm_state` has no `STOPPING`/transitional handling (`vagrant.py:113-124`); unknown →
    `VMState.UNKNOWN` already.
- Minimal change: deterministic environment fingerprint (canonical env path + machine name +
  generated Vagrantfile content + box identity + provider), symlink rejection before
  mutation, and persistence of provider machine ID after first up (architecture §4: "Do not
  boot a VM during build solely to obtain a provider machine ID"). These are new helpers on
  the existing backend class or metadata store — no new subsystem.
- Affected paths/tests: Linux Vagrant regression `tests/test_lifecycle.py:338-415
  test_manual_vagrant_template_reference_builds_scenario_environment`; Windows-Vagrant
  denial test `tests/test_lifecycle.py:418-499`.

### C.5 `rangeforge/runtime/lifecycle.py` — `ScenarioLifecycle` convergence and gates

- Symbols: `ScenarioLifecycle.build` (`lifecycle.py:107-198`), `.up` (`lifecycle.py:200-315`),
  `.status` (`lifecycle.py:317-371`), `.destroy` (`lifecycle.py:373-397`),
  `._resource_exists`/`._state`/`._ip_addresses` (`lifecycle.py:431-450`),
  `._verify_windows_management` (`lifecycle.py:399-429`).
- Evidence/reason (current vs required):
  - **No generic stop.** No `stop()` exists; destroy embeds its own stop+poll
    (`lifecycle.py:383-390`) without convergence verification (see §H).
  - **No pre-mutation plan/scenario/host consistency gate.** `build()` trusts the supplied
    plan: it never checks `plan.scenario_id == scenario.scenario.id`, nor that the plan's
    host/backend/image/architecture match the current host — only template-vs-host
    architecture is checked (`lifecycle.py:126-130`) and Windows-Vagrant denied
    (`lifecycle.py:118-124`). Evidence: tests fabricate plans directly
    (`tests/test_lifecycle.py:374-398`, `tests/test_management_readiness.py:160-185`), so a
    mismatched-but-`deployable=True` fabricated plan would pass. Architecture §7 requires
    consistency checks: same scenario, same detected host, backend matches host policy,
    scenario/guest/image/template platform+architecture agreement, plan image == template
    image.
  - **Idempotent build under-validates.** With existing metadata + existing resource,
    build returns unchanged after `validate_ownership` + platform check only
    (`lifecycle.py:134-142`); it does not compare the current plan against persisted
    backend/image/template/architecture, nor verify backend template object existence, nor
    UUID agreement.
  - **Up timeout semantics.** `timeout` bounds only the start-convergence loop
    (`lifecycle.py:254-260`); the 10 s settle (`lifecycle.py:227,283` via
    `_WINDOWS_MANAGEMENT_SETTLE_SECONDS = 10.0`, `lifecycle.py:49`) and the full probe
    budget (`_PROBE_TOTAL_BUDGET = 300.0`, `management.py:1520`) sit **outside** any single
    lifecycle deadline. Architecture §8 requires one operation deadline covering VM
    convergence + management readiness, with remaining budget passed to the probe.
  - **Up failure semantics.** When the probe fails, up currently returns a successful
    `LifecycleResult` with management UNAVAILABLE (`lifecycle.py:304-315`); architecture
    §8 requires an explicit lifecycle failure and nonzero CLI exit. (Tests currently assert
    success-returning behavior, e.g. `tests/test_management_readiness.py:271-286` asserts
    the returned metadata is UNAVAILABLE; these tests will need to change to assert
    failure semantics.)
  - **Status does not re-probe every running Windows VM.** See §A.5: persisted NOT_READY /
    UNAVAILABLE are never re-probed (`lifecycle.py:346-351`); architecture §9 requires
    probing regardless of persisted state.
  - **Status change reporting.** `status()` always persists `updated` and returns
    `changed=False` (`lifecycle.py:367-371`); architecture §9 requires the result to
    indicate whether reconciliation changed persisted metadata.
  - **Destroy.** Deletes by name without confirming stopped state or post-delete absence
    (`lifecycle.py:385-396`); proceeds on `UNKNOWN` state; does not distinguish stale
    metadata / conflicting same-name foreign UUID cases (architecture §10 "Stale and
    conflict handling").
- Minimal change: one shared pre-mutation consistency + ownership gate used by build, up,
  stop, destroy (architecture §4 "One shared pre-mutation consistency and ownership gate");
  a generic bounded `stop()` reused by destroy; backend template existence check in build
  (§4 "Template readiness"); single-operation-deadline refactor in up; explicit failure on
  management-not-ready; status reconciliation updates per §9. All of this lives in the
  existing class — **no `WindowsLifecycle`, no parallel orchestrator** (architecture §2).
- Affected paths/tests: every lifecycle flow; nearly every lifecycle/readiness test needs
  review; new tests per architecture §§15-16.

### C.6 `rangeforge/runtime/management.py` — probe deadline integration only

- Symbol: `probe_windows_management` (`management.py:1696-1725`), `_run_readiness_probe`
  (`management.py:1555-1693`, `_PROBE_TOTAL_BUDGET = 300.0` at `management.py:1520`).
- Evidence/reason: the probe owns its own total budget (`management.py:1577`); lifecycle
  cannot pass a remaining deadline, so architecture §8 ("Invoke `probe_windows_management()`
  with the remaining deadline") cannot be satisfied today.
- Minimal change: accept an optional explicit remaining budget/deadline parameter that
  overrides `_PROBE_TOTAL_BUDGET` when provided; keep the default for direct callers
  (architecture §4 "Keep the existing default budget for direct callers"). Everything else
  (QGA framing, PowerShell, attestation, cleanup) stays inside management.py.
- Affected paths/tests: `tests/test_management_transport.py:TestProbeBudget`
  (`tests/test_management_transport.py:2137`) and readiness tests that patch
  `probe_windows_management` (`tests/test_management_readiness.py:203-221
  _patch_probe` — patched factories accept `**_`, so signature extension is compatible).

### C.7 `rangeforge/cli.py` — stop command, lifecycle validation mode, failure exit, status output

- Symbols: `app`/`runtime_app` command registrations (`cli.py:54-63`), `_lifecycle_command`
  (`cli.py:777-813`), `_runtime_context`/`_lifecycle_only_context` (`cli.py:113-195`),
  `_render_lifecycle` (`cli.py:755-774`).
- Evidence/reason:
  - No `stop` command exists (command list: generate/doctor/images/artifacts/cve/runtime
    plan/build/up/provision/validate/status/destroy; see `cli.py:233-980`).
  - `_render_lifecycle` (`cli.py:760-774`) prints Scenario/Runtime/Backend/VM/State/
    Template/Guest architecture/IP/Management/Provisioning/Validation but **not guest OS
    (product/version) or Ownership**; architecture §9 requires guest OS, guest architecture,
    backend, ownership, management state, VM state, address.
  - Up-management-failure returns exit code 0 today (only exceptions raise `typer.Exit(1)`,
    `cli.py:793-812`); architecture §8 requires nonzero exit.
  - Full static validation is applied uniformly; no lifecycle-specific structural
    validation mode exists (see §A.7). Note the architecture mandates this as a
    command-scoped narrower validator — implemented either as a new validation mode
    parameter on the CLI context builders or a small new validator path — but must not
    weaken `ScenarioValidator` for generation/provision/validate (architecture §20 item 1).
  - Bypassing full static validation is necessary but not sufficient. The stock profile has
    no `runtime_defaults["windows"]` (`oscp.yaml:39-44`), so `RuntimePlanner.plan()` returns
    `_incomplete_plan()` before compatibility/image resolution (`planner.py:84-92`). Existing
    Windows planner tests prove this by constructing an in-memory `_windows_profile()` view
    (`tests/test_runtime_planner.py:73-89`) rather than changing production policy. The
    architecture requires an explicit lifecycle-only guest requirement source while leaving
    `allowed_platforms` and technique policy unchanged.
  - Build and up unconditionally call `primitive_engine.compile_plan(...)` before lifecycle
    dispatch (`cli.py:784-788`). That couples standalone lifecycle to Linux runtime primitive
    resolution and deterministic provisioning configuration even though Phase 5.4 must not
    enable Windows primitives. Existing Linux training scenarios may rely on this preflight,
    so it must not be removed globally without regression evidence.
- Minimal change: add `stop` command routed through `_lifecycle_command` (with plan-less
  context like status/destroy); select the lifecycle-scoped structural validator by command;
  provide a command-scoped planner profile view containing the existing `GuestRequirement`
  for Windows 11 while preserving the production profile's Linux-only `allowed_platforms`
  and techniques; skip primitive-plan compilation only for the standalone lifecycle-only
  Windows path; add extended status rendering and explicit nonzero exit when up cannot reach
  Windows management readiness. This uses existing `TrainingProfile`/`GuestRequirement`
  models and does not add a persisted scenario flag.
- Affected paths/tests: `tests/test_cli.py` additions per architecture §15 (CLI tests).

### C.8 `rangeforge/validation/scenario.py` — lifecycle-scoped structural validation hook

- Symbol: `ScenarioValidator.validate` (`validation/scenario.py:13-102`).
- Evidence/reason: production profile denies Windows (`oscp.yaml:3-4`), and the validator
  couples profile eligibility, primitive eligibility, graph solvability, and mode checks in
  one method. Standalone Windows lifecycle cannot pass platform checks
  (`validation/scenario.py:24-27`) without weakening the production policy.
- Minimal change (per approved architecture, not a redesign): introduce a lifecycle-scoped
  validation path selected by command scope — the narrowest implementation is a new
  function/method (e.g. structural-only validation of scenario identity and runtime-relevant
  structure) invoked by the six lifecycle commands, leaving `ScenarioValidator.validate`
  untouched for generate/provision/validate. This is a **new helper**, not a modification of
  the default-deny semantics. The architectural wording "runtime-lifecycle structural
  validation" (architecture §2 target-flow diagram) maps to this helper plus existing
  loader strictness.
- Affected paths/tests: `tests/test_cli.py` (Windows input accepted only by runtime plan,
  build, up, status, stop, destroy; still rejected by provision/validate/generate —
  architecture §15) and `tests/test_validation.py`.

### C.9 `rangeforge/images/templates.py` — build-time backend template existence

- Symbol: `TemplateManager.require_ready` (`templates.py:125-145`).
- Evidence/reason: `require_ready` validates metadata+fingerprint freshness only. The
  backend existence check exists only in `prepare()` (`templates.py:88,97-101`). A READY
  metadata record whose backend object was deleted passes `require_ready` and would reach
  `self.utm.clone(template.reference, name)` → backend failure at clone time, i.e. **after**
  lifecycle mutation begins. Architecture §4 requires the existence confirmation before
  cloning, explicitly "existence verification, not a second template readiness policy."
- Minimal change: lifecycle build calls the backend's `template_exists(template.reference)`
  (existing method on both backends — `utm.py:66-72`, `vagrant.py:64-74`) after
  `require_ready`; **no change to `require_ready` semantics**. This is "stricter use of an
  existing symbol" (the `TemplateBackend` protocol at `templates.py:41-44` already declares
  `template_exists`); the change belongs in `lifecycle.build`, keeping `templates.py`
  read-mostly. (If deemed cleaner, a thin `TemplateManager.require_deployable(image_id,
  backend, driver)` wrapper could be added, but that is optional.)
- Affected paths/tests: build path; new test "READY template record whose backend object is
  missing fails before clone" (architecture §15).

---

## D. New components genuinely required

Per architecture §2 and the reconnaissance above, **no new top-level subsystem or class is
required.** Specifically, no `WindowsLifecycle`, no parallel Windows planner/registry/image
manager, and no second metadata store. The genuinely new items are small and local:

1. **Lifecycle-scoped structural validator** (helper function or method; see C.8).
   - Responsibility: validate scenario identity and runtime-relevant structure (YAML schema,
     identity fields, declared platform/architecture well-formedness) without curriculum,
     primitive, graph-solvability, or attack-path policy.
   - Why existing abstractions cannot handle it: `ScenarioValidator.validate`
     (`validation/scenario.py:13-102`) is profile-default-deny by design and is the
     mechanism that must keep generation/provisioning Windows-denied; reusing it would
     either block the mandated Windows lifecycle or weaken production policy. The
      architecture explicitly scopes this to command selection with no persisted scenario
      flag.
2. **Lifecycle-only planner requirement view** (small CLI/context helper using existing
   `TrainingProfile` and `GuestRequirement` models; see C.7).
   - Responsibility: provide the Windows 11 guest family/distribution/version required by
     `RuntimePlanner` only for lifecycle commands, without adding Windows to the profile's
     `allowed_platforms` or technique policy.
   - Why existing: `RuntimePlanner` requires `profile.runtime_defaults[platform]` and returns
     an incomplete plan when absent (`planner.py:84-92`); the stock profile intentionally
     omits Windows. The tests' `_windows_profile()` fixture demonstrates the required input
     shape but is not available to production CLI code.
3. **Ownership fingerprint helper** (function in `metadata.py`; see C.2).
   - Responsibility: compute/verify the deterministic fingerprint over schema, managed ID,
     backend, backend-native identity, expected name, template identity+fingerprint,
     platform, architecture (architecture §6).
   - Why existing: `scenario_managed_id` binds scenario content but not any backend object
     identity; there is nothing to reuse for backend-native binding.
4. **Typed UTM inventory record + UUID lookup helpers** on `UTMBackend` (C.3).
   - A small typed record (uuid, name, state) plus lookup by UUID/name. Existing
     `_names_from_listing` cannot provide UUIDs (drops them at `utm.py:87-89`).
5. **Vagrant environment fingerprint helper** (C.4) and provider machine-ID persistence.
   - Existing `environment_exists` is a boolean on `Vagrantfile` presence
     (`vagrant.py:101-102`); no identity binding exists.
6. **CLI `stop` command** (C.7) and generic `ScenarioLifecycle.stop()` (C.5).
   - New method + command; reuses backend `stop` implementations already present
     (`utm.py:98-99`, `vagrant.py:107-108`).

Everything else is an extension of existing symbols (new enum members, new model fields,
stricter validation calls).

---

## E. Linux-specific assumptions discovered

Lifecycle-relevant (in Phase 5.4 scope):

| Assumption | Where | Evidence | Phase 5.4 handling |
|---|---|---|---|
| Linux readiness = "has an IP" | `lifecycle.py:285-287` (`ready = bool(addresses)`), `lifecycle.py:352-355` (status) | QEMU guest agent reports IP; used as Linux management readiness | Already branched per-platform (Windows uses the probe); parameterize tests rather than duplicate. Windows readiness never uses IP (comment `lifecycle.py:272-273`). |
| UTM `stopping` ≡ stopped | `utm.py:114` | `"stopping": VMState.STOPPED` mapping | Must change to `STOPPING` (generic; affects Linux too — needs a Linux regression). |
| Destroy assumes stop completed | `lifecycle.py:385-391` | no STOPPED assertion after poll; delete by name | Generic bounded stop with convergence proof (C.5). |
| Identity = name string | `lifecycle.py:152-156,250,268,434-435,441-442,449`; `utm.py:74-130`; `vagrant.py:101-124` | Every backend call is name/directory keyed | Backend-native identity (C.3/C.4); generic. |
| `up` treats Linux settle/probe budgets as unlimited | `lifecycle.py:49,227,283`; `management.py:1520` | settle constant 10 s; probe budget independent of up timeout | Single operation deadline (C.5/C.6). |

Provisioning/validation assumptions **out of Phase 5.4 scope** (listed for completeness; do
not touch in 5.4, per architecture §19):

| Assumption | Where | Evidence |
|---|---|---|
| Root-owned shell staging under `/root/.rangeforge-*` and `/var/lib/rangeforge/artifacts` | `runtime_primitives/transport.py:116-117,202,207,251-256` (UTM and Vagrant push paths) | Unix paths and `install -d -o root -g root` shell commands |
| Vagrant SSH with `sudo -n /bin/bash -s` | `runtime_primitives/transport.py:236-248` | Linux usernames/root semantics and shell |
| SSH-based address discovery for Vagrant | `vagrant.py:126-131` (`ssh-config` HostName) | SSH-centric readiness for Vagrant Linux guests |
| POSIX shell completion marker framing (`RF_TRANSPORT_COMPLETE`) | `runtime_primitives/transport.py:26,118-128` | shell-specific |
| QGA exec via `/bin/bash` | `runtime_primitives/transport.py:159-166` | shell interpreter path |

These are provisioning-transport concerns, already platform-branched through
`owned_guest_transport` (Linux-only, `management.py:1442-1475`) vs the Windows control
plane; Phase 5.4's mandate is lifecycle, not provisioning (roadmap line 135-141; Windows
provisioning is Task 5.5).

Ubuntu-specific image IDs and template naming (`ubuntu-24.04-arm64`,
`rf-base-ubuntu-24.04-arm64`): **no Linux-only assumption in production code** — template
naming derives from the generic image ID (`templates.py:37-38`); Windows equivalents already
exist (`windows-11-arm64`, `rf-base-windows-11-arm64`; `windows.yaml:10-27`, asserted by
`tests/test_templates.py:101-104`). Ubuntu IDs appear only in fixtures (e.g.
`tests/test_lifecycle.py:128,147`).

Linux usernames / guest users: none in the lifecycle path; `/root` usage is in the
provisioning transport only (out of scope).

QGA behavior assumptions (semantics of `utmctl exec`/`file push/pull` return codes) are
documented and modeled inside `management.py` Phase 5.3 code and the Linux transport; the
lifecycle layer itself assumes only `vm_state`/`ip_addresses` semantics.

---

## F. Windows transport integration points

Current Phase 5.3 path (as invoked from lifecycle):

1. `lifecycle.py:284` / `lifecycle.py:338-340` call
   `self._verify_windows_management(scenario, scenario_path)` (`lifecycle.py:399-429`).
2. `_verify_windows_management` calls `probe_windows_management(
   scenario, scenario_path, host=self.host, utm=self.utm, vagrant=self.vagrant,
   template_manager=self.template_manager,
   expected_architecture=self.host.architecture)` (`lifecycle.py:409-417`) and converts
   `ManagementTransportError` / `ImageManagerError` / `RuntimeMetadataError` / `OSError`
   into `(False, ("management_transport_unavailable",))` (`lifecycle.py:418-427`).
3. `probe_windows_management` (`management.py:1696-1725`) → `_owned_management_transport`
   (`management.py:1401-1439`) → `validate_management_target` (`management.py:131-263`),
   which validates: persisted metadata integrity, ownership, template identity completeness
   + fingerprint shape (`management.py:171-179`), platform match, allowlisted
   (platform, backend, transport, language) tuple vs `_MANAGEMENT_TRANSPORT_MATRIX`
   (`management.py:72-91,208-222` — Windows/Vagrant denied at `management.py:214-218`),
   host-backend policy via `VM_HOST_BACKENDS` (`management.py:224-228`), architecture match
   (`management.py:229-233`), trusted template registry reconciliation
   (`management.py:235-247`), and then backend existence + RUNNING state
   (`management.py:249-262`).
4. `_WindowsPowerShellTransport` (`management.py:459-1290`) executes the fixed protocol:
   warmup → bootstrap → sweep → pre-clean → upload barrier → framed exec → marker polling →
   verified cleanup; probe checks in `_run_readiness_probe` (`management.py:1555-1693`):
   `qga_execution`, `powershell_version`, `guest_architecture`, `marker_integrity`,
   `file_round_trip`, `staged_cleanup`, `exit_code_propagation`, `workspace_clean`.

Minimal lifecycle call boundary: **exactly the two existing call sites**
(`lifecycle.py:284`, `lifecycle.py:338-340`) plus the new status reprobe and the
stop/destroy paths must never invoke the probe (stopped/missing cannot be READY;
architecture §5 state table). Generic lifecycle may know:

- the probe's boolean outcome and failed check names (already consumed at
  `lifecycle.py:428-429`);
- the desired remaining deadline (new parameter, C.6);
- the management state enum to persist.

What must remain inside `management.py`: all QGA command construction (`_push_argv`,
`_pull_argv`, `_exec_argv` at `management.py:554-612`), fixed PowerShell path/argv
(`management.py:317-332`), all probe scripts (`management.py:1488-1552`), warmup/bootstrap/
sweep/pre-clean/cleanup logic, output bounding (`management.py:348-364`), per-VM locking
(`management.py:334-345`), and ownership/template gating (`validate_management_target`).
Architecture §3: "Phase 5.4 must not add architecture tables, Windows image selection
rules, QGA command framing, or PowerShell commands to `ScenarioLifecycle`."

Note for stop/destroy integration: `validate_management_target` requires the VM to be
RUNNING (`management.py:254-255,261-262`); therefore stop/destroy correctly never construct
transports. `_verify_windows_management` currently also re-loads metadata through the probe
factory, so the probe is inherently bound to persisted (validated) identity — after C.1/C.3
add backend-native identity, the resolution inside `management.py:249-255` should be
hardened to use the persisted UUID as the lookup root with the name as invariant (mirrors
C.3); this is a small change inside the ownership gate, still within `management.py`.

---

## G. Ownership/destroy safety findings

Current evidence:

- **Ownership model is metadata-only + name-keyed.** `validate_ownership`
  (`metadata.py:87-99`) checks scenario id/profile/name/managed_id/template-name inequality.
  Managed ID is a hash of scenario content (`metadata.py:32-34`) — deterministic and
  tamper-evident for metadata, but it cannot distinguish the actual backend object.
- **Scenario clone vs base template:** build refuses a same-name UTM VM before cloning
  (`lifecycle.py:152-155`); metadata refuses `vm.name == template.name`
  (`metadata.py:98-99`); probe refuses to target a template identity
  (`tests/test_management_readiness.py:485-519 test_probe_never_targets_base_template`).
  Clean template preservation in destroy is by construction: destroy only deletes
  `metadata.vm.name` and never touches `template.reference`; regression
  `tests/test_lifecycle.py:239-247` asserts template metadata and source artifact survive.
- **Unrelated VMs:** safe because mutations are keyed on the exact metadata name; nothing
  enumerates or pattern-matches VMs (`utm.py` listing use is name-membership only).
- **Stale backend VM with same name (no metadata):** build refuses to adopt
  (`lifecycle.py:152-155`, UTM); status with no metadata returns "not built" without
  inspecting (`lifecycle.py:320-321`) — architecture §9 requires reporting an ownership
  conflict when the expected name exists without metadata; destroy with no metadata just
  removes runtime dir (`lifecycle.py:376-378`) and **does not** check for a same-name VM —
  this is compliant with "refuse deletion" but the required conflict reporting (and the
  build-time conflict) currently hinge on name alone.
- **Same-name foreign VM (different UUID):** **indistinguishable today** — UTM UUIDs are
  discarded (`utm.py:87-89`). If an operator deletes RangeForge's clone and creates a new VM
  named `rf-5004`, current build sees metadata + `_resource_exists` → "already exists"
  (`lifecycle.py:134-142`), and destroy would stop+delete the **foreign** VM. This is the
  highest-impact ownership gap (architecture §1 gap #3, §6 "A changed UUID under the same
  name is an ownership conflict").
- **UTM UUIDs:** not parsed (see C.3).
- **Vagrant environments:** identity = scenario-local directory Vagrantfile presence
  (`vagrant.py:101-102`); no fingerprint/machine ID; destroy targets the directory with
  `vagrant destroy --force` (`vagrant.py:110-111`). A foreign `runtime/vagrant/` directory
  without metadata blocks build (`lifecycle.py:162-165`), and `_remove_vagrant_directory`
  refuses symlink/parent-mismatch (`lifecycle.py:472-477`), but Vagrant machine identity is
  provider-side and unverified.
- **Partial failure:** if `utmctl clone` succeeds but `store.save` fails
  (`lifecycle.py:156,193` — e.g. OSError mid-save), the next build hits the same-name
  refusal and reports a conflict; there is no orphan-conflict classification (architecture
  §7 "Build failures": report an orphan conflict, do not adopt). If the stop request succeeds
  but convergence times out during destroy, delete proceeds anyway today (see §H); a backend
  stop error itself raises before delete. If `delete` fails
  (`BackendOperationError` → `LifecycleError`), metadata is retained (store.remove at
  `lifecycle.py:396` never runs) — this part is already safe for retry.
- **Git history context:** ownership-by-metadata-first and refuse-to-claim semantics arrived
  in `2ccfe8d` ("feat: add image lifecycle, runtime primitives, and curated CVE framework")
  and the fail-closed treatment of legacy (pre-platform) metadata was hardened deliberately
  in `62a3f24` ("Fail closed on pre-platform metadata for Windows scenarios at build and
  status, preserving legacy Linux IP readiness") — showing the project's established
  pattern: never infer or upgrade ownership, always fail closed and require explicit
  operator action. Phase 5.4's fingerprint/UUID model extends this same decision.

Exact gaps to close (mapped to architecture §6): persist backend-native identity at clone
time (UTM UUID via post-clone inventory inspection; Vagrant machine/provider ID after first
up, not during build); ownership fingerprint; UUID+name agreement check before every
mutation; name-lookup conflict detection; destroy must not require the template to remain
present (currently `destroy` never consults the template — already compliant; note
`_verify_windows_management` does require template registry presence for status reprobes —
acceptable per §11 row "Shared template is removed after build ... destroy remains
allowed").

---

## H. Idempotence findings

| Operation | Current behavior (evidenced) | Required Phase 5.4 behavior |
|---|---|---|
| build twice | 2nd run: `validate_ownership` + platform check + `_resource_exists` → `changed=False` "already exists" (`lifecycle.py:134-142`); regression `tests/test_lifecycle.py:224-225`. Gaps: no plan-vs-metadata comparison, no backend template existence check, no UUID agreement; if the resource was replaced by a foreign same-name VM, build silently returns unchanged. | Return unchanged only when ownership validates, plan identity matches persisted host/backend/image/platform/architecture, template provenance+fingerprint match, backend object exists, UUID/env identity+name match, object is not the shared template (architecture §7 "Idempotent build"). |
| build with metadata but missing resource | `LifecycleError` "managed scenario resource is missing. Run destroy to clear..." (`lifecycle.py:143-146`). | Preserved and refined: stale state; build never silently replaces; destroy may clear metadata only if no conflicting name exists (§10); MISSING state representation needs `VMState.MISSING`. |
| up twice (Linux) | 2nd run: if RUNNING+READY → `changed=False` (`lifecycle.py:216-221`); no start issued. | Same, under shared deadline semantics. |
| up twice (Windows, READY) | Re-probe after 10 s settle; READY → unchanged; wedged → converge to UNAVAILABLE (`lifecycle.py:222-237`); regression `tests/test_management_readiness.py:630-711`. | Same reprobe semantics, but probe must run under the shared operation deadline (remaining budget), and failure must produce lifecycle failure + nonzero CLI exit per §8 (behavior change from today's success-with-UNAVAILABLE return). |
| up twice (Windows, NOT_READY/UNAVAILABLE) | Falls through: re-persist STARTING/WAITING, **no duplicate start** (state already RUNNING), re-probe (`lifecycle.py:277-284`). | Preserved; a persisted non-ready running Windows VM can recover via up. |
| stop twice | **No stop exists.** | First stop: one requested stop + bounded wait to STOPPED, management → NOT_READY. Repeated stop: unchanged, no backend stop call (architecture §16 stop tests). |
| destroy twice | 2nd run: metadata gone → `store.remove()` + `changed=False` (idempotent cleanup including lock artifacts) (`lifecycle.py:376-378`); regression `tests/test_lifecycle.py:246-247`. | Preserved; additionally unchanged when both metadata and backend object are absent. |
| destroy with stop timeout | Poll loop expires and **delete proceeds anyway** (`lifecycle.py:385-391`); worse, `"stopping"` maps to STOPPED (`utm.py:114`) so the loop exits immediately while UTM is still stopping. | Stop timeout must never continue to delete; STOPPING must be a distinct state; delete requires confirmed STOPPED (architecture §10 row 5-6). |
| destroy partial failure | `delete` failure raises before `store.remove()` (`lifecycle.py:391,396`) → metadata retained for retry — already safe. Post-delete absence is not confirmed; a silent delete failureMode misreported as success is possible if backend returns 0 without deleting. | Confirm exact identity absent after delete; only then remove metadata (§10 rows 8-9). Retry must target the same persisted identity. |
| destroy with stale metadata (backend object gone) | UTM: `vm_exists` False → skips delete → `store.remove()` → `changed=True` (`lifecycle.py:380-396`). Actually cleans stale metadata idempotently; but no distinction between "absent" and "conflicting same-name foreign object." | Keep idempotent cleanup when no conflicting name exists; report conflict and preserve metadata when the name belongs to another UUID (§10 "Stale and conflict handling"). |
| status against stale/unknown backend state | UTM unknown states → `VMState.UNKNOWN` (`utm.py:107,115`); persisted verbatim by status. Architecture requires fail-closed UNKNOWN handling without inferring power state — currently compliant at the backend layer, but `destroy` treats UNKNOWN as "not running/starting" and proceeds to delete; up treats UNKNOWN as "not RUNNING" so it issues a start. | Fail closed: never start/stop/delete on UNKNOWN; reconcile explicitly (§5 row "Backend reports an unknown state"). |

Interrupt recovery today: a start issued but the CLI killed mid-poll leaves metadata at
STARTING/WAITING (persisted at `lifecycle.py:239-247`); next up sees state from backend and
recovers; but a persisted STARTING with the VM actually STOPPED forces a new start — fine
and idempotent. Architecture §11 requires this reconciliation to remain deterministic, now
keyed on backend-native identity.

---

## I. Test map

Baseline executed during reconnaissance: `pytest` → 317 passed, 3 deselected (default `-m
'not runtime'`, `pyproject.toml:49`). All existing tests are offline/mocked unless marked
`runtime`/`cve_runtime`. **Mocked AMD64/Vagrant coverage is not runtime verification** —
and per architecture §13/§17, Windows AMD64/Vagrant denial must be verified offline only,
never reported as runtime-verified. The current Windows "real" evidence is the gated smoke
`tests/test_management_smoke.py:37-91` (requires `RANGEFORGE_RUN_WINDOWS_MANAGEMENT=1` and a
pointer to an owned clone).

### Existing tests to reuse (parameterize or rely on as Linux regression)

| Test file/symbol | Current behavior asserted | Phase 5.4 reuse |
|---|---|---|
| `tests/test_lifecycle.py::test_scenario_vm_naming_and_identity_are_deterministic` (line 174) | `rf-<id>` naming, deterministic managed ID | Reuse unchanged; add fingerprint determinism assertion (§15). |
| `tests/test_lifecycle.py::test_runtime_metadata_serialization` (line 180) | build → YAML round-trip | Extend to new schema (UUID/product/version/fingerprint round-trip; §15 metadata tests). |
| `tests/test_lifecycle.py::test_build_requires_ready_template` (line 197) | non-deployable plan rejected | Reuse unchanged. |
| `tests/test_lifecycle.py::test_clean_utm_build_up_status_destroy_lifecycle` (line 211) | full Linux UTM happy path, no re-clone, destroy preserves source+template, repeated destroy unchanged | **Primary Linux UTM regression** for UUID-aware identity (§16 regression tests); extend to assert build-up-stop-status-destroy-stop sequences exist with same semantics. |
| `tests/test_lifecycle.py::test_architecture_mismatch_is_rejected_before_clone` (line 250) | template.arch vs host.arch denial pre-clone | Reuse unchanged; sibling tests for the new plan-consistency gate (§15). |
| `tests/test_lifecycle.py::test_status_model_parsing_round_trip` (line 287) | UNKNOWN state persistence | Extend for STOPPING/MISSING round-trip. |
| `tests/test_lifecycle.py::test_destroy_rejects_tampered_ownership_metadata` (line 310) | tampered managed_id blocks destroy; VM survives | Parameterize with tampered UUID/fingerprint cases (§15). |
| `tests/test_lifecycle.py::test_manual_vagrant_template_reference_builds_scenario_environment` (line 338) | Linux Vagrant build path | **Primary Linux Vagrant regression** for environment hardening (§16). |
| `tests/test_lifecycle.py::test_windows_vagrant_build_rejected_before_backend_calls` (line 418) | Windows+Vagrant denied pre-mutation, zero backend calls | Reuse unchanged; keep as the Windows-AMD64 denial evidence (offline only). |
| `tests/test_management_readiness.py` (14 tests, lines 224-711) | Windows readiness semantics (probe-gated READY, no IP-only READY, re-probe, downgrade, legacy metadata denial, transport errors → UNAVAILABLE) | Reuse with updates where §8/§9 semantics change (up failure exit surface; status reprobing every running Windows VM). Fakes `LifecycleUTM`/`_patch_probe` pattern should be extended with UUID-aware inventory. |
| `tests/test_management_transport.py` classes `TestOwnershipGate` (line 1632), `TestPolicyHelpers` (2011), `TestReadinessProbe` (2034), `TestProbeBudget` (2137), `TestAbsoluteDeadlineUnderLockContention` (2242), plus ownership fakes `RecordingUTM`/`RecordingVagrant`/`StubTemplates` (504-560) | transport/ownership gating, deadlines, probe internals | Reuse; extend deadline tests for the new explicit remaining-budget parameter. |
| `tests/test_guest_platform.py::TestCheckGuestCompatibilityWindows` (line 272) and `TestCheckGuestCompatibilityBackendPolicy` (210) | Windows capability + Windows-Vagrant denial | Reuse unchanged; §15 planner regressions add UTM selection and determinism checks. |
| `tests/test_runtime_planner.py` Windows tests (lines 227-666) incl. `test_runtime_plan_windows_arm64_on_macos_utm_is_compatible_not_deployable` (480), `test_runtime_plan_windows_amd64_on_vagrant_host_with_shipped_identity` (537), `test_same_windows_scenario_produces_same_runtime_plan` (626) | determinism, compatibility vs deployability, denial | Reuse unchanged; assert lifecycle extensions do not alter planner outcomes (§15). |
| `tests/test_templates.py` (lines 62-231) | fingerprint determinism, readiness/stale logic, Windows template identity (`test_windows_template_identity_follows_image_id`, line 101), checksum-pending Windows denial (106), manual Vagrant template rules (187, 231) | Reuse unchanged; add "READY record whose backend object is missing fails before clone" at the lifecycle level (the `prepare()`-side analog already exists at lines referenced). |
| `tests/test_runtime_integration.py::test_real_utm_phase3_rebuild` (line 18) and `test_real_utm_phase4_cve_rebuild` (55) | gated real-runtime Linux flows | Remain gated Linux real-runtime evidence; unmodified. |
| `tests/test_management_smoke.py::test_real_windows_arm64_utm_qga_management_smoke` (line 37) | gated real Windows probe | Remains gated; §17 adds a broader gated lifecycle acceptance sequence (new test, distinguished from this one). |

### Tests to extend

- `tests/test_lifecycle.py` — extend `_environment`/`FakeUTM` to be UUID-aware; extend the
  full-lifecycle test with stop and repeated stop (parameterize Linux/Windows where the
  asserted behavior is platform-neutral: build idempotence, ownership rejection, stale
  metadata, destroy preservation). Parameterization approach: shared fixtures producing
  Linux and Windows lifecycle environments (the `tests/test_management_readiness.py`
  fixtures already demonstrate the Windows-side environment); assert identical
  platform-neutral invariants rather than duplicating test logic.
- `tests/test_management_readiness.py` — update expectations for §8 failure semantics (up
  returns failure when management stays unavailable) and §9 status reprobe rules (reprobe
  every running Windows VM regardless of persisted state); add single-deadline assertions.
- `tests/test_management_transport.py::TestProbeBudget` — extend for
  `probe_windows_management(..., timeout=remaining)` parameter.
- `tests/test_cli.py` — add `stop --help`, status output fields, up nonzero-exit on
  management failure, and Windows-input command-scope acceptance/denial matrix (§15).
- `tests/test_validation.py` — scope tests: structural lifecycle validation accepts Windows
  runtime-relevant structure while `ScenarioValidator` still denies curriculum eligibility.

### New tests

Per architecture §§15-16 (condensed to repository-concrete targets):

1. **Lifecycle consistency** (`tests/test_lifecycle.py`): plan/scenario mismatch pre-clone;
   host mismatch pre-mutation; architecture/platform/backend/plan-image-vs-template-image
   mismatches pre-clone; READY-record-with-missing-backend-object pre-clone; `rf-5004`
   naming; fingerprint determinism; complete metadata+identity → unchanged build; missing
   backend identity → no replacement (stale); same-name w/o metadata → never adopted;
   same-name other UUID → never adopted.
2. **Metadata schema** (`tests/test_lifecycle.py` or a metadata-focused module): schema-4
   YAML round-trip incl. Windows product/version, UTM UUID, Vagrant env fingerprint/provider
   ID; legacy (v2/v3) metadata valid for Linux behavior but never upgraded into Windows
   ownership; missing backend identity rejects Windows mutation; tamper matrix (UUID,
   fingerprint, scenario id, profile, name, backend, platform, architecture, template
   identity); symlinked runtime/Vagrant paths rejected pre-mutation.
3. **Mocked-backend Windows lifecycle** (extend `tests/test_management_readiness.py` with a
   UUID-faithful fake inventory): build creates exactly one stopped clone and never starts
   it; persisted metadata carries UUID/platform/product/arch/template/fingerprint; repeated
   build no-op; orphan-conflict when clone identity cannot be established; source/template
   untouched. Up: start→STARTING→RUNNING→probe sequence, probe targets only validated
   identity, READY recording, already-running revalidation without duplicate start,
   UNAVAILABLE→READY recovery without start, management timeout → RUNNING/UNAVAILABLE +
   failure, start timeout → no probe + retained clone, single shared deadline. Status:
   stopped → STOPPED/NOT_READY no probe; running+persisted-NOT_READY probes and can
   recover; running+persisted-READY probes and can downgrade; missing UUID → MISSING;
   foreign same-name UUID → conflict; status never starts/stops. Stop: one stop + wait;
   preserves clone; management NOT_READY; repeated stop no backend call; timeout retains
   metadata+clone; up-after-stop performs full probe. Destroy: running→stop→confirmed
   STOPPED→delete exact UUID→confirm absent→metadata removed; repeated destroy unchanged;
   missing owned resource + no conflicting name → clears stale metadata; foreign same-name
   never stopped/deleted; delete failure retains metadata; retry targets same UUID;
   preservation of source artifact, source metadata, template metadata, template inventory
   entry, unrelated VMs, shared caches.
4. **Planner regressions** (`tests/test_runtime_planner.py`, `tests/test_guest_platform.py`):
   Windows ARM64 macOS → UTM deterministically; cross-arch denied; Windows-Vagrant denied;
   plan determinism incl. serialization; lifecycle extensions don't change planner outcomes.
5. **CLI** (`tests/test_cli.py`): `stop --help`; status renders guest OS, architecture,
   backend, VM state, management state, ownership, address; up exits nonzero on management
   unavailability; standalone Windows input accepted only by runtime plan/build/up/status/
   stop/destroy; still rejected by provision/validate/generate.
6. **Gated real-runtime acceptance** (new, `@pytest.mark.runtime` + environment gates, in
   the style of `tests/test_management_smoke.py`): the §17 command sequence with
   preservation assertions (source checksum/metadata, template UUID/state/fingerprint,
   unrelated VM inventory, shared cache state). Explicitly excluded from default CI.
7. **Windows AMD64 denial**: offline-only tests proving deterministic denial with zero fake
   backend mutation, and an explicit verification statement that mocked coverage is not
   runtime verification (architecture §13, §17 "AMD64/Vagrant verification statement").

---

## J. Risks ranked

### HIGH

1. **Foreign same-name VM can be mutated/destroyed.** Evidence: UTM inventory parsing drops
   UUIDs (`utm.py:87-89`); all mutations name-keyed (`lifecycle.py:152-156, 250, 384-391`);
   ownership checks are metadata-only (`metadata.py:87-99`). Affected paths: build
   (false "unchanged"), up, destroy (deletes foreign VM). Mitigation: C.1-C.3 (persisted
   UUID, typed inventory, agreement gate before every mutation), ownership fingerprint
   (C.2), conflict semantics per §5/§10; tests in I (new 1, 3).
2. **Destroy proceeds without proven stop.** Evidence: poll-then-delete with no
   post-condition check (`lifecycle.py:385-391`); `"stopping"` mapped to STOPPED
   (`utm.py:114`), so a still-stopping VM is treated as stopped and deleted — UTM may then
   fail or corrupt state, and metadata is already removed by `lifecycle.py:396`. Affected
   path: destroy (and future stop). Mitigation: `VMState.STOPPING`, bounded generic
   `stop()` requiring confirmed STOPPED before delete (C.1, C.3, C.5); delete/absence
   confirmation; regression tests (I new 3 "Destroy").
3. **Validation and planner profile coupling currently denial-block the mandated Windows
    lifecycle path, and a mis-scoped fix could leak into curriculum policy.**
    Evidence: `cli.py:122-125,173-176` run full `ScenarioValidator`; `oscp.yaml:3-4` denies
    Windows; `validation/scenario.py:24-27` produces violations. Even after bypassing that
    check, `RuntimePlanner.plan()` returns incomplete because `oscp.yaml:39-44` has no Windows
    runtime requirement (`planner.py:84-92`). Build/up also compile runtime primitives before
    lifecycle dispatch (`cli.py:784-788`). A poorly scoped fix could accidentally enable
    Windows provisioning/validity — violating AGENTS.md default-deny constraints. Mitigation:
    command-scope selection of the narrower structural validator plus lifecycle-only planner
    requirement view and primitive-compile bypass (C.7, C.8); tests proving provision/
    validate/generate still reject Windows input (I new 5); no persisted runtime-only flag
    and no changes to `allowed_platforms` or allowed techniques.
4. **Management-channel wedge windows vs bounded budget.** Evidence: Phase 5.3 documents a
   cold-boot exec wedge and asynchronous exec semantics (`management.py:478-516`); the
   lifecycle currently sleeps a fixed 10 s (`lifecycle.py:49,227,283`) and lets the probe
   use its own 300 s budget (`management.py:1520`) unbounded by the caller. Without a single
   operation deadline (C.5/C.6), up can exceed its advertised timeout and confuse failure
   classification. Mitigation: one deadline threaded from CLI → lifecycle → probe; tests
   `TestProbeBudget` extension and up deadline tests (I new 3 "Up").

### MEDIUM

5. **Up currently returns success with management UNAVAILABLE**, and CLI exits 0
   (`lifecycle.py:304-315`; `cli.py:793-813`). §8 requires nonzero failure. Risk: silent
   operator misread during Windows bring-up; test churn (existing tests assert the current
   success-returning behavior, e.g. `tests/test_management_readiness.py:271-286`) —
   mitigation is to update those tests deliberately with the semantics change and add CLI
   exit tests.
6. **Status cannot recover a running Windows VM stuck at NOT_READY/UNAVAILABLE** — persisted
   non-ready states are never re-probed (`lifecycle.py:346-351`); only up recovers today.
   §9 requires reprobe on every running Windows VM. Mitigation: C.5 status reconciliation;
   regression risk is low-blast-radius (metadata-only) but changes current persisted-state
   preservation.
7. **READY template metadata without backend object passes `require_ready`**
   (`templates.py:125-145`); failure then surfaces at clone time (mutation boundary) instead
   of pre-clone. Mitigation: build-time `template_exists` check (C.9).
8. **Vagrant identity weakening under symlinks / stale environments**: `prepare_environment`
   follows symlinked parents (`vagrant.py:84`), `environment_exists` is Vagrantfile-presence
   only (`vagrant.py:101-102`). Linux-scoped but must not regress. Mitigation: C.4/C.2
   canonical-path + symlink rejection before mutation; regression via
   `test_manual_vagrant_template_reference_builds_scenario_environment` and new tamper
   tests.
9. **Build-orphan window**: clone succeeds but metadata save fails (`lifecycle.py:156,193`)
   → subsequent builds/refusals are name-only and undifferentiated. Mitigation: atomic
   identity persistence after clone and explicit orphan-conflict classification (§7);
   test I new 3 "Build".

### LOW

10. **Legacy (v1/v2) metadata semantics shift** when schema bumps to 4: the established
    fail-closed pattern (`lifecycle.py:70-88`, `management.py:113-120`, regression tests at
    `tests/test_management_readiness.py:551-627`) already handles this; risk is confined to
    adding "legacy cannot be silently treated as Windows" assertions (I new 2).
11. **Fake backend drift in tests**: `FakeUTM`/`LifecycleUTM` (`tests/test_lifecycle.py:51`,
    `tests/test_management_readiness.py:65`) must be extended UUID-faithfully; drift would
    silently weaken assertions. Mitigation: §16 mandates a filesystem-faithful fake UTM
    inventory.
12. **Documentation drift**: README status matrix (README lines 22-26, 286-289) describes
    the 4-command lifecycle and Windows support caveats; adding stop and failure-exit
    semantics requires doc alignment — but per this task's constraints and architecture
    §20 item 17, docs updates follow implementation; low risk, tracked.

---

## K. Recommended implementation sequence

Grounded in current dependency order (models → metadata → backends → lifecycle gates →
management deadline → CLI → tests), aligned with architecture §20 (not a redesign):

1. **Lifecycle-scoped validation and planning boundary + acceptance-test skeleton.** Add the
   structural validation helper (C.8), lifecycle-only planner requirement view (C.7), and
   scoped primitive-compile bypass; write the failing acceptance tests for the §5 state
   machine that do not depend on backend identity (e.g. stop command presence, up failure
   exit). Do not touch `ScenarioValidator`, `allowed_platforms`, or technique-policy
   semantics.
2. **Runtime models** (C.1): `VMState.STOPPING`/`MISSING`, `VMIdentity.resource_id`,
   `RuntimeGuestState.product/version`, bounded failure fields, `metadata_version` bump, and
   migration semantics for legacy metadata (fail closed for Windows, unchanged for Linux).
3. **Metadata hardening** (C.2): ownership fingerprint helper, UUID-aware and
   fingerprint-aware `validate_ownership`, canonical-path/symlink pre-mutation checks.
4. **UTM backend identity** (C.3): typed inventory records (uuid/name/state), UUID+name
   lookups, `stopping`→`STOPPING`, identity-validated targeting for start/stop/delete/
   state/address.
5. **Vagrant backend hardening** (C.4): canonical env fingerprint, symlink rejection,
   provider machine-ID persistence (post-up only); preserve Linux behavior and extend
   `tests/test_lifecycle.py::test_manual_vagrant_template_reference_builds_scenario_environment`.
6. **Shared pre-mutation consistency + ownership gate in `ScenarioLifecycle`** (C.5, first
   slice): plan↔scenario↔host↔backend↔image↔template consistency checks (architecture §7
   preconditions 1-8), including the build-time backend template existence check (C.9).
7. **Generic `stop()` + CLI `stop`** (C.5 slice 2, C.7 slice 1): bounded stop with
   convergence proof; reuse in destroy.
8. **Destroy refactor** (C.5 slice 3): require confirmed STOPPED, delete by validated
   identity, confirm exact absence, only then remove metadata; stale/conflict handling per
   §10, preserving the scenario-local lock-artifact cleanup currently in
   `RuntimeMetadataStore.remove()` (`metadata.py:69-85`) unchanged (architecture §10 final
   paragraph).
9. **Management probe deadline parameter** (C.6) in `management.py`, defaults preserved.
10. **Up refactor** (C.5 slice 4): single operation deadline, remaining-budget probe,
    explicit failure + nonzero CLI exit on management unavailability (C.7 slice 2).
11. **Status refactor** (C.5 slice 5): reconcile all states (STOPPED/STOPPING/MISSING/
    UNKNOWN), re-probe every running Windows VM, truthful `changed` reporting; extended CLI
    status rendering incl. guest OS and ownership (C.7 slice 3).
12. **Full offline test matrix** (I): unit, metadata, mocked UTM/Vagrant lifecycle,
    planner/CLI regressions; run `pytest`, `ruff check .`, `mypy rangeforge`,
    `git diff --check` per AGENTS.md.
13. **Independent ownership/destructive-operation review** of the ownership gate and
    destroy path.
14. **Gated Apple Silicon UTM real-runtime acceptance** (I new 6) on an owned Windows 11
    ARM64 clone, with preservation evidence; explicitly record that Windows AMD64/Vagrant
    remains planning-denied and that mocked coverage is not runtime verification.
15. **Docs/roadmap reconciliation** only after the above, per architecture §20 item 17.

---

### Repository discrepancy notes (architecture wording vs current interfaces)

- Architecture §1 says "`rangeforge/runtime/lifecycle.py` contains one generic
  `ScenarioLifecycle` implementing `build`, `up`, `status`, and `destroy`" — accurate; but
  its §4/§8 "stop" presumes a `stop()` that does not exist yet (confirmed by absence in
  `lifecycle.py` and `cli.py`). This map treats stop as a required new method/command, not
  an existing one.
- Architecture §5 state table lists `NOT_BUILT` as a metadata/backend condition — it exists
  as `VMState.NOT_BUILT` (`models.py:74`) but is today produced only by backends (missing VM)
  rather than persisted as lifecycle state; the "NOT_BUILT" metadata row describes a no-
  metadata situation. No interface conflict, but implementations should use `MISSING` for
  "metadata exists, backend identity absent" and keep `NOT_BUILT` for "no metadata and no
  backend object" to avoid ambiguity.
- Architecture §2 says "CLI runtime planning, build, and up create a runtime plan before
  lifecycle mutation. Status and destroy operate from persisted runtime identity without
  requiring a new plan." — confirmed exact (`cli.py:783-792`); the new `stop` command must
  follow status/destroy in using the plan-less context.
- Architecture §2 requires lifecycle-specific structural validation but does not state how
  the unchanged planner obtains a Windows `GuestRequirement`. The current planner cannot
  proceed without `profile.runtime_defaults["windows"]` (`planner.py:84-92`), while the stock
  profile intentionally contains only Linux (`oscp.yaml:39-44`). Implementation therefore
  needs the lifecycle-only planner requirement view identified in C.7/D, without changing
  curriculum eligibility; bypassing `ScenarioValidator` alone cannot make the CLI path work.
- Architecture §7 example "simple scenario ID `5004` becomes `rf-5004`" — consistent with
  `scenario_vm_name` (`metadata.py:20-29`) and `tests/test_lifecycle.py:174-177`.
- Architecture §12 default template identity `rf-base-windows-11-arm64` — matches
  `template_id()` derivation (`templates.py:37-38`) and `tests/test_templates.py:101-104`;
  the architecture's caution against inventing `rf-base-windows11-24h2-arm64` identities is
  justified by the actual naming convention.
- Windows AMD64/Vagrant is currently rejected in **three** layers: planning
  (`guest.py:227-231`), lifecycle build (`lifecycle.py:118-124`), and management-transport
  construction (`management.py:214-218`); the shipped `windows-11-amd64` manifest is
  additionally checksum-pending (`images/definitions/windows.yaml:44-46`), so its source can
  never become READY (`manager.py:81-87` UNVERIFIABLE →
  `ArtifactState.DOWNLOADED`), and template state is forced STALE for checksum-pending
  images (`cache.py:78-82`). All planning-time denial coverage is offline/mocked only; it is
  not runtime verification.
