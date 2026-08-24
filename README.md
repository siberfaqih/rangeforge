# RangeForge

RangeForge is a curriculum-aware, attack-graph-driven procedural cyber-range scenario
generator for controlled and authorized offensive-security training. It turns a training
profile and data-defined attack primitives into a reproducible, statically validated
scenario definition.

## Current status

Phase 4 adds a versioned, default-deny CVE registry and a trusted artifact lifecycle on top
of Phase 3's scenario-scoped runtime primitive engine. The first curated definition models
Apache ActiveMQ Classic 5.18.2 affected by CVE-2023-46604 on ARM64/UTM and AMD64/Vagrant.
Selection, provisioning, and validation remain limited to owned local lab clones.

Phase 4 is runtime-validated on Apple Silicon with a clean Ubuntu 24.04.4 ARM64 UTM
template. A real owned scenario clone installed the checksum-pinned service as a non-root
account, passed every primitive, flag, and negative validator, and passed a complete
destroy/rebuild cycle with identical scenario, lockfile, provisioning-plan, and validation
fingerprints. AMD64/Vagrant remains covered by schema and offline fixtures but has not been
executed on a real x86 host.

Supported inputs are:

- profile: `oscp`
- mode: `standalone`
- platform: `linux`
- difficulty: `easy`, `medium`, or `hard`
- deployment: local VM provisioning for the first runtime-capable chain

The OSCP-style profile is a configurable training profile, not an authoritative
representation of any certification vendor's exam.

## Architecture

```text
Training Profile
      ↓
Primitive Registry (default deny)
      ↓
NetworkX Attack Graph
      ↓
Seeded Scenario Generator
      ↓
Static Scenario Validator
      ↓
scenario.yaml
```

Runtime planning is a separate pipeline:

```text
Host Detection
      ↓
Runtime Resolution
      ↓
Backend Resolution
      ↓
Profile Guest Requirement
      ↓
Trusted Image Registry
      ↓
Image Cache / Template Readiness
      ↓
Runtime Plan
      ↓
Prepared Base Template
      ↓
Scenario VM Clone / Lifecycle
```

Phase 3 provisioning is a third, explicit pipeline:

```text
Validated Attack Graph
      ↓
Runtime Primitive Resolver
      ↓
Scenario-ordered Provisioning Plan
      ↓
Owned Scenario VM (never the base template)
      ↓
Primitive Provisioners
      ↓
Primitive Validators + Negative Checks
      ↓
VALID or INVALID
```

Phase 4 CVE resolution is data-driven and happens before deployment:

```text
Curated CVE Registry
      ↓
Profile + Platform + Runtime + Backend + Architecture Filtering
      ↓
Seeded Primitive Selection
      ↓
Version-pinned Artifact Registry
      ↓
Checksum-verified Shared Cache
      ↓
Scenario Runtime Lock
      ↓
Owned Clone Provisioning + Layered Runtime Validation
```

Profiles own curriculum rules. Primitive YAML files own state transitions. The graph
engine only connects declared `requires` and `provides` states, so it remains independent
of any certification. The validator separately checks policy, state continuity, graph
length, and objective reachability.

All random choices use one `random.Random` instance owned by `ScenarioRandomizer`.
For a fixed generator version, the same inputs and seed reproduce the same logical YAML.

### Difficulty

Each primitive declares enumeration, exploitation, and dependency complexity from 1 to 3.
RangeForge averages those dimensions for each primitive and then averages the complete
path. Scores `<= 1.50` are easy, `<= 2.35` are medium, and higher scores are hard. The
generator selects only paths whose calculated difficulty matches the requested level.

## Install and run

Python 3.11 or newer is required.

```bash
python -m pip install -e '.[dev]'

rangeforge generate \
  --profile oscp \
  --mode standalone \
  --platform linux \
  --difficulty medium \
  --seed 1337
```

The command writes `output/scenario-1337/scenario.yaml` and prints its validation result.
An example attack graph is:

```text
NO_ACCESS
  ↓ service_enumeration
SERVICE_DISCOVERED
  ↓ web_command_injection
LOW_PRIV_SHELL
  ↓ credential_discovery_config
USER_SHELL
  ↓ linux_suid_misconfiguration
ROOT
```

## Runtime architecture

Docker and VM are first-class runtime types. Docker always uses Docker directly. VM
backend selection is automatic and follows this initial host policy:

| Host | VM backend |
|---|---|
| macOS ARM64 / Apple Silicon | UTM, directly |
| macOS AMD64 | Vagrant |
| Linux AMD64 | Vagrant |
| Windows AMD64 | Vagrant |
| Other combinations | Explicitly unsupported |

RangeForge does not route UTM through Vagrant and does not silently emulate AMD64 guests
on ARM. Docker compatibility is evaluated separately from the VM matrix.

The first vulnerable primitive chain is VM-backed. Docker remains part of the generic
runtime architecture but is not accepted by these Phase 3 implementations.

UTM discovers `utmctl` through `PATH` and the UTM application bundle and supports direct
clone, start, stop, status, IP discovery, and delete commands. Vagrant supports trusted
box inspection and scenario-scoped environment lifecycle commands. Docker remains a
separate runtime and is not part of the Phase 2B VM lifecycle.

### Host diagnostics

```bash
rangeforge doctor
```

This reports normalized OS/architecture, Apple Silicon status, detected executables,
the selected VM backend, and image-cache status. It does not create the cache or modify
host configuration.

### Runtime plans

```bash
rangeforge runtime plan output/scenario-1337/scenario.yaml
rangeforge runtime plan output/scenario-1337/scenario.yaml --runtime docker
```

A plan combines the scenario's primitive compatibility, the profile's data-defined guest
requirement, host policy, backend readiness, image resolution, and cache state. Planning
is deterministic for the same scenario, host model, registry, and cache state. It never
deploys anything.

## Images and cache

Trusted manifests under `rangeforge/images/definitions/` define guest OS, architecture,
runtime/backend compatibility, vendor source metadata, artifact name, and SHA-256
metadata. Python code never invents or searches for image URLs.

The default cache root is `~/.rangeforge/images` and is configurable through
`~/.config/rangeforge/config.yaml`:

```yaml
runtime:
  default: auto
images:
  cache_dir: ~/.rangeforge/images
artifacts:
  cache_dir: ~/.rangeforge/artifacts
utm:
  executable: null
vagrant:
  executable: null
docker:
  executable: null
```

The cache separates `downloads/`, backend-specific `templates/`, and `metadata/`.
A verified ISO or source artifact being ready does not mean a reusable UTM template is
ready. Vagrant integrations may later delegate box storage to Vagrant rather than copy
boxes into RangeForge's cache.

The registry pins Canonical's 2026-08-01 Ubuntu 24.04 cloud-image release and SHA-256
for both ARM64 and AMD64. Pulls stream only the configured HTTPS URL into a `.partial`
file, verify it, and atomically rename it. Existing valid files are reused; existing
invalid files require explicit `--replace-invalid`.

Available image commands are:

```bash
rangeforge images list
rangeforge images info ubuntu-24.04-arm64
rangeforge images pull ubuntu-24.04-arm64
rangeforge images import ~/Downloads/image.img --image ubuntu-24.04-arm64
rangeforge images verify ubuntu-24.04-arm64
rangeforge images prepare ubuntu-24.04-arm64
```

Local imports use the same mandatory checksum. A mismatch fails before the artifact is
cached. Source status and template status remain independent.

### Base templates

RangeForge tracks deterministic template metadata containing the image ID, source
checksum, backend, architecture, schema version, creator version, and fingerprint.
Templates use stable names such as `rf-base-ubuntu-24.04-arm64`; scenarios use identities
such as `rf-1337`.

UTM's CLI can clone and control a prepared VM but cannot safely configure a management-
ready Ubuntu cloud image from scratch. Therefore `images prepare` registers an existing,
clean UTM base VM with the stable name (or `--template-name`) after verifying the source.
It never claims an OS installation succeeded. The base must contain QEMU Guest Agent
support for `utmctl ip-address` and Phase 3 guest command/file transport.

For Vagrant, the trusted manifest maps Ubuntu AMD64 to a configured box reference.
RangeForge records metadata while Vagrant retains ownership of its box cache.

### Scenario VM lifecycle

```bash
rangeforge runtime plan output/scenario-1337/scenario.yaml
rangeforge build output/scenario-1337/scenario.yaml
rangeforge up output/scenario-1337/scenario.yaml
rangeforge provision output/scenario-1337/scenario.yaml
rangeforge validate output/scenario-1337/scenario.yaml
rangeforge status output/scenario-1337/scenario.yaml
rangeforge destroy output/scenario-1337/scenario.yaml
```

`build` validates the scenario and plan, then clones the shared UTM template or creates a
scenario-specific Vagrant environment. It does not start the VM. `up` starts it, waits
for the backend's running state, and asks the backend management integration for an IP.
UTM uses QEMU Guest Agent-backed `utmctl ip-address`; Vagrant uses `ssh-config`. No address
is guessed from host network tables.

A prepared Linux template may use a dedicated `rangeforge` management account and SSH,
but those credentials are infrastructure-only metadata and must never be exposed as a
student account or incorporated into the generated attack graph.

Runtime ownership is recorded at `runtime/runtime.yaml` beside `scenario.yaml`. Destroy
validates the deterministic VM name and ownership token before deletion, removes only
scenario runtime state, and preserves `scenario.yaml`, downloads, and shared templates.
Repeated build/up/destroy operations return stable already-present/already-absent results.

Once a verified source and registered template are present, the complete build, up,
provision, validate, status, and destroy workflow needs no internet connectivity.

## Curated CVE registry and artifacts

RangeForge never searches the internet for vulnerabilities or exploit code. Every supported
CVE is a local definition bundle under `rangeforge/cve/definitions/` containing typed
metadata, a logical primitive, instructor knowledge, a provisioner, a validator, and declared
artifact requirements. `registry.yaml` versions the curated set. Loading is default-deny:
unknown CVEs, profile-disallowed techniques, missing scripts, unknown artifacts, architecture
mismatches, and inconsistent graph transitions are rejected.

Compatibility is evaluated before seeded selection. A CVE must match the selected training
profile, platform, runtime, backend, guest architecture, and base guest family/distribution/
version. CVSS is not used as training difficulty; the primitive's deterministic enumeration,
exploitation, and dependency scores remain the curriculum input. The graph stores only the
declared state transition, never payloads or exploit instructions.

The artifact registry pins the exact upstream URL, filename, product/JRE version, SHA-256,
architecture, license, and redistribution policy. Downloads are allowed only from those HTTPS
URLs, stream to a `.partial` file, and become ready only after checksum verification and an
atomic rename. Valid cached files are reused; invalid cached files require the explicit
`--replace-invalid` option. Shared artifacts survive scenario destruction. Once all required
artifacts and the base template are ready, provisioning and validation are offline.

Available administrative commands are:

```bash
rangeforge cve list
rangeforge cve info CVE-2023-46604
rangeforge cve validate-registry

rangeforge artifacts list
rangeforge artifacts info apache-activemq-5.18.2
rangeforge artifacts pull apache-activemq-5.18.2
rangeforge artifacts verify apache-activemq-5.18.2
```

The only current CVE definition is Apache ActiveMQ Classic 5.18.2 / CVE-2023-46604.
It uses the official Apache archive and a pinned Eclipse Temurin JRE 17.0.19+10 selected for
ARM64 or AMD64. The service is configured only inside an owned scenario clone, runs as the
deterministic unprivileged scenario service account, and exposes OpenWire on port 61616.
RangeForge does not download or execute a public proof of concept.

Seed 85 selects the CVE-backed easy path deterministically for ARM64 VM generation:

```text
NO_ACCESS
  ↓ service_enumeration
SERVICE_DISCOVERED
  ↓ cve_2023_46604_activemq_rce
LOW_PRIV_SHELL
  ↓ credential_discovery_config
USER_SHELL
  ↓ linux_sudo_misconfiguration
ROOT
```

```bash
rangeforge generate --profile oscp --mode standalone --platform linux \
  --difficulty easy --seed 85 --runtime vm --architecture arm64
rangeforge runtime plan output/scenario-85/scenario.yaml
rangeforge build output/scenario-85/scenario.yaml
rangeforge up output/scenario-85/scenario.yaml
rangeforge provision output/scenario-85/scenario.yaml
rangeforge validate output/scenario-85/scenario.yaml
rangeforge status output/scenario-85/scenario.yaml
rangeforge destroy output/scenario-85/scenario.yaml
```

`runtime/lock.yaml` records the schema, seed, profile, runtime/backend, architecture, CVE
registry version, base-image fingerprint, ordered primitive versions, exact CVE/service
version, artifact IDs, filenames, versions, architectures, and checksums. It is deterministic
for fixed inputs. Student artifacts omit the CVE ID, product/version, primitive names,
credentials, flags, management data, and lock content; instructor runtime files remain mode
`0600`.

CVE validation is layered. It checks the installation layout, exact service version,
actual base guest release, configuration, service/listener state, affected-version
prerequisites, non-root identity, authentication expectation, and artifact lock before
accepting the logical transition. Provisioning also refuses a guest whose actual release does
not match the curated base constraint.
Starting a service alone is never sufficient for validity.

## Runtime primitives and vulnerable lab lifecycle

A logical primitive remains graph data: it declares required and provided access states.
A runtime primitive adds a separate manifest, generic knowledge, provisioner, and validator
under `rangeforge/runtime_primitives/definitions/`. Provisioners never select paths and the
graph never contains guest commands. `build` rejects a graph before cloning when a selected
primitive lacks an exact platform, architecture, runtime, and backend implementation; it
never substitutes another technique.

The first complete runtime chain is:

```text
NO_ACCESS
  ↓ service_enumeration
SERVICE_DISCOVERED
  ↓ simple_web_foothold
LOW_PRIV_SHELL
  ↓ credential_discovery_config
USER_SHELL
  ↓ linux_sudo_misconfiguration
ROOT
```

The foothold is a purpose-built RangeForge diagnostics application for authorized local
labs, not a public CVE or third-party vulnerable package. It runs as an unprivileged
service identity. The configuration primitive creates a deterministic local user and a
credential artifact readable only from the service context. The sudo primitive grants
that user one deliberately unsafe `/usr/bin/find` rule, never passwordless sudo-all.

Seed 81 currently selects this easy chain deterministically:

```bash
rangeforge generate --profile oscp --mode standalone --platform linux \
  --difficulty easy --seed 81
rangeforge build output/scenario-81/scenario.yaml
rangeforge up output/scenario-81/scenario.yaml
rangeforge provision output/scenario-81/scenario.yaml
rangeforge validate output/scenario-81/scenario.yaml
rangeforge status output/scenario-81/scenario.yaml
rangeforge destroy output/scenario-81/scenario.yaml
```

`provision` revalidates static policy, ensures the owned VM is running, persists the
scenario-ordered plan, applies idempotent primitive scripts, and runs runtime validation.
State is recorded as `NOT_PROVISIONED`, `PROVISIONING`, `COMPLETE`, or `FAILED`. A partial
failure records the active and completed primitives and cannot be reported as valid.

UTM guest commands use QEMU Guest Agent execution against the owned VM name. Vagrant uses
its scenario-specific SSH configuration. There is no command that accepts an arbitrary
provisioning IP. Runtime ownership, VM identity, architecture, running state, management
readiness, and template separation are checked before scripts execute.

### Deterministic identities and flags

Scenario usernames, credentials, service ports, `local.txt`, and `/root/proof.txt` use
domain-separated SHA-256 derivation over the seed, scenario/profile identity, generator
version, and Phase 3 schema. They are stable for the same inputs and normally change with
the seed. `local.txt` is readable from the service context; `proof.txt` is root-owned mode
`0600`. Values are stored in mode-`0600` instructor metadata and never printed in normal
student output.

### Runtime validation and audience separation

Each primitive checks deployed service state, identity, permissions, authentication, and
the intended transition through the trusted management channel. Global checks verify both
flags and reject obvious shortcuts: root service/user identities, world-readable proof,
solution leakage, passwordless sudo-all, and sudo access for unrelated users. Results are
persisted at `runtime/validation.json`; provisioning success by itself is not validity.

`student/README.md` and `student/targets.txt` contain only the current target IP and the
two objectives. `runtime/instructor.json` contains the deterministic lab configuration and
is not student-facing. Attack graphs, primitive names, credentials, weaknesses,
management secrets, and flag values are excluded from student artifacts.

Run the quality checks with:

```bash
pytest
ruff check .
mypy rangeforge
```

## Current limitations and roadmap

RangeForge does not automate interactive UTM guest installation or cloud-init seed creation;
the clean, management-ready UTM base must currently be prepared explicitly and then
registered. The current stable UTM template was verified as Ubuntu 24.04.4 and passed the
real ARM64 CVE lifecycle. AMD64/Vagrant has schema and offline fixture coverage only and has
not been executed on a real x86 host. UTM guest-agent file transfer is reliable but slow for
the two approximately 45 MB cached archives.

Phase 3 temporarily uses the backend-discovered VM network for the student target; a dedicated
student/attack network remains future work. Docker CVE deployment, Windows guests, Active
Directory, cloud ranges, arbitrary targets, dynamic CVE/PoC discovery, and AI-driven validity
decisions remain out of scope.

## Security and authorization

RangeForge is intended only for systems you own or have explicit permission to test,
inside controlled and isolated training environments. It intentionally creates a vulnerable
local scenario clone only after RangeForge ownership checks. Source images and shared base
templates remain clean. RangeForge has no arbitrary-target input or discovery, internet
scanning, remote-system provisioning, real credential attacks, malware, persistence, evasion,
or dynamic public-exploit downloading. CVE metadata, compatibility, and runtime validity come
from reviewed registry data and deterministic validators, never from AI output.
