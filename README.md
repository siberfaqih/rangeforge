# RangeForge

RangeForge is a curriculum-aware, attack-graph-driven procedural cyber-range scenario
generator for controlled and authorized offensive-security training. It turns a training
profile and data-defined attack primitives into a reproducible, statically validated
scenario definition.

## Current status

Phase 2A adds a read-only host/runtime planner and trusted local image-management
foundation to the Phase 1 deterministic engine. It **does not provision vulnerable
machines**, install operating systems or services, run exploits, start containers, or
contact remote systems.

Supported inputs are:

- profile: `oscp`
- mode: `standalone`
- platform: `linux`
- difficulty: `easy`, `medium`, or `hard`
- deployment: dry-run only

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
Non-destructive Runtime Plan
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
  --seed 1337 \
  --dry-run
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

The backend implementations in Phase 2A only detect dependencies and perform safe,
read-only inspection. UTM discovers `utmctl` through `PATH` and the UTM application
bundle. Vagrant can inspect its version and existing box list. Docker can inspect daemon
version and architecture. VM/container lifecycle operations are not implemented.

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

Available image commands are:

```bash
rangeforge images list
rangeforge images info ubuntu-24.04-arm64
rangeforge images import ~/Downloads/image.iso --image ubuntu-24.04-arm64
rangeforge images verify ubuntu-24.04-arm64
rangeforge images prepare ubuntu-24.04-arm64
```

Local imports are checked against registry SHA-256 metadata when configured. A mismatch
fails before the artifact is cached. Manifests whose placeholder checksum is not yet
configured can only reach `DOWNLOADED`, never `READY`. Remote pulling and base-template
creation are intentionally not implemented in Phase 2A.

Run the quality checks with:

```bash
pytest
ruff check .
mypy rangeforge
```

## Current limitations and roadmap

Phase 2A does not download images, create UTM templates, add Vagrant boxes, create VMs or
containers, provision vulnerabilities, or run guest commands. Later phases may add
explicit isolated Linux provisioning and runtime validation. Windows guests, Active
Directory, cloud ranges, arbitrary targets, and AI-driven validity decisions remain out
of scope.

## Security and authorization

RangeForge is intended only for systems you own or have explicit permission to test,
inside controlled and isolated training environments. Phase 2A creates inert scenario
metadata and read-only plans only. It has no arbitrary-target discovery, internet scanning, remote
exploitation, credential attacks, payload delivery, malware, persistence, or evasion
capability.
