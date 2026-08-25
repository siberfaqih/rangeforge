# RangeForge

RangeForge is a deterministic, curriculum-aware cyber-range generator for controlled and
authorized offensive-security training. It builds reproducible attack-graph scenarios from
training profiles and data-defined primitives, validates every selected path, and keeps
logical scenario generation separate from runtime deployment.

> RangeForge is intended only for isolated systems you own or are explicitly authorized to
> test. It does not scan networks, discover arbitrary targets, or provision remote systems.

## Current support

| Capability | Status |
|---|---|
| Deterministic standalone scenario generation | Supported |
| Production training platform | Linux |
| Production profile | `oscp` |
| Difficulty levels | `easy`, `medium`, `hard` |
| VM runtime on macOS ARM64 | UTM directly |
| VM runtime on supported AMD64 hosts | Vagrant |
| Ubuntu 24.04 ARM64 and AMD64 images | Supported |
| Windows 11 ARM64 image planning and readiness | Supported with manual media and UTM |
| Windows 11 AMD64 compatibility planning | Supported; media and local Vagrant base remain operator-supplied |
| Windows scenario generation and provisioning | Not enabled |
| Curated CVE runtime | CVE-2023-46604 on owned Linux scenario clones |
| Docker runtime model | Supported; current vulnerable primitives remain VM-only |

Windows is represented by the same generic guest, image, planner, template, and backend
models as Linux. There is no parallel Windows runtime architecture. Production profile
policy remains default-deny for Windows attack graphs, management transport, credentials,
and provisioning.

## Core guarantees

- One seeded randomizer owns every generation-time random decision.
- The same seed, profile, mode, platform, runtime, architecture, and generator version
  produce the same logical scenario.
- Training-profile policy is separate from generic graph traversal.
- Techniques are data-defined primitives with declared state transitions.
- Generated paths are statically validated before they are accepted.
- Runtime planning is deterministic and has no deployment side effects.
- Host and guest architectures are explicit; RangeForge never silently substitutes or
  emulates another architecture.
- Source artifacts, reusable base templates, and scenario VMs are separate resources.
- A source artifact cannot become `READY` without checksum verification.
- Vulnerability provisioning targets only RangeForge-owned scenario clones, never source
  images or shared base templates.
- Scenario destruction validates ownership and preserves shared images, templates, and CVE
  artifacts.
- AI is never a source of truth for scenario validity, curriculum eligibility, image
  compatibility, CVE metadata, or runtime validation.

## Architecture

### Scenario generation

```text
Training Profile
      |
Primitive Registry (default deny)
      |
NetworkX Attack Graph
      |
Seeded Scenario Generator
      |
Static Scenario Validator
      |
scenario.yaml
```

Profiles define curriculum rules. Primitive YAML files define `requires` and `provides`
states, categories, techniques, architecture support, runtime support, and difficulty
dimensions. The graph engine only connects declared transitions and remains independent of
certification-specific policy.

### Runtime planning

```text
Host Detection
      |
Runtime and Backend Resolution
      |
Profile Guest Requirement
      |
Guest Compatibility Policy
      |
Trusted Image Resolution
      |
Source and Template Inspection
      |
Runtime Plan
```

A runtime plan reports the selected backend, exact guest architecture, image identity,
acquisition method, source readiness, template readiness, compatibility, deployability,
issues, and the next required action. Planning never creates or changes a VM.

### Owned runtime lifecycle

```text
Verified Source Artifact
      |
Registered Clean Base Template
      |
Owned Scenario VM
      |
Scenario-ordered Runtime Primitives
      |
Positive and Negative Validators
      |
VALID or INVALID
```

Attack graphs contain logical transitions, not guest commands. Runtime primitive manifests
map selected techniques to provisioners and validators only after platform, architecture,
runtime, and backend compatibility has been established.

### Curated CVE resolution

```text
Curated CVE Registry
      |
Profile, Platform, Guest, Runtime, Backend, and Architecture Filtering
      |
Seeded Primitive Selection
      |
Version-pinned Artifact Registry
      |
Checksum-verified Shared Cache
      |
Scenario Runtime Lock
      |
Owned Clone Provisioning and Runtime Validation
```

RangeForge never selects arbitrary internet CVEs or downloads public exploit proofs of
concept. CVSS is metadata, not a training-difficulty input.

## Requirements

- Python 3.11 or newer
- UTM with `utmctl` for VM runtime on Apple Silicon
- Vagrant for VM runtime on supported AMD64 hosts
- Docker only when using compatible Docker-backed content

Runtime tools are optional for scenario generation. Generation remains available even when
no VM backend is installed.

## Installation

```bash
python -m pip install -e '.[dev]'
rangeforge doctor
```

`rangeforge doctor` normalizes the host OS and architecture, detects Docker, UTM, and
Vagrant, reports the selected VM backend, and inspects the image-cache path without creating
or modifying runtime resources.

## Quick start

Generate and statically validate a Linux scenario:

```bash
rangeforge generate \
  --profile oscp \
  --mode standalone \
  --platform linux \
  --difficulty medium \
  --seed 1337 \
  --runtime vm \
  --architecture arm64
```

The output is written to `output/scenario-1337/scenario.yaml`. Inspect its runtime plan
before making any lifecycle change:

```bash
rangeforge runtime plan output/scenario-1337/scenario.yaml
```

When the plan reports `Deployable: YES`, the owned lifecycle is:

```bash
rangeforge build output/scenario-1337/scenario.yaml
rangeforge up output/scenario-1337/scenario.yaml
rangeforge provision output/scenario-1337/scenario.yaml
rangeforge validate output/scenario-1337/scenario.yaml
rangeforge status output/scenario-1337/scenario.yaml
rangeforge destroy output/scenario-1337/scenario.yaml
```

`build` creates an owned scenario resource from a registered clean base. `up` starts it and
refreshes backend state. `provision` applies the scenario-ordered runtime primitives and then
validates them. `destroy` removes only the owned scenario VM or scenario-local Vagrant
environment.

## Host and guest compatibility

VM backend selection follows the normalized host, not user preference:

| Host | VM backend |
|---|---|
| macOS ARM64 / Apple Silicon | UTM directly |
| macOS AMD64 | Vagrant |
| Linux AMD64 | Vagrant |
| Windows AMD64 | Vagrant |
| Other combinations | Unsupported |

Windows image identities are exact and architecture-specific:

| Image | Guest architecture | Backend | Acquisition |
|---|---|---|---|
| `windows-11-arm64` | ARM64 | UTM | Manual, checksum-pinned media |
| `windows-11-amd64` | AMD64 | Vagrant | Manual, checksum-pending media |

`windows-11-amd64` remains compatible but non-deployable until a reviewed checksum and an
existing clean local Vagrant box are registered on a supported AMD64 host. RangeForge never
converts an AMD64 request into ARM64 or routes UTM through Vagrant.

## Configuration

The default configuration path is `~/.config/rangeforge/config.yaml`:

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

An explicit configuration can be supplied with `--config` on runtime and administrative
commands.

## Images and reusable templates

Trusted manifests under `rangeforge/images/definitions/` define guest product, architecture,
runtime/backend compatibility, vendor metadata, acquisition method, filename, and checksum.
RangeForge never scrapes vendor pages or discovers image URLs dynamically.

The image cache separates:

```text
downloads/              verified source artifacts
templates/<backend>/    reusable template metadata
metadata/               source acquisition records
```

Source readiness does not imply template readiness. A reusable template is registered only
after its source is checksum-verified and the backend confirms that the clean template
resource exists.

Common image commands:

```bash
rangeforge images list
rangeforge images info ubuntu-24.04-arm64
rangeforge images pull ubuntu-24.04-arm64
rangeforge images verify ubuntu-24.04-arm64
rangeforge images prepare ubuntu-24.04-arm64
```

Windows ARM64 media is obtained manually and imported against the checksum-pinned manifest:

```bash
rangeforge images import ~/Downloads/Win11_25H2_English_Arm64_v2.iso \
  --image windows-11-arm64
rangeforge images verify windows-11-arm64
rangeforge images prepare windows-11-arm64 --backend utm \
  --template-name rf-base-windows-11-arm64
```

RangeForge does not redistribute Windows media, bypass licensing or activation, or automate
interactive Windows installation. The operator must prepare a clean base explicitly.

UTM templates use stable names such as `rf-base-windows-11-arm64`. Manual Vagrant images
require an explicitly named existing local box. Template metadata binds the image ID,
verified source checksum, backend, architecture, schema version, and deterministic
fingerprint.

## Runtime metadata and ownership

Scenario runtime state is stored beside `scenario.yaml` under `runtime/`. The metadata
records the deterministic scenario identity, backend, VM name, template reference,
architecture, management state, provisioning state, and validation state.

Destructive operations validate the scenario identity and RangeForge ownership token before
deleting anything. They preserve:

- `scenario.yaml`
- source artifacts
- reusable base templates
- shared CVE artifacts

Management credentials are infrastructure secrets. They are never valid student attack-path
credentials and must not appear in generated graphs or student artifacts.

## Runtime primitives

A runtime primitive consists of:

- typed metadata
- instructor knowledge
- a provisioner
- a runtime validator
- positive and negative tests

The current Linux runtime chain includes service enumeration, a purpose-built local foothold,
credential discovery, and restricted privilege-escalation conditions. Vulnerable conditions,
student users, and flags are created only inside owned scenario clones.

Provisioning is idempotent and records `NOT_PROVISIONED`, `PROVISIONING`, `COMPLETE`, or
`FAILED`. A partial failure records the active and completed primitives and can never be
reported as valid.

## Curated CVE registry and artifacts

The current curated CVE definition is Apache ActiveMQ Classic 5.18.2 affected by
`CVE-2023-46604`. It uses a pinned official Apache archive and Eclipse Temurin JRE selected
for the guest architecture. The service is installed as an unprivileged scenario-specific
identity only inside an owned clone.

Administrative commands:

```bash
rangeforge cve list
rangeforge cve info CVE-2023-46604
rangeforge cve validate-registry

rangeforge artifacts list
rangeforge artifacts info apache-activemq-5.18.2
rangeforge artifacts pull apache-activemq-5.18.2
rangeforge artifacts verify apache-activemq-5.18.2
```

Artifact downloads are limited to configured HTTPS URLs, stream through a partial file, and
become ready only after checksum verification and atomic replacement. Invalid cached files
require explicit replacement. Shared artifacts survive scenario destruction.

The scenario runtime lock records the runtime/backend selection, architecture, base-image
fingerprint, primitive versions, CVE/service version, and exact artifact identities and
checksums. It is deterministic for fixed inputs.

## Validation and audience separation

Static validation checks profile policy, graph continuity, path length, objective
reachability, and declared compatibility. Runtime validation separately checks deployed
service state, identity, permissions, authentication expectations, flags, and intended state
transitions.

Negative validators reject unsafe shortcuts including root service identities,
world-readable proof files, passwordless sudo-all, unrelated-user sudo access, and solution
leakage. Successful provisioning alone is never sufficient for validity.

Student artifacts contain only the target and objectives. They exclude attack graphs,
primitive names, credentials, weaknesses, management secrets, flags, CVE details, and runtime
lock content. Instructor runtime files are stored separately with restrictive permissions.

## Testing

The default suite excludes tests that require real VM lifecycle access:

```bash
pytest
ruff check .
mypy rangeforge
```

Runtime-marked tests must be enabled explicitly in an authorized local environment. Ordinary
CI and development tests remain deterministic, offline, and side-effect free.

## Current limitations

- Production scenario generation is Linux-only.
- Windows management transport, provisioning, attack graphs, Active Directory, and Windows
  Server are not implemented.
- Windows AMD64 has deterministic schema and lifecycle coverage but has not been validated on
  a real x86 host.
- Interactive UTM and Windows installation are operator-managed.
- Current vulnerable runtime primitives are VM-backed; Docker content remains limited.
- The student target currently uses the backend-discovered VM network; a dedicated isolated
  student network remains future work.
- Cloud ranges, arbitrary targets, internet scanning, dynamic CVE discovery, public PoC
  downloads, malware, persistence, and evasion are outside project scope.

## Security and authorization

Use RangeForge only in isolated environments you own or are explicitly authorized to test.
Source images and reusable base templates must remain clean and non-vulnerable. Provisioners
target only RangeForge-owned scenario clones after identity, architecture, runtime, backend,
template, and ownership checks succeed.

RangeForge has no arbitrary-target input, network discovery, remote-system provisioning,
real-world credential attacks, malware, persistence, evasion, or dynamic exploit downloading.
Scenario validity and compatibility come from deterministic code and reviewed local registry
data, never from AI output.
