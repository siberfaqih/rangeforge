# RangeForge

RangeForge is a curriculum-aware, attack-graph-driven procedural cyber-range scenario
generator for controlled and authorized offensive-security training. It turns a training
profile and data-defined attack primitives into a reproducible, statically validated
scenario definition.

## Current status

Phase 1 implements the deterministic core engine and an OSCP-style standalone Linux
dry-run generator. It **does not provision vulnerable machines**, install services,
run exploits, start containers, or contact remote systems.

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

Run the quality checks with:

```bash
pytest
ruff check .
mypy rangeforge
```

## Roadmap

Later phases may add isolated Linux provisioning, runtime validation, concrete lab-only
primitives, Windows and Active Directory, and additional configurable training profiles.
Provider protocols mark extension boundaries, but Phase 1 deliberately includes no
provisioning, runtime, knowledge, or AI implementation.

## Security and authorization

RangeForge is intended only for systems you own or have explicit permission to test,
inside controlled and isolated training environments. Phase 1 creates inert scenario
metadata only. It has no arbitrary-target discovery, internet scanning, remote
exploitation, credential attacks, payload delivery, malware, persistence, or evasion
capability.

