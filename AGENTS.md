# RangeForge Engineering Constraints

RangeForge is a deterministic procedural cyber-range generator for authorized,
isolated training.

- Keep scenario generation separate from infrastructure provisioning.
- Keep training-profile policy separate from generic graph logic.
- Represent attack techniques as data-driven primitives; never hardcode certification
  transitions in the graph engine.
- Use one `ScenarioRandomizer` per generation and route every random decision through it.
- Preserve reproducibility: the same seed, profile, inputs, and generator version must
  produce the same logical scenario.
- Validate every generated path before considering it valid.
- Apply curriculum policy with deterministic, default-deny profile rules.
- AI must never be the source of truth for scenario validity or curriculum eligibility.
- Do not introduce techniques outside the selected training profile.
- Keep all future vulnerable infrastructure isolated and explicitly intended for local,
  authorized training.
- Do not add internet scanning, arbitrary target discovery, remote exploitation,
  credential attacks against real systems, malware, persistence, or evasion features.
- RangeForge distinguishes deterministic scenario generation from runtime deployment.
- `runtime=docker` uses Docker directly.
- `runtime=vm` selects its backend from the normalized host OS and architecture.
- macOS ARM64 / Apple Silicon uses UTM directly; never route UTM through Vagrant.
- AMD64 VM hosts use Vagrant.
- Host and guest architectures are first-class, and x86 guests must not be silently
  emulated on ARM.
- Images must come from configured trusted registry definitions.
- Downloaded artifacts must be checksum-verifiable before becoming ready.
- Image acquisition and backend-template preparation are separate lifecycle states.
- UTM environments should prefer cloning prepared reusable base templates.
- Phase 1 scenario generation must never depend on runtime or backend availability.

Every future real primitive should eventually provide:

- metadata
- knowledge
- a provisioner
- a runtime validator
- tests

Before completing a change, run `pytest`, `ruff check .`, and `mypy rangeforge`.
