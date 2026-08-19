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

Every future real primitive should eventually provide:

- metadata
- knowledge
- a provisioner
- a runtime validator
- tests

Before completing a change, run `pytest`, `ruff check .`, and `mypy rangeforge`.

