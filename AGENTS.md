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
- Source images, shared base templates, and scenario VMs are separate resources.
- Destroying a scenario must never delete its source image or shared base template.
- Scenario VMs should be cloned from prepared base templates whenever the backend supports it.
- Checksum verification is mandatory before a source image can become `READY`.
- Runtime lifecycle state belongs in scenario-specific runtime metadata, never in the attack graph.
- Destructive lifecycle operations must validate RangeForge ownership metadata first.
- Phase 2B base images and templates must remain clean and non-vulnerable.
- Phase 3 vulnerability provisioning, flags, and student users belong only to owned scenario clones.
- Attack graphs describe logical transitions only.
- Primitive provisioners create runtime conditions; primitive validators verify them.
- Provisioning must target only RangeForge-managed scenario resources.
- Shared base templates and source images must never receive vulnerability provisioning.
- Management credentials are infrastructure secrets and must never enter student attack paths.
- Student artifacts must not expose solutions, credentials, primitive names, or flag values.
- Runtime validity requires positive and negative checks; successful provisioning alone is not validity.
- RangeForge never selects arbitrary internet CVEs.
- Only curated CVE registry entries may participate in scenario generation.
- CVE primitives are ordinary runtime primitives with additional vulnerability metadata.
- CVE selection must respect profile, platform, runtime, backend, base guest, and architecture
  compatibility.
- External vulnerable service artifacts must be version-pinned and checksum-verified.
- Do not dynamically download arbitrary exploit proofs of concept.
- Attack graphs store state transitions, not exploit instructions.
- CVE provisioning must target only RangeForge-managed scenario resources.
- Base templates remain clean and must never receive CVE provisioning.
- Scenario destroy never removes shared CVE artifacts.
- CVE CVSS scores must not determine training difficulty.
- AI is not a source of truth for CVE metadata, compatibility, or validation.

Every future real primitive should eventually provide:

- metadata
- knowledge
- a provisioner
- a runtime validator
- tests

Before completing a change, run `pytest`, `ruff check .`, and `mypy rangeforge`.
