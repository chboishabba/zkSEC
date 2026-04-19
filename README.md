# zkSEC

`zkSEC` is initialized as a local workspace for security-oriented architecture and implementation work.

## Operating Rules
- Start from canonical context (`COMPACTIFIED_CONTEXT.md`) before major decisions.
- Keep one canonical chat archive at `/home/c/chat_archive.sqlite`.
- Use the workflow: Docs -> TODO -> Code -> Changelog.
- Maintain the local surface invariant: no outbound network access is performed by this security decision surface.
- Treat public/undercertain signals as proposal-only; high-authority action requires verified actor, authorized scope, and explicit approval/receipt flow (no silent authority crossing).

## Relevant Adjacent Surfaces
- `../ITIR-suite`
- `../zos-server`
- `../zkperf`
- `../ipfs-dasl`
- `../kant-zk-pastebin` (relevant to ZOS-related flows)
- `../litellm-config.yaml` (incident-context relevance only, due to recent LiteLLM hack)

See `docs/DEPENDENCIES.md` for details.

## Standards and Compliance Mapping
- Required standards and architectural surfaces are tracked in [`docs/GOVERNANCE_ALIGNMENT.md`](/home/c/Documents/code/zkSEC/docs/GOVERNANCE_ALIGNMENT.md).

## Current Status
- Repository initialized on 2026-04-07.
- Initial context pulled from ChatGPT thread: `LiteLLM hack analysis`.
- Milestone 01 scaffold defined in `docs/MILESTONE_01.md`.
- Milestones 02 and 03 complete: security gate, adapter contracts, and adapter-aware routing.
- Milestones 04 and 05 now in place: execution directives and deterministic reporting.
- Milestone 06 in place: CLI flow and integration harness.
- Milestones 07 through 11 implemented: syscall boundary hardening,
  actor/authority integrity constraints, resource/secret-exfiltration guardrails,
  governance traceability alignment, and capability/channel/ring geometry controls.
- Milestone 12 implemented: transform admissibility, ZOS proposal-only bridge
  enforcement, unified detector scoring, multi-step chain blocking, and
  ontology-poisoning checks.
- Milestone 13 implemented: grounded `mu_exec` witness modeling, routing and
  audit receipt threading, and focused verification for grounded-safe,
  grounded-failure, and proposal-only cases.

## Architecture Diagram
- [Control architecture diagram (SVG)](docs/uml/zksec-control-architecture.svg)
- [PlantUML source](docs/uml/zksec-control-architecture.puml)
- [C4 architecture diagram (SVG)](docs/uml/zksec-c4-architecture.svg)
- [C4 source](docs/uml/zksec-c4-architecture.puml)
