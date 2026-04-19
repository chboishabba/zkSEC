# TODO

## Initialization
- [x] Initialize git repository for `zkSEC`.
- [x] Create compact context with canonical thread metadata.
- [x] Add project README with operating rules.
- [x] Create changelog.

## Milestone 01: Project Skeleton + Baseline Interfaces
- [x] `docs/DEPENDENCIES.md`: record and justify adjacent relevant surfaces.
- [x] `docs/MILESTONE_01.md`: define objective, concrete files, and acceptance checks.
- [x] `src/zksec/__init__.py`: expose baseline public interface.
- [x] `src/zksec/context.py`: provide security context and known surface declarations.
- [x] `tests/test_context.py`: validate baseline interface and adjacent surface list.
- [x] Run `PYTHONPATH=src pytest -q tests/test_context.py` and record result (`4 passed`).

## Milestone 02: Security Gate Foundation
- [x] `docs/MILESTONE_02.md`: define priority and acceptance checks.
- [x] `src/zksec/security.py`: define `SecurityDecision`, `assess_action`, and `policy_receipt`.
- [x] `src/zksec/__init__.py`: expose security gate API.
- [x] `tests/test_security.py`: validate gate invariants and core blocks.
- [x] `src/zksec/adapters/contracts.py`: define `zos_server_contract` and `kant_zk_pastebin_contract`.
- [x] `src/zksec/adapters/__init__.py`: export adapter contracts and check helpers.
- [x] `tests/test_adapters.py`: validate adapter contract behavior.

## Milestone 03: Adapter-Aware Routing
- [x] `docs/MILESTONE_03.md`: define objective, concrete files, and acceptance checks.
- [x] `src/zksec/routing.py`: add `evaluate_adapter_action`.
- [x] `tests/test_routing.py`: validate adapter/security interaction checks.
- [x] `src/zksec/__init__.py`: expose routing API.

## Milestone 04: Execution Directive Boundary
- [x] `docs/MILESTONE_04.md`: define objective, concrete files, and acceptance checks.
- [x] `src/zksec/execution.py`: add adapter execution directive abstraction.
- [x] `tests/test_execution.py`: validate blocked/confirm/ready transition behavior.
- [x] `src/zksec/__init__.py`: expose execution API.

## Milestone 05: Audit Reporting Surface
- [x] `docs/MILESTONE_05.md`: define objective, concrete files, and acceptance checks.
- [x] `src/zksec/reporting.py`: add deterministic audit payload helper.
- [x] `tests/test_reporting.py`: validate audit payload shape.
- [x] `src/zksec/__init__.py`: expose reporting API.

## Milestone 06: CLI Flow and Integration Harness
- [x] `docs/MILESTONE_06.md`: define objective, concrete files, and acceptance checks.
- [x] `src/zksec/cli.py`: add command-line evaluator.
- [x] `src/zksec/__main__.py`: wire module execution path.
- [x] `tests/test_cli.py`: validate CLI status and output behavior.
- [x] `tests/test_integration.py`: validate routing→execution→reporting flow.

## Milestone 07: No-Syscall Surface Verification
- [x] `docs/MILESTONE_07.md`: define objective and acceptance checks.
- [x] `tests/test_syscall_guard.py`: enforce static no-network/no-process API imports/calls.
- [x] `docs/DEPENDENCIES.md`: include external strace verification references.
- [x] Update `CHANGELOG.md` with hardening note.

## Milestone 08: Maintainer/Actor Integrity Boundaries
- [x] Capture actor-legitimacy and authority-crossing constraints in `docs/DEPENDENCIES.md` and `README.md` for public/external candidates.
- [x] Add `docs/MILESTONE_08.md` documenting explicit identity/scope/receipt preconditions before high-authority action.
- [x] Add enforcement tests for actor identity/scope gating before any high-authority action surface.
- [x] Add explicit receipt-backed execution precondition checks for high-trust lanes.

## Milestone 09: Data Boundary and Secret-Exfiltration Detection
- [x] Add adapter-specific resource scope boundaries in contract definitions.
- [x] Add payload/resource guardrails for out-of-bounds resource access attempts.
- [x] Add secret-token/pattern detection on request content and block suspicious material.
- [x] Add CLI flags for resource/payload checks and wire through routing.
- [x] Update docs and changelog with new boundary controls.

## Milestone 10: Governance and Standards Traceability Register
- [x] Add `docs/GOVERNANCE_ALIGNMENT.md` with required standard coverage evidence map.
- [x] Link the register from `README.md` and keep `CHANGELOG.md` aligned.
- [x] Add/update governance evidence entries from milestone implementations and strace captures.

## Milestone 11: Capability, Channel, and Ring Geometry
- [x] Add adapter-level capability/ring/channel envelopes with per-action profiles in `src/zksec/adapters/contracts.py`.
- [x] Enforce capability geometry checks (`F_cap`) in `src/zksec/routing.py`.
- [x] Expose geometry assertions in CLI (`--requested-capability`, `--requested-channel`, `--requested-ring`, `--requested-destination`).
- [x] Add tests for capability widening, channel widening, and ring widening scenarios.
- [x] Add explicit checks for capability expansion, transform drift, and structural drift before execution.
- [x] Carry geometry metadata into receipts, execution directives, and audit payloads.
- [x] Update runtime evidence pointers for `54 passed` local verification and strace traces in `docs/MILESTONE_07.md`, `docs/DEPENDENCIES.md`, and `CHANGELOG.md`.

## Milestone 12: Transform Admissibility and Proposal Bridge
- [x] Add a normalized admissibility kernel in `src/zksec/admissibility.py`.
- [x] Add a ZOS proposal-only bridge surface with forbidden authority crossing checks.
- [x] Add a unified detector surface covering `F_cap`, `F_channel`, `F_delta`, and `F_onto`.
- [x] Add a multi-step attack-chain harness for composed-flow rejection checks.
- [x] Thread admissibility and detector metadata into routing receipts and audit reporting.
- [x] Add focused tests for bridge rejection, ontology poisoning, admissible benign deltas, and chain blocking.
- [x] Revalidate the full suite with `PYTHONPATH=src pytest -q`.

## Milestone 13: `mu_exec` Extractor Grounding
- [x] Resolve the `Language Model Security` chat into the canonical archive and
  record thread metadata in `COMPACTIFIED_CONTEXT.md`.
- [x] Add `docs/MILESTONE_13.md` documenting the proposal-only trace boundary
  and IR-grounded `mu_exec` direction.
- [x] Define the bounded `mu_exec` witness type and supporting grounding inputs
  in `src/zksec/`.
- [x] Add routing/reporting integration points for grounded witness evidence
  without changing the local no-network invariant.
- [x] Add focused tests for grounded-safe, grounded-violation, and
  unresolved/proposal-only cases.
- [x] Revalidate the impacted test surface with `PYTHONPATH=src pytest -q`
  and record `67 passed`.
