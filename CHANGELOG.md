# Changelog

## 2026-04-19
### Added
- Added `docs/MILESTONE_13.md` to define the docs-first plan for a grounded
  `mu_exec` extractor.
- Added `docs/MILESTONE_14.md` to define the next-step `ghidra + trace`
  extractor pipeline milestone and lane structure.
- Added `src/zksec/mu_exec.py` with `MuExecWitness` plus deterministic witness
  build, invariant-evaluation, and receipt-field helpers.
- Added library-only Milestone 14 ingest helpers in `src/zksec/mu_exec.py`:
  `MuExecTraceProposalFact`, `MuExecGhidraGroundingFact`,
  `MuExecIngestBundle`, `MuExecLinkResolution`,
  `normalize_mu_exec_ingest(...)`, and
  `build_mu_exec_witness_from_ingest(...)`.
- Added `tests/test_mu_exec.py` for fixture-driven ingest normalization and
  witness materialization coverage.

### Changed
- Updated `COMPACTIFIED_CONTEXT.md` with canonical metadata for the
  `Language Model Security` thread:
  - title `Language Model Security`
  - online UUID `69e43a82-9fc0-839f-a022-cbf28c6c6a5f`
  - canonical thread ID `a70ae3942d8e8f440ec62db62464775e8979d6c4`
  - source `db` after direct online UUID pull
- Updated `README.md` to mark Milestone 13 as the current planning surface.
- Updated `TODO.md` with Milestone 13 planning and implementation tasks.
- Recorded the repo-facing architectural decision that raw trace surfaces stay
  proposal-only, IR grounds `mu_exec`, and invariant failure over grounded
  witnesses is the point where a security violation exists.
- Refreshed the canonical `Language Model Security` thread from the online UUID
  and recorded the sharper follow-up decision that the next milestone is a
  concrete `ghidra + trace` extractor pipeline rather than only abstract
  witness grounding.
- Updated `README.md` and `TODO.md` to mark Milestone 14 implemented as a
  library-only ingest surface rather than a future plan.
- Extended `src/zksec/admissibility.py` so grounded `mu_exec` invariant
  failures reject, grounded-safe witnesses allow, and proposal-only witnesses
  require confirmation rather than silently promoting to violations.
- Extended `src/zksec/routing.py` and `src/zksec/reporting.py` to thread
  deterministic `mu_exec_*` evidence into routing decisions, receipts, and
  audit outputs.
- Extended `src/zksec/__init__.py` to export the Milestone 13 witness helpers.
- Added focused Milestone 13 coverage in `tests/test_admissibility.py`,
  `tests/test_routing.py`, and `tests/test_reporting.py`.
- Revalidated the extractor-facing and authority-split test surface with
  `PYTHONPATH=src pytest -q tests/test_mu_exec.py tests/test_admissibility.py tests/test_routing.py tests/test_reporting.py`
  and recorded `38 passed`.
- Revalidated the full suite with `PYTHONPATH=src pytest -q` and recorded
  `67 passed`.

## 2026-04-07
### Added
- Initialized git repository in `/home/c/Documents/code/zkSEC`.
- Added `COMPACTIFIED_CONTEXT.md` with resolved thread metadata:
  - title `LiteLLM hack analysis`
  - online UUID `69ce0ac6-dd2c-839f-8b84-a0d397285f90`
  - canonical thread ID `130c635a73d780dfb0552107cc0a77a77d4cfea9`
  - source `db` (after online UUID pull)
- Added `README.md` with repo operating rules.
- Added `TODO.md` with initialization and next-step tasks.
- Added `docs/DEPENDENCIES.md` and `docs/MILESTONE_01.md`.
- Added minimal project scaffold:
  - `src/zksec/__init__.py`
  - `src/zksec/context.py`
  - `tests/test_context.py`
- Added `.gitignore` for Python cache and bytecode artifacts.
- Added security gate scaffold:
  - `docs/MILESTONE_02.md`
  - `src/zksec/security.py`
  - `tests/test_security.py`
- Added adjacent adapter contracts:
  - `src/zksec/adapters/contracts.py`
  - `src/zksec/adapters/__init__.py`
  - `tests/test_adapters.py`
- Added adapter-aware routing implementation and tests:
  - `docs/MILESTONE_03.md`
  - `src/zksec/routing.py`
  - `tests/test_routing.py`
- Added execution gating and reporting milestones:
  - `docs/MILESTONE_04.md`
  - `src/zksec/execution.py`
  - `tests/test_execution.py`
  - `docs/MILESTONE_05.md`
  - `src/zksec/reporting.py`
  - `tests/test_reporting.py`
- Added CLI and integration harness:
  - `docs/MILESTONE_06.md`
  - `src/zksec/cli.py`
  - `src/zksec/__main__.py`
  - `tests/test_cli.py`
  - `tests/test_integration.py`

### Changed
- Updated `README.md` to include adjacent relevance scope and LiteLLM incident-context note.
- Updated `TODO.md` for Milestone 01 through Milestone 06 completion tracking.
- Updated `COMPACTIFIED_CONTEXT.md` with adjacent relevance decisions and ITIR security alignment.
- Documented and codified a local surface invariant in `src/zksec/context.py` and `docs/DEPENDENCIES.md`
  requiring no outbound network access for the local zkSEC decision surface.
- Added milestone 7 syscall-boundary hardening (`tests/test_syscall_guard.py`) and
  documented external trace validation references in `docs/DEPENDENCIES.md` using `zkperf`.
  Re-ran the documented strace-based checks and recorded `39 passed` in `docs/MILESTONE_07.md`.
- Added actor/maintainer legitimacy controls:
  - documented proposal-only external discovery and verified identity/scope gating in `README.md` and `docs/DEPENDENCIES.md`;
  - added `Milestone 08` in `TODO.md` and `docs/MILESTONE_08.md` to track
    receipt-gated, high-authority execution checks.
- Completed Milestone 08 enforcement for high-trust lanes:
  - added actor identity/scope/plan receipt requirements in `src/zksec/security.py`;
  - wired identity/scope/plan_ref propagation through `src/zksec/routing.py` and
    `src/zksec/cli.py`;
  - added execution-layer receipt preconditions in `src/zksec/execution.py`;
  - added enforcement tests in `tests/test_security.py`, `tests/test_routing.py`, 
    `tests/test_execution.py`, and `tests/test_cli.py`.
- Implemented Milestone 09 resource-boundary and secret-leak detection:
  - added adapter-scoped `resource_roots` in `src/zksec/adapters/contracts.py`;
  - added boundary/content guardrails in `src/zksec/security.py`;
  - wired `resource` and `request_payload` validation through `src/zksec/routing.py`
    and CLI inputs (`src/zksec/cli.py`);
  - added tests in `tests/test_adapters.py`, `tests/test_security.py`,
    `tests/test_routing.py`, `tests/test_cli.py`;
  - added `docs/MILESTONE_09.md` and updated `TODO.md`/`docs/DEPENDENCIES.md`.

- Added governance alignment register (`docs/GOVERNANCE_ALIGNMENT.md`) and linked it from
  `README.md` to record explicit standard and surface traceability.
- Added C4-formalized control diagram and evidence bridge artifact:
  `docs/uml/zksec-c4-architecture.puml`, `docs/uml/zksec-c4-architecture.svg`,
  and `docs/GOVERNANCE_STANDARD_GAPS.md`.

- Added `docs/MILESTONE_10.md` to explicitly track governance standard alignment
  and traceability updates.

- Implemented Milestone 11 geometry controls:
  - added explicit per-action capability/channel/ring/destination profiles to
    `src/zksec/adapters/contracts.py`;
  - added admissibility checks for widening in `src/zksec/routing.py`
    (`capability_widening_detected`, `channel_widening_detected`,
    `ring_widening_detected`, `destination_widening_detected`);
  - added additional admissibility checks for capability expansion, transform drift,
    and structural anomaly controls.
  - added CLI geometry selectors in `src/zksec/cli.py`;
  - propagated geometry metadata into execution directives and audit records;
  - added geometry-focused tests in `tests/test_routing.py` and `tests/test_cli.py`.
  - revalidated full suite to `54 passed` and updated runtime trace evidence
    (`/tmp/zksec_pytest_trace_m11.txt`, `/tmp/zksec_cli_trace_m11.txt`) in
    `docs/MILESTONE_07.md` and `docs/DEPENDENCIES.md`.

- Implemented Milestone 12 transform admissibility controls:
  - added `src/zksec/admissibility.py` with the normalized admissibility tuple,
    proposal-only ZOS bridge, unified detector (`F_cap`, `F_channel`, `F_delta`,
    `F_onto`), ontology-surface scoring, and multi-step attack-chain harness;
  - integrated admissibility decisions into `src/zksec/routing.py` so proposal-side
    metadata, semantic poisoning, and transform drift are evaluated before activation
    while preserving current action-gate behavior;
  - carried admissibility and detector metadata into routing receipts and
    `src/zksec/reporting.py` audit outputs;
  - exposed the new primitives through `src/zksec/__init__.py`;
  - added `tests/test_admissibility.py` covering benign admissible deltas,
    forbidden authority crossings, ontology poisoning, and composed attack chains;
  - revalidated the full suite to `61 passed`.
