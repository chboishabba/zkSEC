# Milestone 14: `mu_exec` Extractor Pipeline

## Goal

Turn the Milestone 13 witness boundary into a concrete local extractor design
for `mu_exec` that preserves the repo's authority split:

- `trace` / `zkperf` / `strace` propose candidate execution links
- `ghidra` / IR / binary semantics ground the witness
- invariant evaluation decides whether a grounded witness is a real violation

## Non-Goals

- Do not introduce outbound-network dependency into the local zkSEC decision
  surface.
- Do not promote trace-only observations into authoritative violations.
- Do not hard-code vulnerability labels as the primary extractor output.

## Required Deliverables

1. Define the bounded extractor contract for proposed versus grounded witness
   inputs.
2. Identify the first local ingest shape for `ghidra`-derived IR facts and
   trace-derived proposal facts.
3. Specify the deterministic normalization path from raw extractor facts to
   `MuExecWitness`.
4. Thread any new extractor-facing fields through receipts only if they are
   provenance-bearing and stable.
5. Add tests for unresolved links, grounded links, and invariant-triggered
   violation materialization.

## Acceptance Criteria

- A repo-local design exists for `ghidra + trace` input normalization.
- Proposal-only trace facts remain non-authoritative in routing and reporting.
- Grounded `mu_exec` witnesses can be constructed from a documented local
  extractor input shape.
- The first implementation slice is narrow enough to land without requiring
  live trace capture or a full Ghidra integration runtime.
- The first producer contract is pinned in a dedicated document with a minimal
  trace fixture and a minimal IR grounding fixture.

## Implementation Status

- Implemented as a library-only surface in `src/zksec/mu_exec.py`.
- Added ingest dataclasses for proposal facts, grounding facts, bundle inputs,
  and normalized link resolution.
- Added deterministic helper entrypoints:
  `normalize_mu_exec_ingest(...)` and
  `build_mu_exec_witness_from_ingest(...)`.
- Added a pinned V1 producer contract in
  [docs/producer_contracts/mu_exec_ingest_v1.md](producer_contracts/mu_exec_ingest_v1.md)
  with the first `zkperf` and `ghidra` fixture pair.
- Added dedicated producer-facing modules:
  `src/zksec/ingest_types.py` and
  `src/zksec/build_mu_exec_from_ingest.py`.
- Added fixture-backed coverage in `tests/test_mu_exec_ingest.py`.
- Verified the first extractor-facing and authority-split test surface with:
  `PYTHONPATH=src pytest -q tests/test_mu_exec_ingest.py tests/test_mu_exec.py tests/test_admissibility.py tests/test_routing.py tests/test_reporting.py`
  yielding `41 passed`.

## Planned Lanes

- Lane `extractor-contract`: define the input/output contract and normalization
  boundary for proposed and grounded witness facts.
- Lane `adjacent-surface-read`: inspect `../ITIR-suite` and `../zkperf` for
  nearby local evidence formats that can inform the first ingest shape.
- Lane `verification-shape`: define the smallest stable test surface for the
  first extractor-facing implementation slice.
