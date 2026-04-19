# Milestone 13: `mu_exec` Extractor Grounding

## Objective
Define the first repo-native planning surface for a `mu_exec` extractor that
keeps trace-derived observations proposal-only, grounds execution interactions
through IR/binary semantics, and derives security violations only from
invariant failure over grounded witnesses.

## Concrete Files
- `COMPACTIFIED_CONTEXT.md`
- `README.md`
- `TODO.md`
- `CHANGELOG.md`
- `docs/MILESTONE_13.md`
- `src/zksec/mu_exec.py`
- `src/zksec/routing.py`
- `src/zksec/admissibility.py`
- `src/zksec/reporting.py`
- `src/zksec/__init__.py`
- `tests/test_admissibility.py`
- `tests/test_routing.py`
- `tests/test_reporting.py`

## Design
- Treat `trace`, `zkperf`, and `strace` as proposal-only observation surfaces.
- Materialize `mu_exec` only after linking trace proposals to IR/binary
  semantics and explicit execution structure.
- Keep the normalized zkSEC analysis stack explicit:
  `code/binary/trace -> Phi_exec -> mu_exec -> epsilon_exec -> kappa_sec -> Admk_sec -> vulnerability witness`.
- Derive concrete violation classes from invariant failure over grounded
  witnesses rather than from hand-authored vulnerability labels whenever
  grounding is available.
- Preserve the local-first invariant: no outbound network dependency is
  introduced by the extractor design or verification flow.
- Make the implementation phase produce deterministic evidence surfaces suitable
  for receipts, routing, and audit outputs.

## Acceptance Checks
1. The repo documents the `mu_exec` extractor boundary and the proposal versus
   grounding split before code changes begin.
2. The implementation plan identifies a bounded witness type, grounding inputs,
   and invariant-evaluation surface.
3. New code exposes grounded witness material without treating raw trace events
   as verified violations.
4. Tests cover at least one grounded safe case, one grounded invariant failure,
   and one unresolved/proposal-only case.
5. Existing admissibility, routing, execution, and reporting controls do not
   regress.
6. Audit/reporting surfaces can carry extractor evidence without violating the
   no-network local surface invariant.

## Governance Impact
- Tightens the proposal-versus-authority boundary already used elsewhere in
  zkSEC by preventing raw trace heuristics from silently becoming truth.
- Improves ISO 42001, NIST AI RMF, and ISO 23894 alignment by requiring
  grounded evidence before promotion into security-relevant conclusions.
- Improves ISO 9001 and Six Sigma style defect traceability by making witness
  generation, invariant checks, and unresolved states explicit and testable.

## Verification
- `PYTHONPATH=src pytest -q tests/test_admissibility.py tests/test_routing.py tests/test_reporting.py` -> `34 passed`
- `PYTHONPATH=src pytest -q` -> `67 passed`
