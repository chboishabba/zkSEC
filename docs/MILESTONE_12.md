# Milestone 12: Transform Admissibility and Proposal Bridge

## Objective
Shift zkSEC from action-only gating to pre-activation transform admissibility.
This milestone adds one normalized admissibility kernel, one ZOS proposal-only
bridge, one unified detector surface, one multi-step attack harness, and one
ontology-poisoning detector without changing the local no-network invariant.

## Concrete Files
- `src/zksec/admissibility.py`
- `src/zksec/routing.py`
- `src/zksec/reporting.py`
- `src/zksec/__init__.py`
- `tests/test_admissibility.py`
- `tests/test_routing.py`
- `tests/test_cli.py`
- `tests/test_execution.py`
- `tests/test_integration.py`
- `TODO.md`
- `CHANGELOG.md`

## Design
- Add a normalized admissibility tuple covering:
  - prior state
  - proposed state
  - delta surface
  - capability delta
  - channel delta
  - semantic delta
  - admissibility verdict
- Add a ZOS-to-zkSEC bridge that accepts only proposal metadata:
  - resonance
  - embedding neighborhood
  - factor coordinates
  - normalization hints
  - semantic clustering
  - structural similarity
- Reject direct authority crossings from proposal-side inputs:
  - publish authority
  - execute authority
  - capability decisions
  - policy mutation
  - truth promotion
- Add one unified detector with four bounded surfaces:
  - `F_cap`
  - `F_channel`
  - `F_delta`
  - `F_onto`
- Add ontology-poisoning detection using compression/resonance gain versus
  groundedness, provenance, and control consistency loss.
- Add an offline multi-step attack-chain harness that evaluates step sequences
  without introducing a second execution doctrine.
- Carry admissibility, detector, changed-surface, and bridge metadata into
  receipts and audit outputs for deterministic evidence.

## Acceptance Checks
1. Benign admissible deltas with unchanged geometry remain allowed.
2. ZOS proposal metadata is accepted only as proposal-side context.
3. ZOS authority fields are blocked before activation with explicit reason codes.
4. Ontology-poisoning candidates are denied or forced into confirmation before
   any canonical/control promotion.
5. Multi-step attack chains stop at the first inadmissible transform.
6. Existing action, proposal/authority, capability, channel, ring, and receipt
   gates do not regress.
7. Audit outputs include admissibility verdict, detector verdict/severity, and
   bridge status.
8. Full test suite passes after integration.

## Verification
- `PYTHONPATH=src pytest -q` -> `61 passed`

## Governance Impact
- Strengthens ISO 27001 evidence for preventive control and monitored authority boundaries.
- Strengthens ISO 42001 and NIST AI RMF evidence by keeping semantic/AI-origin
  signals proposal-only until explicitly admitted.
- Strengthens ISO 23894 evidence by making semantic/control mismatch and
  composed-chain failure modes measurable.
- Improves ISO 9001, ITIL, and Six Sigma evidence by leaving behind explicit
  acceptance criteria, defect classes, and deterministic blocked-path outputs.
