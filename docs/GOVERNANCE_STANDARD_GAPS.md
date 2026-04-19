# Governance Standard Gaps and Evidence Addendum

## Purpose
Track concrete, repository-local evidence and explicit gap closures for remaining governance mappings.

## Current Position
This project is a policy-orchestrator surface with explicit boundaries. Several standards require additional process/ops documentation before full implementation.

## Standards Status Summary

- **ISO 27701**: Current evidence now includes actor/secret/source trust controls, receipt-based action gating, and ontology/semantic misuse checks. Full privacy-governance lifecycle evidence (data lineage/retention/subject rights handling) is not yet documented as a dedicated artifact.
- **ISO 23894**: Risk handling is encoded in decision-level controls, source confidence rules, semantic/control mismatch checks, and attack-chain rejection tests, but formal risk treatment plans and post-action audit of residual risk are pending.
- **ISO 9241-161**: Accessibility-oriented validation criteria are not yet documented.
- **ISO 9241-210**: User-centered validation is partial; operator controls are tested for functional correctness but not for usability studies.
- **ISO 24552**: Lifecycle and assurance evidence is partial (artifact-level checks only); lifecycle governance plan is pending.
- **ISO 16817**: Privacy/forensic chain evidence exists for deterministic receipts, but full chain-of-custody protocol artifacts are pending.
- **ISO 9241-306**: Accessibility governance controls are not yet documented.
- **ISO 22727**: Information-assurance process controls are represented at a policy/gate level, but formal management review and sign-off artifacts are pending.

## Concrete evidence already tied to these gaps
- [src/zksec/security.py](/home/c/Documents/code/zkSEC/src/zksec/security.py)
- [src/zksec/routing.py](/home/c/Documents/code/zkSEC/src/zksec/routing.py)
- [src/zksec/execution.py](/home/c/Documents/code/zkSEC/src/zksec/execution.py)
- [src/zksec/cli.py](/home/c/Documents/code/zkSEC/src/zksec/cli.py)
- [docs/GOVERNANCE_ALIGNMENT.md](/home/c/Documents/code/zkSEC/docs/GOVERNANCE_ALIGNMENT.md)
- [docs/DEPENDENCIES.md](/home/c/Documents/code/zkSEC/docs/DEPENDENCIES.md)
- [docs/MILESTONE_07.md](/home/c/Documents/code/zkSEC/docs/MILESTONE_07.md)
- [docs/MILESTONE_08.md](/home/c/Documents/code/zkSEC/docs/MILESTONE_08.md)
- [docs/MILESTONE_09.md](/home/c/Documents/code/zkSEC/docs/MILESTONE_09.md)
- [docs/MILESTONE_12.md](/home/c/Documents/code/zkSEC/docs/MILESTONE_12.md)
- [src/zksec/admissibility.py](/home/c/Documents/code/zkSEC/src/zksec/admissibility.py)
- [tests/test_admissibility.py](/home/c/Documents/code/zkSEC/tests/test_admissibility.py)
