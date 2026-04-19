# Governance Alignment Register

This file maps required governance/standards surfaces to concrete evidence already present in the repository.

Status legend:
- `implemented`: direct artifact exists and is explicitly documented.
- `partial`: some related control exists, but the standard is not fully mapped.
- `missing`: no direct mapping or evidence is documented yet.

## Standards Traceability

| Standard / Surface | Current Evidence | Status | Evidence Pointer |
|---|---|---|---|
| ITIL | Service-management controls are partially codified as documented operating rules, evidence-ready milestones, and blocked-path transform/attack-chain outputs. | partial | `docs/DEPENDENCIES.md`, `docs/MILESTONE_07.md`, `docs/MILESTONE_08.md`, `docs/MILESTONE_09.md`, `docs/MILESTONE_12.md`, `tests/test_admissibility.py` |
| ISO 9001 | QA/QMS controls are partially represented via Docs→TODO→Changelog traceability and explicit acceptance checks per milestone, including transform-admissibility verification. | partial | `TODO.md`, `CHANGELOG.md`, `docs/MILESTONE_02.md`, `docs/MILESTONE_09.md`, `docs/MILESTONE_12.md`, `tests/test_admissibility.py` |
| ISO 42001 | AI-governance mapping is partially represented by explicit source-trust, actor/authority preconditions, proposal-only semantic bridge controls, and ontology-risk checks. | partial | `src/zksec/security.py`, `src/zksec/routing.py`, `src/zksec/admissibility.py`, `docs/MILESTONE_08.md`, `docs/MILESTONE_12.md` |
| ISO 27001 | ISMS control mapping is partially represented by explicit policy gates, separation of proposal and authority, unified admissibility checks, and audit trail outputs. | partial | `src/zksec/security.py`, `src/zksec/admissibility.py`, `src/zksec/execution.py`, `src/zksec/reporting.py`, `docs/MILESTONE_08.md`, `docs/MILESTONE_12.md` |
| ISO 27701 | Privacy-governance controls are partially represented by request payload secret detection, no-network policy, and semantic/ontology misuse checks; full lifecycle privacy evidence remains partial. | partial | `src/zksec/security.py`, `src/zksec/admissibility.py`, `tests/test_security.py`, `tests/test_admissibility.py`, `docs/GOVERNANCE_STANDARD_GAPS.md` |
| ISO 23894 | Formal risk-management is partially represented through risk levels, confirmation gating, semantic/control mismatch checks, and attack-chain rejection evidence. | partial | `src/zksec/security.py`, `src/zksec/admissibility.py`, `docs/GOVERNANCE_STANDARD_GAPS.md`, `docs/MILESTONE_09.md`, `docs/MILESTONE_12.md` |
| ISO 9241-110 | Usability-governance mapping is partial; operator-facing UX decisions are logged in milestone docs only. | partial | `src/zksec/cli.py`, `docs/MILESTONE_06.md` |
| ISO 9241-161 | Accessibility/usability evidence is partially represented by operator-facing CLI outputs and reason-code visibility. | partial | `src/zksec/cli.py`, `tests/test_cli.py`, `docs/GOVERNANCE_STANDARD_GAPS.md` |
| ISO 9241-210 | Usability/control evidence is partial: current unit-path and CLI flows are validated, with user-experience depth pending. | partial | `src/zksec/cli.py`, `tests/test_cli.py`, `docs/GOVERNANCE_STANDARD_GAPS.md` |
| ISO 24552 | Lifecycle and assurance controls are partially represented through milestone evidence retention (`TODO`/`CHANGELOG`) with explicit gap notes. | partial | `CHANGELOG.md`, `TODO.md`, `docs/GOVERNANCE_STANDARD_GAPS.md` |
| ISO 16817 | Forensic auditability is partial through receipt/command/audit records and trace evidence references. | partial | `src/zksec/security.py`, `src/zksec/execution.py`, `src/zksec/reporting.py`, `docs/GOVERNANCE_STANDARD_GAPS.md` |
| ISO 9241-306 | Accessibility governance controls are currently partially represented via deterministic CLI output formats and explicit reason-code handling. | partial | `src/zksec/cli.py`, `tests/test_cli.py`, `docs/GOVERNANCE_STANDARD_GAPS.md` |
| ISO 24505 | Compliance controls are partially represented by milestone acceptance checks and evidence links. | partial | `TODO.md`, `docs/MILESTONE_07.md`, `docs/MILESTONE_09.md` |
| ISO 22727 | Information assurance controls are partial via strict syscall restrictions and execution gating, with additional formal controls pending. | partial | `tests/test_syscall_guard.py`, `src/zksec/execution.py`, `docs/GOVERNANCE_STANDARD_GAPS.md` |
| NIST AI RMF | Partial mapping via action-risk policy, bounded source trust, proposal-only semantic ingestion, detector outputs, and receipt-backed execution checks. | partial | `src/zksec/security.py`, `src/zksec/routing.py`, `src/zksec/admissibility.py`, `src/zksec/execution.py`, `tests/test_security.py`, `tests/test_admissibility.py` |
| Six Sigma | Quality control metrics are partially present via full automated pass counts, explicit detector defect classes, and attack-chain/blocking tests; DMAIC-style process controls are pending. | partial | `docs/MILESTONE_07.md`, `docs/MILESTONE_12.md`, `TODO.md`, `tests/` |
| C4 | C4-style decomposition is implemented with separate formalized control/container/context views. | implemented | `docs/uml/zksec-c4-architecture.puml`, `docs/uml/zksec-c4-architecture.svg` |
| PlantUML | Control architecture PlantUML artifact exists and is rendered as SVG. | implemented | `docs/uml/zksec-control-architecture.puml`, `docs/uml/zksec-control-architecture.svg` |

## Milestone-to-Evidence Index

- `src/` behavior controls are documented in milestone files `docs/MILESTONE_02.md` through `docs/MILESTONE_12.md`.
- Test evidence is in `tests/` and grouped by milestone in the same files.
- Runtime-style hardening artifacts and external references are in `docs/MILESTONE_07.md` and `docs/DEPENDENCIES.md`.

## Maintenance Rule

- When controls or references are updated, keep `TODO.md`, `README.md`, and `CHANGELOG.md` aligned with the same evidence pointers.
