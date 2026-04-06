# Milestone 05: Audit Reporting Surface

## Objective
Add a lightweight reporting helper to produce deterministic audit records for
execution directives so downstream systems can track operator and policy lineage.

## Concrete Files
- `src/zksec/reporting.py`
- `tests/test_reporting.py`
- `src/zksec/__init__.py`
- `TODO.md`
- `CHANGELOG.md`

## Acceptance Checks
1. `execution_audit_record` accepts an execution directive and emits a stable map.
2. Audit payload includes operator, adapter, action, execution status, reason, and command.
3. Helper is importable from package root and tested.
