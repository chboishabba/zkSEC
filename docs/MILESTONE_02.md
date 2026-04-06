# Milestone 02: Security Gate Foundation

## Priority
Align initial runtime behavior with ITIR security doctrine:
- proposals must not become authority from public sources
- consequential actions require managed/internal trust and explicit controls

## Concrete Files
- `src/zksec/security.py`
- `src/zksec/adapters/contracts.py`
- `src/zksec/adapters/__init__.py`
- `src/zksec/__init__.py`
- `tests/test_security.py`
- `tests/test_adapters.py`
- `TODO.md`
- `COMPACTIFIED_CONTEXT.md`
- `CHANGELOG.md`

## Design
- Add a single, explicit security gate API in `zksec/security.py`.
- Add bounded adapter contracts for adjacent systems.
- Represent decisions with explicit reason codes.
- Enforce core invariants in the gate:
  - public source findings remain proposals
  - high-risk managed actions require confirmation
  - unknown actions are denied

## Acceptance Checks
1. `SecurityDecision` and `assess_action` exist and return structured result.
2. Public-source `deploy`/`remediate` actions are denied.
3. High-risk managed actions move to `requires_confirmation`.
4. `TODO.md` marks Milestone 02 tasks as concrete and completed.
5. `src/zksec/adapters/contracts.py` defines bounded contracts for `../zos-server` and `../kant-zk-pastebin`.
6. Changelog records security gate and adapter-contract scaffolding.
