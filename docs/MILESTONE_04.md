# Milestone 04: Execution Directive Boundary

## Objective
Add a bounded execution layer that converts a routed action decision into a
safe, inspectable execution directive before any side effect would occur.

## Concrete Files
- `src/zksec/execution.py`
- `tests/test_execution.py`
- `src/zksec/__init__.py`
- `TODO.md`
- `CHANGELOG.md`

## Acceptance Checks
1. Unknown or denied route decisions return an execution directive with `blocked` status.
2. Confirm-required route decisions return `requires_confirmation` and include a command.
3. Allowed route decisions return `ready` with a deterministic command string.
4. New behavior is exported from package `__init__` and covered by tests.
