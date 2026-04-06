# Milestone 06: CLI Flow and Integration Harness

## Objective
Provide a command-line entrypoint and deterministic end-to-end integration verification for
routing, execution, and reporting decisions.

## Concrete Files
- `src/zksec/cli.py`
- `src/zksec/__main__.py`
- `tests/test_cli.py`
- `tests/test_integration.py`
- `TODO.md`
- `CHANGELOG.md`

## Acceptance Checks
1. CLI accepts adapter/action/source/risk/confirmation inputs.
2. CLI exits with status:
   - `0` for `ready`
   - `2` for `requires_confirmation`
   - `3` for `blocked`
3. JSON output includes `adapter`, `action`, `execution_status`, `reason_code`, and `command`.
4. At least one integration-style test validates full routing->execution->reporting behavior.
