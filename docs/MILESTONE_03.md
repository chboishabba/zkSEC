# Milestone 03: Adapter-Aware Routing

## Objective
Create a single routing step that combines security gate decisions and adjacent-adapter action contracts before any execution path.

## Concrete Files
- `src/zksec/routing.py`
- `src/zksec/__init__.py`
- `tests/test_routing.py`
- `TODO.md`
- `COMPACTIFIED_CONTEXT.md`
- `CHANGELOG.md`

## Acceptance Checks
1. `evaluate_adapter_action` resolves known adapters from explicit contracts.
2. Unknown adapters return a blocked decision with `unknown_adapter` reason code.
3. Public high-impact action is denied before execution.
4. High-risk managed action that is adapter-allowed returns `requires_confirmation`.
5. Adapter-disallowed action returns a blocked decision with `adapter_action_blocked`.
