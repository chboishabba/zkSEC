# Milestone 01: Project Skeleton + Baseline Interfaces

## Objective
Establish a minimal, testable repository skeleton for `zkSEC` with explicit interfaces for:
- loading security context
- listing known adjacent dependency surfaces

## Concrete Files
- `docs/DEPENDENCIES.md`
- `docs/MILESTONE_01.md`
- `src/zksec/__init__.py`
- `src/zksec/context.py`
- `tests/test_context.py`

## Acceptance Checks
1. `src/zksec/context.py` defines:
- `SECURITY_CONTEXT_VERSION`
- `load_security_context()`
- `known_adjacent_surfaces()`

2. `tests/test_context.py` verifies:
- version exists and is non-empty
- `load_security_context()` returns expected keys
- `known_adjacent_surfaces()` contains the four primary relevant repos and `kant-zk-pastebin`

3. Current TODO milestone points directly to these files.
