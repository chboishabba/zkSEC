# Changelog

## 2026-04-07
### Added
- Initialized git repository in `/home/c/Documents/code/zkSEC`.
- Added `COMPACTIFIED_CONTEXT.md` with resolved thread metadata:
  - title `LiteLLM hack analysis`
  - online UUID `69ce0ac6-dd2c-839f-8b84-a0d397285f90`
  - canonical thread ID `130c635a73d780dfb0552107cc0a77a77d4cfea9`
  - source `db` (after online UUID pull)
- Added `README.md` with repo operating rules.
- Added `TODO.md` with initialization and next-step tasks.
- Added `docs/DEPENDENCIES.md` and `docs/MILESTONE_01.md`.
- Added minimal project scaffold:
  - `src/zksec/__init__.py`
  - `src/zksec/context.py`
  - `tests/test_context.py`
- Added `.gitignore` for Python cache and bytecode artifacts.
- Added security gate scaffold:
  - `docs/MILESTONE_02.md`
  - `src/zksec/security.py`
  - `tests/test_security.py`
- Added adjacent adapter contracts:
  - `src/zksec/adapters/contracts.py`
  - `src/zksec/adapters/__init__.py`
  - `tests/test_adapters.py`
- Added adapter-aware routing implementation and tests:
  - `docs/MILESTONE_03.md`
  - `src/zksec/routing.py`
  - `tests/test_routing.py`
- Added execution gating and reporting milestones:
  - `docs/MILESTONE_04.md`
  - `src/zksec/execution.py`
  - `tests/test_execution.py`
  - `docs/MILESTONE_05.md`
  - `src/zksec/reporting.py`
  - `tests/test_reporting.py`
- Added CLI and integration harness:
  - `docs/MILESTONE_06.md`
  - `src/zksec/cli.py`
  - `src/zksec/__main__.py`
  - `tests/test_cli.py`
  - `tests/test_integration.py`

### Changed
- Updated `README.md` to include adjacent relevance scope and LiteLLM incident-context note.
- Updated `TODO.md` for Milestone 01 through Milestone 06 completion tracking.
- Updated `COMPACTIFIED_CONTEXT.md` with adjacent relevance decisions and ITIR security alignment.
