# TODO

## Initialization
- [x] Initialize git repository for `zkSEC`.
- [x] Create compact context with canonical thread metadata.
- [x] Add project README with operating rules.
- [x] Create changelog.

## Milestone 01: Project Skeleton + Baseline Interfaces
- [x] `docs/DEPENDENCIES.md`: record and justify adjacent relevant surfaces.
- [x] `docs/MILESTONE_01.md`: define objective, concrete files, and acceptance checks.
- [x] `src/zksec/__init__.py`: expose baseline public interface.
- [x] `src/zksec/context.py`: provide security context and known surface declarations.
- [x] `tests/test_context.py`: validate baseline interface and adjacent surface list.
- [x] Run `PYTHONPATH=src pytest -q` and record result (`3 passed`).

## Milestone 02: Security Gate Foundation
- [x] `docs/MILESTONE_02.md`: define priority and acceptance checks.
- [x] `src/zksec/security.py`: define `SecurityDecision`, `assess_action`, and `policy_receipt`.
- [x] `src/zksec/__init__.py`: expose security gate API.
- [x] `tests/test_security.py`: validate gate invariants and core blocks.
- [x] `src/zksec/adapters/contracts.py`: define `zos_server_contract` and `kant_zk_pastebin_contract`.
- [x] `src/zksec/adapters/__init__.py`: export adapter contracts and check helpers.
- [x] `tests/test_adapters.py`: validate adapter contract behavior.

## Milestone 03: Adapter-Aware Routing
- [x] `docs/MILESTONE_03.md`: define objective, concrete files, and acceptance checks.
- [x] `src/zksec/routing.py`: add `evaluate_adapter_action`.
- [x] `tests/test_routing.py`: validate adapter/security interaction checks.
- [x] `src/zksec/__init__.py`: expose routing API.

## Milestone 04: Execution Directive Boundary
- [x] `docs/MILESTONE_04.md`: define objective, concrete files, and acceptance checks.
- [x] `src/zksec/execution.py`: add adapter execution directive abstraction.
- [x] `tests/test_execution.py`: validate blocked/confirm/ready transition behavior.
- [x] `src/zksec/__init__.py`: expose execution API.

## Milestone 05: Audit Reporting Surface
- [x] `docs/MILESTONE_05.md`: define objective, concrete files, and acceptance checks.
- [x] `src/zksec/reporting.py`: add deterministic audit payload helper.
- [x] `tests/test_reporting.py`: validate audit payload shape.
- [x] `src/zksec/__init__.py`: expose reporting API.

## Milestone 06: CLI Flow and Integration Harness
- [x] `docs/MILESTONE_06.md`: define objective, concrete files, and acceptance checks.
- [x] `src/zksec/cli.py`: add command-line evaluator.
- [x] `src/zksec/__main__.py`: wire module execution path.
- [x] `tests/test_cli.py`: validate CLI status and output behavior.
- [x] `tests/test_integration.py`: validate routing→execution→reporting flow.
