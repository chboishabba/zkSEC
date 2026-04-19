# Milestone 09: Data Boundary and Secret-Exfiltration Detection

## Objective
Introduce bounded request/resource validation for adapter actions so zkSEC blocks
out-of-scope reads and obvious secret-exfiltration signals before execution
is ever prepared.

## Concrete Files
- `src/zksec/adapters/contracts.py`
- `src/zksec/security.py`
- `src/zksec/routing.py`
- `src/zksec/cli.py`
- `src/zksec/__init__.py`
- `tests/test_adapters.py`
- `tests/test_security.py`
- `tests/test_routing.py`
- `tests/test_cli.py`
- `TODO.md`

## Design
- Extend each adapter contract with `resource_roots` that define the allowed
  filesystem or artifact scope for requests.
- Add `assess_data_boundary` to reject:
  - URI-like resource references (`scheme://`),
  - resources outside known adapter roots,
  - obvious secret-like token markers in request resource/payload.
- Keep decisions deterministic by returning explicit reason codes into the same
  routing/receipt path as existing policy checks.
- Add CLI passthrough fields so operators can trigger validation checks using
  `--resource` and `--request-payload`.

## Acceptance Checks
1. Known adapters expose at least one scoped root in contract metadata.
2. Routing denies resource access outside those scopes with reason
   `resource_scope_out_of_bounds`.
3. Routing denies suspicious secret/token signals with reason
   `secret_material_detected`.
4. CLI supports blocking `--resource`/`--request-payload` checks and exits with
   blocked status for detected violations.
