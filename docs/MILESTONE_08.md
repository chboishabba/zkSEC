# Milestone 08: Maintainer/Actor Integrity Boundaries

## Objective
Make proposal-only public/adaptive inputs impossible to become high-authority writes by
adding explicit actor/identity/scope/receipt preconditions before execution surfaces.

## Concrete Files
- `docs/DEPENDENCIES.md`
- `README.md`
- `TODO.md`
- `src/zksec/security.py`
- `src/zksec/routing.py`
- `src/zksec/execution.py`
- `tests/test_security.py`
- `tests/test_routing.py`
- `tests/test_execution.py`

## Design
- Keep existing boundary for `public` sources: they can emit candidate findings,
  follow obligations, and review recommendations.
- Add explicit lane checks that deny high-authority execution unless:
  - actor identity is verified,
  - identity/route is authorized for the target action,
  - receipts and plan references are present,
  - rollback and scope are explicit.
- Preserve explicit, auditable refusal messages that do not silently reinterpret
  authority for unexpected actor channels.

## Acceptance Checks
1. Security/router contract contains a bounded condition that `public`/`undercertain`
   signals never directly authorize `deploy`/`remediate`.
2. Execution tests cover untrusted actor and unauthorized scope paths as blocked states.
3. Existing execution readiness path remains intact when actor, scope, and receipts
   satisfy policy.
4. `TODO.md` marks this milestone as complete and no high-authority follow-up tasks
   remain in this surface.
