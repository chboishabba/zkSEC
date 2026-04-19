# Milestone 11: Capability, Channel, and Ring Geometry

## Objective
Introduce explicit geometry constraints so zkSEC evaluates not only whether an
action is allowed, but whether the declared capability, channel, and destination
surface are admissible before execution readiness.

## Concrete Files
- `src/zksec/adapters/contracts.py`
- `src/zksec/routing.py`
- `src/zksec/cli.py`
- `src/zksec/execution.py`
- `src/zksec/reporting.py`
- `src/zksec/security.py`
- `tests/test_adapters.py`
- `tests/test_routing.py`
- `tests/test_cli.py`
- `TODO.md`

## Design
- Add explicit capability surfaces and per-action profiles to adapter contracts:
  - action capabilities
  - allowed channels (`proposal`, `confirmed`, `autonomous`)
  - allowed rings (`sovereign`, `bounded`, `remote`)
  - destination classes
- Add `evaluate_adapter_action` gating for:
  - capability widening (`capability_widening_detected`)
  - capability expansion against previous state (`capability_expansion_detected`)
  - transform drift (`transform_drift_detected`)
  - structural drift (`structural_anomaly_detected`)
  - channel widening (`channel_widening_detected`)
  - ring widening (`ring_widening_detected`)
  - destination widening (`destination_widening_detected`)
  - ring escalation (`ring_escalation_detected`)
- Add explicit remote-data minimization rejection (`unsanitized_remote_request`).
- Provide explicit geometry inputs at CLI level for explicit testable control and audit.
- Carry requested geometry fields into receipts and execution directives for deterministic evidence.
- Add placeholder structural hash bookkeeping fields for state-delta reasoning
  (`requested_artifact_hash`, `previous_artifact_hash`, `artifact_hash_delta`).

## Acceptance Checks
1. Routing blocks the same action with an undeclared capability and returns `capability_widening_detected`.
2. Routing blocks capability expansion compared to a prior state using `capability_expansion_detected`.
3. Routing blocks the same action with a ring/channel not declared for that action and returns `ring_widening_detected`/`channel_widening_detected`.
4. Routing blocks transform/structural drift with `transform_drift_detected`/`structural_anomaly_detected`.
5. Routing blocks the same adapter action when a destination class is outside declared geometry with `destination_widening_detected`.
6. CLI test surface proves geometry arguments are rejected with blocked status and evidence.
7. Routing blocks constrained ring widening from previous state using `ring_escalation_detected`.
8. Routing rejects unsanitized remote payloads using `unsanitized_remote_request`.
9. Audit payload includes geometry and structural hash metadata for downstream review.
