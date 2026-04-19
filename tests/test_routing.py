from dataclasses import replace

from zksec import (
    RoutedActionDecision,
    build_mu_exec_witness,
    evaluate_adapter_action,
    evaluate_mu_exec_invariants,
)
from zksec.adapters import (
    AdapterCapabilityPolicy,
    AdapterContract,
    zos_server_contract,
)


def _remote_read_contract() -> AdapterContract:
    base = zos_server_contract()
    profiles = list(base.action_capability_policies.action_profiles)
    read_profile = next(item for item in profiles if item.action == "read")
    read_profile = replace(
        read_profile,
        rings=("sovereign", "bounded", "remote"),
        transforms=("read",),
    )
    policy = AdapterCapabilityPolicy(
        action_profiles=tuple(
            read_profile if item.action == "read" else item for item in profiles
        )
    )
    return replace(
        base,
        allowed_rings=("sovereign", "bounded", "remote"),
        action_capability_policies=policy,
    )


def test_unknown_adapter_is_denied() -> None:
    decision = evaluate_adapter_action(
        adapter_name="mystery_adapter",
        action="read",
        actor_role="operator",
        source="managed",
    )
    assert isinstance(decision, RoutedActionDecision)
    assert decision.status == "deny"
    assert decision.reason_code == "unknown_adapter"


def test_public_high_impact_deploy_is_denied_for_known_adapter() -> None:
    decision = evaluate_adapter_action(
        adapter_name="zos_server",
        action="deploy",
        actor_role="operator",
        actor_identity="ops-123",
        scope="sandbox",
        plan_ref="plan-2026-04-07",
        source="public",
        risk_level="high",
    )
    assert decision.status == "deny"
    assert decision.reason_code == "proposal_from_public_source"
    assert decision.security_decision.decision == "deny"


def test_high_risk_requires_confirmation_for_allowed_adapter_action() -> None:
    decision = evaluate_adapter_action(
        adapter_name="zos_server",
        action="patch",
        actor_role="operator",
        actor_identity="ops-123",
        scope="sandbox",
        plan_ref="plan-2026-04-07",
        source="managed",
        risk_level="high",
        confirmed=False,
    )
    assert decision.status == "requires_confirmation"
    assert decision.reason_code == "requires_confirmation"


def test_adapter_disallows_action_outside_contract() -> None:
    decision = evaluate_adapter_action(
        adapter_name="kant_zk_pastebin",
        action="remediate",
        actor_role="operator",
        actor_identity="ops-123",
        scope="sandbox",
        plan_ref="plan-2026-04-07",
        source="managed",
        risk_level="low",
    )
    assert decision.status == "deny"
    assert decision.reason_code == "adapter_action_blocked"


def test_known_adapter_high_authority_without_plan_receipt_is_denied() -> None:
    decision = evaluate_adapter_action(
        adapter_name="zos_server",
        action="deploy",
        actor_role="operator",
        actor_identity="ops-123",
        scope="sandbox",
        plan_ref="",
        source="managed",
        risk_level="high",
        confirmed=True,
    )
    assert decision.status == "deny"
    assert decision.reason_code == "missing_plan_receipt"


def test_read_with_out_of_bounds_resource_is_denied() -> None:
    decision = evaluate_adapter_action(
        adapter_name="zos_server",
        action="read",
        actor_role="operator",
        actor_identity="ops-123",
        scope="sandbox",
        plan_ref="plan-2026-04-07",
        resource="../outside/zone",
        source="managed",
        risk_level="low",
    )
    assert decision.status == "deny"
    assert decision.reason_code == "resource_scope_out_of_bounds"


def test_read_with_authorized_resource_is_allowed() -> None:
    decision = evaluate_adapter_action(
        adapter_name="zos_server",
        action="read",
        actor_role="operator",
        actor_identity="ops-123",
        scope="sandbox",
        plan_ref="plan-2026-04-07",
        resource="../zos-server/contracts/adapter.md",
        source="managed",
        risk_level="low",
    )
    assert decision.status == "allow"


def test_read_with_secret_payload_is_blocked() -> None:
    decision = evaluate_adapter_action(
        adapter_name="zos_server",
        action="read",
        actor_role="operator",
        actor_identity="ops-123",
        scope="sandbox",
        plan_ref="plan-2026-04-07",
        request_payload="payload: AKIAABCDEFGHIJKLMNOP",
        source="managed",
        risk_level="low",
    )
    assert decision.status == "deny"
    assert decision.reason_code == "secret_material_detected"


def test_same_action_with_remote_publish_capability_is_denied() -> None:
    decision = evaluate_adapter_action(
        adapter_name="zos_server",
        action="read",
        actor_role="operator",
        actor_identity="ops-123",
        scope="sandbox",
        plan_ref="plan-2026-04-07",
        requested_capabilities=("artifact_publish",),
        source="managed",
        risk_level="low",
    )
    assert decision.status == "deny"
    assert decision.reason_code == "capability_widening_detected"
    assert decision.requested_capabilities == ("artifact_publish",)


def test_same_action_with_remote_channel_widening_is_denied() -> None:
    decision = evaluate_adapter_action(
        adapter_name="zos_server",
        action="review",
        actor_role="operator",
        actor_identity="ops-123",
        scope="sandbox",
        plan_ref="plan-2026-04-07",
        requested_channel="autonomous",
        source="managed",
        risk_level="low",
    )
    assert decision.status == "deny"
    assert decision.reason_code == "channel_widening_detected"


def test_capability_expansion_relative_to_previous_state_is_detected() -> None:
    decision = evaluate_adapter_action(
        adapter_name="zos_server",
        action="read",
        actor_role="operator",
        actor_identity="ops-2026",
        scope="sandbox",
        plan_ref="plan-2026-04-07",
        source="managed",
        risk_level="low",
        requested_capabilities=("read", "write"),
        previous_capabilities=("read",),
    )
    assert decision.status == "deny"
    assert decision.reason_code == "capability_expansion_detected"


def test_transform_drift_is_detected_for_action_profile() -> None:
    decision = evaluate_adapter_action(
        adapter_name="zos_server",
        action="read",
        actor_role="operator",
        actor_identity="ops-2026",
        scope="sandbox",
        plan_ref="plan-2026-04-07",
        requested_transform="transform",
        source="managed",
        risk_level="low",
    )
    assert decision.status == "deny"
    assert decision.reason_code == "transform_drift_detected"


def test_structural_anomaly_is_detected() -> None:
    decision = evaluate_adapter_action(
        adapter_name="zos_server",
        action="read",
        actor_role="operator",
        actor_identity="ops-2026",
        scope="sandbox",
        plan_ref="plan-2026-04-07",
        resource="../zos-server/contracts/adapter.md",
        source="managed",
        risk_level="low",
        requested_artifact_state="zos_server:read:contracts/adapter.md@v1",
        previous_artifact_state="zos_server:read:contracts/adapter.md@v0",
    )
    assert decision.status == "deny"
    assert decision.reason_code == "structural_anomaly_detected"


def test_remote_ring_requires_explicitly_declared_ring() -> None:
    decision = evaluate_adapter_action(
        adapter_name="kant_zk_pastebin",
        action="read",
        actor_role="operator",
        actor_identity="ops-123",
        scope="sandbox",
        plan_ref="plan-2026-04-07",
        requested_ring="remote",
        source="managed",
        risk_level="low",
    )
    assert decision.status == "deny"
    assert decision.reason_code == "ring_widening_detected"


def test_ring_escalation_detected() -> None:
    decision = evaluate_adapter_action(
        adapter_name="zos_server",
        action="read",
        actor_role="operator",
        actor_identity="ops-2026",
        scope="sandbox",
        plan_ref="plan-2026-04-07",
        source="managed",
        risk_level="low",
        requested_ring="bounded",
        previous_ring="sovereign",
    )
    assert decision.status == "deny"
    assert decision.reason_code == "ring_escalation_detected"


def test_channel_escalation_from_self_to_remote_api() -> None:
    decision = evaluate_adapter_action(
        adapter_name="zos_server",
        action="read",
        actor_role="operator",
        actor_identity="ops-2026",
        scope="sandbox",
        plan_ref="plan-2026-04-07",
        source="managed",
        risk_level="low",
        requested_channel="confirmed",
        previous_source_channel="local",
    )
    assert decision.status == "deny"
    assert decision.reason_code == "channel_escalation_detected"


def test_structural_hash_bookkeeping_is_reflected_in_receipt() -> None:
    decision = evaluate_adapter_action(
        adapter_name="kant_zk_pastebin",
        action="read",
        actor_role="operator",
        actor_identity="ops-2026",
        scope="sandbox",
        plan_ref="plan-2026-04-07",
        source="managed",
        risk_level="low",
        requested_artifact_state="kant:read:state",
        requested_artifact_hash="hash-a",
        previous_artifact_hash="hash-b",
    )
    assert decision.status == "allow"
    assert decision.receipt["requested_artifact_hash"] == "hash-a"
    assert decision.receipt["previous_artifact_hash"] == "hash-b"
    assert decision.receipt["artifact_hash_delta"] == "changed"


def test_read_with_undeclared_destination_is_denied() -> None:
    decision = evaluate_adapter_action(
        adapter_name="zos_server",
        action="read",
        actor_role="operator",
        actor_identity="ops-2026",
        scope="sandbox",
        plan_ref="plan-2026-04-07",
        requested_destination="public",
        source="managed",
        risk_level="low",
    )
    assert decision.status == "deny"
    assert decision.reason_code == "destination_widening_detected"


def test_routing_carries_grounded_mu_exec_receipt_fields() -> None:
    witness = evaluate_mu_exec_invariants(
        witness=build_mu_exec_witness(
            proposal_sources=("strace",),
            grounding_basis=("ghidra_ir",),
            interaction_shape=("copy",),
            summary="grounded copy path",
        )
    )
    decision = evaluate_adapter_action(
        adapter_name="zos_server",
        action="read",
        actor_role="operator",
        actor_identity="ops-2026",
        scope="sandbox",
        plan_ref="plan-2026-04-07",
        source="managed",
        risk_level="low",
        mu_exec_witness=witness,
    )
    assert decision.status == "allow"
    assert decision.mu_exec_state == "grounded"
    assert decision.receipt["mu_exec_grounding_basis"] == "ghidra_ir"
    assert decision.receipt["mu_exec_state"] == "grounded"


def test_routing_keeps_proposal_only_mu_exec_non_authoritative() -> None:
    witness = build_mu_exec_witness(
        proposal_sources=("strace", "zkperf"),
        interaction_shape=("copy",),
        summary="trace proposal only",
    )
    decision = evaluate_adapter_action(
        adapter_name="zos_server",
        action="read",
        actor_role="operator",
        actor_identity="ops-2026",
        scope="sandbox",
        plan_ref="plan-2026-04-07",
        source="managed",
        risk_level="low",
        mu_exec_witness=witness,
    )
    assert decision.status == "requires_confirmation"
    assert decision.mu_exec_state == "proposal_only"
    assert decision.receipt["mu_exec_proposal_sources"] == "strace,zkperf"
    assert decision.reason_code == "mu_exec_grounding_required"


def test_remote_payload_minimization_is_enforced(monkeypatch: object) -> None:
    monkeypatch.setattr(
        "zksec.routing._resolve_adapter",
        lambda _: _remote_read_contract(),
    )
    decision = evaluate_adapter_action(
        adapter_name="zos_server",
        action="read",
        actor_role="operator",
        actor_identity="ops-2026",
        scope="sandbox",
        plan_ref="plan-2026-04-07",
        source="managed",
        request_payload="raw payload data",
        requested_ring="remote",
        risk_level="low",
        payload_sanitized=False,
    )
    assert decision.status == "deny"
    assert decision.reason_code == "unsanitized_remote_request"


def test_remote_payload_minimization_allows_sanitized_payload(monkeypatch: object) -> None:
    monkeypatch.setattr(
        "zksec.routing._resolve_adapter",
        lambda _: _remote_read_contract(),
    )
    decision = evaluate_adapter_action(
        adapter_name="zos_server",
        action="read",
        actor_role="operator",
        actor_identity="ops-2026",
        scope="sandbox",
        plan_ref="plan-2026-04-07",
        source="managed",
        request_payload="raw payload data",
        requested_ring="remote",
        risk_level="low",
        payload_sanitized=True,
    )
    assert decision.status == "allow"
