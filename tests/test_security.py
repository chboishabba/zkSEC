from zksec import SecurityDecision, assess_action, assess_data_boundary


def test_unknown_action_denied() -> None:
    decision = assess_action(
        action="delete_all",
        actor_role="operator",
        source="managed",
        risk_level="low",
    )
    assert decision.decision == "deny"
    assert decision.reason_code == "unknown_action"


def test_public_proposal_is_denied() -> None:
    decision = assess_action(
        action="deploy",
        actor_role="operator",
        source="public",
        risk_level="high",
    )
    assert decision.decision == "deny"
    assert decision.reason_code == "proposal_from_public_source"


def test_high_risk_requires_confirmation() -> None:
    decision = assess_action(
        action="patch",
        actor_role="operator",
        actor_identity="ops-123",
        scope="sandbox",
        plan_ref="plan-2026-04-07",
        source="managed",
        risk_level="high",
        confirmed=False,
    )
    assert decision.decision == "requires_confirmation"
    assert decision.reason_code == "requires_confirmation"


def test_high_authority_requires_actor_identity() -> None:
    decision = assess_action(
        action="deploy",
        actor_role="operator",
        actor_identity="",
        scope="sandbox",
        plan_ref="plan-2026-04-07",
        source="managed",
        risk_level="high",
        confirmed=False,
    )
    assert decision.decision == "deny"
    assert decision.reason_code == "missing_actor_identity"


def test_high_authority_requires_scope_and_plan_receipt() -> None:
    decision = assess_action(
        action="deploy",
        actor_role="operator",
        actor_identity="ops-123",
        scope="",
        plan_ref="",
        source="managed",
        risk_level="medium",
        confirmed=True,
    )
    assert decision.decision == "deny"
    assert decision.reason_code == "missing_scope"


def test_anonymous_is_denied_for_managed_action() -> None:
    decision = assess_action(
        action="patch",
        actor_role="anonymous",
        source="managed",
        risk_level="low",
    )
    assert decision.decision == "deny"
    assert decision.reason_code == "unauthenticated_actor"


def test_data_boundary_denies_unknown_resource_scope_for_adapter() -> None:
    decision = assess_data_boundary(
        action="read",
        adapter="zos_server",
        resource="../unknown/path.conf",
        request_payload=None,
        allowed_resource_roots=("../zos-server", "../ipfs-dasl"),
    )
    assert decision is not None
    assert decision.decision == "deny"
    assert decision.reason_code == "resource_scope_out_of_bounds"


def test_data_boundary_denies_path_traversal_out_of_bounds() -> None:
    decision = assess_data_boundary(
        action="read",
        adapter="zos_server",
        resource="../zos-server/../../outside/zone",
        request_payload=None,
        allowed_resource_roots=("../zos-server", "../ipfs-dasl"),
    )
    assert decision is not None
    assert decision.decision == "deny"
    assert decision.reason_code == "resource_scope_out_of_bounds"


def test_data_boundary_detects_secret_patterns_in_payload() -> None:
    decision = assess_data_boundary(
        action="read",
        adapter="zos_server",
        resource="../zos-server/config/map.conf",
        request_payload="candidate: AKIAABCDEFGHIJKLMNOP",
        allowed_resource_roots=("../zos-server",),
    )
    assert decision is not None
    assert decision.decision == "deny"
    assert decision.reason_code == "secret_material_detected"
