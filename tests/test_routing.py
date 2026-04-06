from zksec import RoutedActionDecision, evaluate_adapter_action


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
        source="managed",
        risk_level="low",
    )
    assert decision.status == "deny"
    assert decision.reason_code == "adapter_action_blocked"
