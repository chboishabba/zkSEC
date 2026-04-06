from zksec.security import SecurityDecision, assess_action


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
        source="managed",
        risk_level="high",
        confirmed=False,
    )
    assert decision.decision == "requires_confirmation"
    assert decision.reason_code == "requires_confirmation"


def test_anonymous_is_denied_for_managed_action() -> None:
    decision = assess_action(
        action="patch",
        actor_role="anonymous",
        source="managed",
        risk_level="low",
    )
    assert decision.decision == "deny"
    assert decision.reason_code == "unauthenticated_actor"
