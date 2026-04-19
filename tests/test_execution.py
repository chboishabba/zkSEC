from zksec import AdapterExecutionDirective, RoutedActionDecision, SecurityDecision, build_execution_directive
from zksec import evaluate_adapter_action


def test_execute_pipeline_blocks_unknown_adapter() -> None:
    route = evaluate_adapter_action(
        adapter_name="mystery",
        action="read",
        actor_role="operator",
        source="managed",
    )
    directive = build_execution_directive(routed=route, operator="ops")
    assert isinstance(directive, AdapterExecutionDirective)
    assert directive.status == "blocked"
    assert directive.command is None


def test_execute_pipeline_requires_confirmation() -> None:
    route = evaluate_adapter_action(
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
    directive = build_execution_directive(routed=route, operator="ops")
    assert directive.status == "requires_confirmation"
    assert directive.command == "sandbox://ops@zos_server/patch"


def test_execute_pipeline_ready_when_allowed() -> None:
    route = evaluate_adapter_action(
        adapter_name="kant_zk_pastebin",
        action="read",
        actor_role="operator",
        actor_identity="ops-123",
        scope="sandbox",
        plan_ref="plan-2026-04-07",
        source="managed",
        risk_level="low",
    )
    directive = build_execution_directive(routed=route, operator="ops")
    assert directive.status == "ready"
    assert directive.command == "sandbox://ops@kant_zk_pastebin/read"
    assert directive.reason_code == "execution_ready"


def test_execute_pipeline_blocks_ready_decision_without_execution_receipt() -> None:
    routed = RoutedActionDecision(
        adapter="zos_server",
        action="deploy",
        status="allow",
        reason_code="policy_allow",
        reason_message="policy allow",
        security_decision=SecurityDecision(
            action="deploy",
            decision="allow",
            reason_code="policy_allow",
            reason_message="policy allow",
        ),
        adapter_check=None,
        capability_profile=None,
        requested_capabilities=("artifact_sync",),
        requested_channel="confirmed",
        requested_ring="bounded",
        requested_destination="peer",
        receipt={
            "scope": "",
            "plan_ref": "",
            "actor_identity": "",
        },
    )
    directive = build_execution_directive(
        routed=routed,
        operator="ops",
    )
    assert directive.status == "blocked"
    assert directive.reason_code == "execution_receipt_precondition_failed"
