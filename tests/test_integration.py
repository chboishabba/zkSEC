from zksec import evaluate_adapter_action
from zksec import build_execution_directive, execution_audit_record


def test_full_pipeline_integration_ready_path() -> None:
    routed = evaluate_adapter_action(
        adapter_name="zos_server",
        action="review",
        actor_role="operator",
        source="managed",
        risk_level="low",
    )
    directive = build_execution_directive(routed=routed, operator="ops", environment="sandbox")
    assert directive.status == "ready"
    assert directive.command == "sandbox://ops@zos_server/review"

    record = execution_audit_record(operator="ops", directive=directive)
    assert record["adapter"] == "zos_server"
    assert record["action"] == "review"
    assert record["execution_status"] == "ready"
    assert record["command"] == "sandbox://ops@zos_server/review"


def test_full_pipeline_integration_confirmation_path() -> None:
    routed = evaluate_adapter_action(
        adapter_name="zos_server",
        action="deploy",
        actor_role="operator",
        actor_identity="ops-123",
        scope="sandbox",
        plan_ref="plan-2026-04-07",
        source="managed",
        risk_level="high",
        confirmed=False,
    )
    directive = build_execution_directive(routed=routed, operator="ops", environment="sandbox")
    assert directive.status == "requires_confirmation"
    record = execution_audit_record(operator="ops", directive=directive)
    assert record["execution_status"] == "requires_confirmation"


def test_full_pipeline_integration_block_path() -> None:
    routed = evaluate_adapter_action(
        adapter_name="kant_zk_pastebin",
        action="remediate",
        actor_role="operator",
        actor_identity="ops-123",
        scope="sandbox",
        plan_ref="plan-2026-04-07",
        source="managed",
        risk_level="low",
    )
    directive = build_execution_directive(routed=routed, operator="ops", environment="sandbox")
    assert directive.status == "blocked"
    record = execution_audit_record(operator="ops", directive=directive)
    assert record["execution_status"] == "blocked"
    assert record["reason_code"] == "adapter_action_blocked"
