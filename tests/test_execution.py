from zksec import AdapterExecutionDirective, build_execution_directive
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
        source="managed",
        risk_level="low",
    )
    directive = build_execution_directive(routed=route, operator="ops")
    assert directive.status == "ready"
    assert directive.command == "sandbox://ops@kant_zk_pastebin/read"
    assert directive.reason_code == "execution_ready"
