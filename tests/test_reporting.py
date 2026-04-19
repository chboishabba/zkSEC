from zksec import AdapterExecutionDirective, execution_audit_record


def test_execution_audit_record_has_required_fields() -> None:
    directive = AdapterExecutionDirective(
        adapter="zos_server",
        action="read",
        status="ready",
        command="sandbox://ops@zos_server/read",
        reason_code="execution_ready",
        reason_message="Execution command is ready and policy checks passed.",
        requested_capabilities="artifact_view",
        requested_channel="confirmed",
        requested_ring="bounded",
        requested_destination="local",
        receipt={
            "action": "read",
            "actor": "ops",
            "source": "../zos-server",
            "decision": "allow",
            "reason_code": "policy_allow",
            "reason_message": "Action passed declared policy and trust checks",
        },
    )
    record = execution_audit_record(operator="ops", directive=directive)
    assert record["operator"] == "ops"
    assert record["adapter"] == "zos_server"
    assert record["execution_status"] == "ready"
    assert record["command"] == "sandbox://ops@zos_server/read"


def test_execution_audit_record_carries_mu_exec_fields() -> None:
    directive = AdapterExecutionDirective(
        adapter="zos_server",
        action="read",
        status="ready",
        command="sandbox://ops@zos_server/read",
        reason_code="execution_ready",
        reason_message="Execution command is ready and policy checks passed.",
        requested_capabilities="artifact_view",
        requested_channel="confirmed",
        requested_ring="bounded",
        requested_destination="local",
        receipt={
            "action": "read",
            "actor": "ops",
            "source": "../zos-server",
            "decision": "allow",
            "reason_code": "policy_allow",
            "reason_message": "Action passed declared policy and trust checks",
            "mu_exec_state": "grounded",
            "mu_exec_grounding_basis": "ghidra_ir,cfg",
            "mu_exec_invariant_codes": "",
            "mu_exec_reason_codes": "",
            "mu_exec_summary": "grounded copy path",
        },
    )
    record = execution_audit_record(operator="ops", directive=directive)
    assert record["mu_exec_state"] == "grounded"
    assert record["mu_exec_grounding_basis"] == "ghidra_ir,cfg"
    assert record["mu_exec_summary"] == "grounded copy path"
