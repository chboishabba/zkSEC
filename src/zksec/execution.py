"""Bounded execution directives derived from routing decisions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .routing import RoutedActionDecision


ExecutionStatus = Literal["blocked", "requires_confirmation", "ready"]


@dataclass(frozen=True)
class AdapterExecutionDirective:
    """Execution-ready view of a routed action."""

    adapter: str
    action: str
    status: ExecutionStatus
    command: str | None
    reason_code: str
    reason_message: str
    requested_capabilities: str
    requested_channel: str
    requested_ring: str
    requested_destination: str
    receipt: dict[str, str]


def build_execution_directive(
    *,
    routed: RoutedActionDecision,
    operator: str,
    environment: str = "sandbox",
) -> AdapterExecutionDirective:
    """Convert a routing decision into a bounded execution descriptor."""

    high_authority_actions = {"deploy", "patch", "remediate"}
    receipt_scope = routed.receipt.get("scope", "").strip()
    receipt_plan = routed.receipt.get("plan_ref", "").strip()
    receipt_actor = routed.receipt.get("actor_identity", "").strip()

    command = None
    status: ExecutionStatus

    if routed.status == "deny":
        status = "blocked"
        reason_code = routed.reason_code
        reason_message = routed.reason_message
    elif routed.security_decision.action in high_authority_actions and (
        not receipt_scope or not receipt_plan or not receipt_actor
    ):
        status = "blocked"
        reason_code = "execution_receipt_precondition_failed"
        reason_message = (
            "High-authority execution must include actor_identity, scope, and plan_ref in receipt"
        )
        return AdapterExecutionDirective(
            adapter=routed.adapter,
            action=routed.action,
            status=status,
            command=None,
            reason_code=reason_code,
            reason_message=reason_message,
            requested_capabilities=",".join(routed.requested_capabilities),
            requested_channel=routed.requested_channel,
            requested_ring=routed.requested_ring,
            requested_destination=routed.requested_destination,
            receipt=routed.receipt,
        )

    else:
        command = f"{environment}://{operator}@{routed.adapter}/{routed.action}"

        if routed.status == "requires_confirmation":
            status = "requires_confirmation"
            reason_code = routed.reason_code
            reason_message = routed.reason_message
        else:
            status = "ready"
            reason_code = "execution_ready"
            reason_message = "Execution command is ready and policy checks passed."

    return AdapterExecutionDirective(
        adapter=routed.adapter,
        action=routed.action,
        status=status,
        command=command,
        reason_code=reason_code,
        reason_message=reason_message,
        requested_capabilities=",".join(routed.requested_capabilities),
        requested_channel=routed.requested_channel,
        requested_ring=routed.requested_ring,
        requested_destination=routed.requested_destination,
        receipt=routed.receipt,
    )
