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
    receipt: dict[str, str]


def build_execution_directive(
    *,
    routed: RoutedActionDecision,
    operator: str,
    environment: str = "sandbox",
) -> AdapterExecutionDirective:
    """Convert a routing decision into a bounded execution descriptor."""

    command = None
    status: ExecutionStatus

    if routed.status == "deny":
        status = "blocked"
        reason_code = routed.reason_code
        reason_message = routed.reason_message
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
        receipt=routed.receipt,
    )

