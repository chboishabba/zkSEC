"""Evaluation routing for adapter-bound actions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .adapters import (
    AdapterContract,
    AdapterCheckResult,
    kant_zk_pastebin_contract,
    validate_action_against_adapter,
    zos_server_contract,
)
from .security import RiskLevel, SecurityDecision, SourceTrust, assess_action, policy_receipt


ActionResult = Literal["allow", "deny", "requires_confirmation"]


@dataclass(frozen=True)
class RoutedActionDecision:
    """Result of adapter-aware security routing."""

    adapter: str
    action: str
    status: ActionResult
    reason_code: str
    reason_message: str
    security_decision: SecurityDecision
    adapter_check: AdapterCheckResult | None
    receipt: dict[str, str]


def _resolve_adapter(name: str) -> AdapterContract | None:
    if name == "zos_server":
        return zos_server_contract()
    if name == "kant_zk_pastebin":
        return kant_zk_pastebin_contract()
    return None


def evaluate_adapter_action(
    *,
    adapter_name: str,
    action: str,
    actor_role: str,
    source: SourceTrust,
    risk_level: RiskLevel = "low",
    confirmed: bool = False,
) -> RoutedActionDecision:
    """Return a deterministic routing decision for a candidate adapter action."""

    adapter = _resolve_adapter(adapter_name)
    if adapter is None:
        security_decision = SecurityDecision(
            action=action,
            decision="deny",
            reason_code="unknown_adapter",
            reason_message=f"No adapter contract registered for '{adapter_name}'",
        )
        return RoutedActionDecision(
            adapter=adapter_name,
            action=action,
            status="deny",
            reason_code=security_decision.reason_code,
            reason_message=security_decision.reason_message,
            security_decision=security_decision,
            adapter_check=None,
            receipt=policy_receipt(security_decision, actor=actor_role, source_ref=adapter_name),
        )

    security_decision = assess_action(
        action=action,
        actor_role=actor_role,
        source=source,
        risk_level=risk_level,
        confirmed=confirmed,
    )

    if security_decision.decision == "deny":
        return RoutedActionDecision(
            adapter=adapter.name,
            action=action,
            status="deny",
            reason_code=security_decision.reason_code,
            reason_message=security_decision.reason_message,
            security_decision=security_decision,
            adapter_check=None,
            receipt=policy_receipt(
                security_decision,
                actor=actor_role,
                source_ref=adapter.system_path,
            ),
        )

    adapter_check = validate_action_against_adapter(adapter=adapter, action=action)

    if not adapter_check.allowed:
        return RoutedActionDecision(
            adapter=adapter.name,
            action=action,
            status="deny",
            reason_code=adapter_check.reason_code,
            reason_message=adapter_check.reason_message,
            security_decision=security_decision,
            adapter_check=adapter_check,
            receipt=policy_receipt(
                security_decision,
                actor=actor_role,
                source_ref=adapter.system_path,
            ),
        )

    if security_decision.decision == "requires_confirmation":
        return RoutedActionDecision(
            adapter=adapter.name,
            action=action,
            status="requires_confirmation",
            reason_code=security_decision.reason_code,
            reason_message=security_decision.reason_message,
            security_decision=security_decision,
            adapter_check=adapter_check,
            receipt=policy_receipt(
                security_decision,
                actor=actor_role,
                source_ref=adapter.system_path,
            ),
        )

    return RoutedActionDecision(
        adapter=adapter.name,
        action=action,
        status="allow",
        reason_code="policy_allow",
        reason_message="Adapter and policy checks passed.",
        security_decision=security_decision,
        adapter_check=adapter_check,
        receipt=policy_receipt(
            security_decision,
            actor=actor_role,
            source_ref=adapter.system_path,
        ),
    )
