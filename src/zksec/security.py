"""Minimal security gate primitives for zkSEC."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Literal

SourceTrust = Literal["managed", "public"]
RiskLevel = Literal["low", "medium", "high"]


@dataclass(frozen=True)
class SecurityDecision:
    """Result of a security gate evaluation."""

    action: str
    decision: str
    reason_code: str
    reason_message: str


_MANAGED = {
    "plan": "low",
    "review": "low",
    "read": "low",
    "collect": "low",
    "deploy": "high",
    "remediate": "high",
    "patch": "high",
}


def assess_action(
    *,
    action: str,
    actor_role: str,
    source: SourceTrust,
    risk_level: RiskLevel = "low",
    confirmed: bool = False,
) -> SecurityDecision:
    """
    Evaluate whether an action can proceed.

    Rules:
    - unknown actions are denied
    - public-source high-impact actions are denied as proposals
    - high-risk actions require confirmation
    - all other known managed actions are allowed
    """

    if action not in _MANAGED:
        return SecurityDecision(
            action=action,
            decision="deny",
            reason_code="unknown_action",
            reason_message=f"action '{action}' is not in the managed action catalog",
        )

    if source == "public" and _MANAGED[action] == "high":
        return SecurityDecision(
            action=action,
            decision="deny",
            reason_code="proposal_from_public_source",
            reason_message=(
                "Public discovery sources can raise findings but cannot authorize"
                " high-impact actions directly."
            ),
        )

    if action not in {"read", "collect", "review", "plan"} and actor_role == "anonymous":
        return SecurityDecision(
            action=action,
            decision="deny",
            reason_code="unauthenticated_actor",
            reason_message="anonymous actor cannot perform managed actions",
        )

    if risk_level == "high" and not confirmed:
        return SecurityDecision(
            action=action,
            decision="requires_confirmation",
            reason_code="requires_confirmation",
            reason_message="High-risk action requires explicit operator confirmation",
        )

    return SecurityDecision(
        action=action,
        decision="allow",
        reason_code="policy_allow",
        reason_message="Action passed declared policy and trust checks",
    )


def policy_receipt(decision: SecurityDecision, *, actor: str, source_ref: str) -> Dict[str, str]:
    """Return a lightweight audit receipt payload."""
    return {
        "action": decision.action,
        "actor": actor,
        "source": source_ref,
        "decision": decision.decision,
        "reason_code": decision.reason_code,
        "reason_message": decision.reason_message,
    }
