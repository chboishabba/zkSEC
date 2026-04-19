"""Minimal security gate primitives for zkSEC."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import re
from typing import Dict, Literal

SourceTrust = Literal["managed", "public"]
RiskLevel = Literal["low", "medium", "high"]


_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_pat_token", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z]{10,70}\b")),
    ("openai_secret", re.compile(r"\bsk-[A-Za-z0-9]{16,64}\b")),
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
)


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
    actor_identity: str | None = None,
    scope: str | None = None,
    plan_ref: str | None = None,
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

    is_high_authority = _MANAGED.get(action) == "high"
    if is_high_authority and source == "managed":
        if not actor_identity or not actor_identity.strip():
            return SecurityDecision(
                action=action,
                decision="deny",
                reason_code="missing_actor_identity",
                reason_message="High-authority actions require explicit actor identity",
            )
        if not scope or not scope.strip():
            return SecurityDecision(
                action=action,
                decision="deny",
                reason_code="missing_scope",
                reason_message="High-authority actions require explicit execution scope",
            )
        if not plan_ref or not plan_ref.strip():
            return SecurityDecision(
                action=action,
                decision="deny",
                reason_code="missing_plan_receipt",
                reason_message="High-authority actions require an explicit plan reference receipt",
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


def _payload_signature(payload: str) -> str:
    return sha256(payload.encode("utf-8")).hexdigest()[:20]


def _build_secret_scoped_probe(
    *,
    resource: str | None,
    request_payload: str | None,
) -> str:
    parts = [part for part in (resource, request_payload) if part]
    return " ".join(p for p in parts if p)


def _normalize_resource_scope(resource: str) -> str:
    """Normalize relative resource paths for deterministic scope checks."""
    parts: list[str] = []
    for segment in resource.split("/"):
        if not segment or segment == ".":
            continue
        if segment == "..":
            if parts and parts[-1] != "..":
                parts.pop()
            else:
                parts.append("..")
            continue
        parts.append(segment)
    return "/".join(parts)


def assess_data_boundary(
    *,
    action: str,
    adapter: str,
    resource: str | None,
    request_payload: str | None,
    allowed_resource_roots: tuple[str, ...],
) -> SecurityDecision | None:
    """Evaluate boundary constraints on resource/request metadata."""
    probe = _build_secret_scoped_probe(resource=resource, request_payload=request_payload).strip()

    if not probe:
        return None

    normalized_resource = resource.strip() if resource else ""

    if normalized_resource:
        normalized_resource = normalized_resource.replace("\\", "/")
        normalized_resource = _normalize_resource_scope(normalized_resource)
        if "://" in normalized_resource:
            return SecurityDecision(
                action=action,
                decision="deny",
                reason_code="resource_scope_uri_forbidden",
                reason_message=(
                    f"{adapter} action '{action}' supplied a URI-style resource; "
                    "bounded filesystem paths are required"
                ),
            )
        normalized_resource = normalized_resource.rstrip("/")
        allowed = tuple(root.rstrip("/") for root in allowed_resource_roots)
        in_scope = False
        if normalized_resource:
            for root in allowed:
                if normalized_resource == root or normalized_resource.startswith(f"{root}/"):
                    in_scope = True
                    break
        if not in_scope:
            return SecurityDecision(
                action=action,
                decision="deny",
                reason_code="resource_scope_out_of_bounds",
                reason_message=(
                    f"{adapter} resource '{normalized_resource}' is outside known scope: "
                    f"{', '.join(allowed)}"
                ),
            )

    for label, pattern in _SECRET_PATTERNS:
        if pattern.search(probe):
            return SecurityDecision(
                action=action,
                decision="deny",
                reason_code="secret_material_detected",
                reason_message=f"Request contains detected {label} signal",
            )

    return None


def policy_receipt(
    decision: SecurityDecision,
    *,
    actor: str,
    actor_identity: str | None = None,
    source_ref: str,
    scope: str | None = None,
    plan_ref: str | None = None,
    resource: str | None = None,
    request_payload: str | None = None,
    required_capabilities: tuple[str, ...] | None = None,
    granted_capabilities: tuple[str, ...] | None = None,
    source_channel: str | None = None,
    destination_channel: str | None = None,
    provenance: str | None = None,
    artifact_state: str | None = None,
    transform: str | None = None,
    requested_capabilities: tuple[str, ...] | None = None,
    requested_channel: str | None = None,
    requested_ring: str | None = None,
    requested_destination: str | None = None,
    requested_artifact_hash: str | None = None,
    previous_artifact_hash: str | None = None,
) -> Dict[str, str]:
    """Return a lightweight audit receipt payload."""
    receipt = {
        "action": decision.action,
        "actor": actor,
        "actor_identity": actor_identity or "",
        "source": source_ref,
        "scope": scope or "",
        "plan_ref": plan_ref or "",
        "resource": resource or "",
        "decision": decision.decision,
        "reason_code": decision.reason_code,
        "reason_message": decision.reason_message,
    }
    if requested_capabilities:
        receipt["requested_capabilities"] = ",".join(requested_capabilities)
    if required_capabilities:
        receipt["required_capabilities"] = ",".join(required_capabilities)
    if granted_capabilities:
        receipt["granted_capabilities"] = ",".join(granted_capabilities)
    if source_channel:
        receipt["source_channel"] = source_channel
    if destination_channel:
        receipt["destination_channel"] = destination_channel
    if provenance:
        receipt["provenance"] = provenance
    if artifact_state:
        receipt["artifact_state"] = artifact_state
    if transform:
        receipt["transform"] = transform
    if requested_channel:
        receipt["requested_channel"] = requested_channel
    if requested_ring:
        receipt["requested_ring"] = requested_ring
    if requested_destination:
        receipt["requested_destination"] = requested_destination
    if requested_artifact_hash:
        receipt["requested_artifact_hash"] = requested_artifact_hash
    if previous_artifact_hash:
        receipt["previous_artifact_hash"] = previous_artifact_hash
    if requested_artifact_hash and previous_artifact_hash:
        receipt["artifact_hash_delta"] = "changed" if requested_artifact_hash != previous_artifact_hash else "unchanged"
    if request_payload:
        receipt["payload_signature"] = _payload_signature(request_payload)
    return receipt
