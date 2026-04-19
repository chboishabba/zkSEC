"""Minimal deterministic reporting helpers for routed actions."""

from __future__ import annotations


def execution_audit_record(*, operator: str, directive: dict[str, str] | object) -> dict[str, str]:
    """Create a stable audit record payload."""
    if isinstance(directive, dict):
        directive_dict = directive
    else:
        # Fallback for non-mapping directive objects, keeping output deterministic.
        receipt = getattr(directive, "receipt", {})
        directive_dict = {
            "adapter": getattr(directive, "adapter", "unknown"),
            "action": getattr(directive, "action", "unknown"),
            "status": getattr(directive, "status", "unknown"),
            "reason_code": getattr(directive, "reason_code", "unknown"),
            "reason_message": getattr(directive, "reason_message", "unknown"),
            "command": getattr(directive, "command", ""),
            "requested_capabilities": getattr(directive, "requested_capabilities", ""),
            "requested_channel": getattr(directive, "requested_channel", ""),
            "requested_ring": getattr(directive, "requested_ring", ""),
            "requested_destination": getattr(directive, "requested_destination", ""),
            "requested_artifact_hash": receipt.get("requested_artifact_hash", ""),
            "previous_artifact_hash": receipt.get("previous_artifact_hash", ""),
            "artifact_hash_delta": receipt.get("artifact_hash_delta", ""),
            "admissibility_verdict": receipt.get("admissibility_verdict", ""),
            "detector_verdict": receipt.get("detector_verdict", ""),
            "detector_severity": receipt.get("detector_severity", ""),
            "detector_reason_codes": receipt.get("detector_reason_codes", ""),
            "changed_surfaces": receipt.get("changed_surfaces", ""),
            "bridge_status": receipt.get("bridge_status", ""),
            "mu_exec_state": receipt.get("mu_exec_state", ""),
            "mu_exec_proposal_sources": receipt.get("mu_exec_proposal_sources", ""),
            "mu_exec_grounding_basis": receipt.get("mu_exec_grounding_basis", ""),
            "mu_exec_interaction_shape": receipt.get("mu_exec_interaction_shape", ""),
            "mu_exec_invariant_codes": receipt.get("mu_exec_invariant_codes", ""),
            "mu_exec_reason_codes": receipt.get("mu_exec_reason_codes", ""),
            "mu_exec_summary": receipt.get("mu_exec_summary", ""),
        }

    return {
        "operator": operator,
        "adapter": directive_dict.get("adapter", "unknown"),
        "action": directive_dict.get("action", "unknown"),
        "execution_status": directive_dict.get("status", "unknown"),
        "reason_code": directive_dict.get("reason_code", "unknown"),
        "reason_message": directive_dict.get("reason_message", "unknown"),
        "command": str(directive_dict.get("command", "")),
        "requested_capabilities": str(directive_dict.get("requested_capabilities", "")),
        "requested_channel": str(directive_dict.get("requested_channel", "")),
        "requested_ring": str(directive_dict.get("requested_ring", "")),
        "requested_destination": str(directive_dict.get("requested_destination", "")),
        "requested_artifact_hash": str(directive_dict.get("requested_artifact_hash", "")),
        "previous_artifact_hash": str(directive_dict.get("previous_artifact_hash", "")),
        "artifact_hash_delta": str(directive_dict.get("artifact_hash_delta", "")),
        "admissibility_verdict": str(directive_dict.get("admissibility_verdict", "")),
        "detector_verdict": str(directive_dict.get("detector_verdict", "")),
        "detector_severity": str(directive_dict.get("detector_severity", "")),
        "detector_reason_codes": str(directive_dict.get("detector_reason_codes", "")),
        "changed_surfaces": str(directive_dict.get("changed_surfaces", "")),
        "bridge_status": str(directive_dict.get("bridge_status", "")),
        "mu_exec_state": str(directive_dict.get("mu_exec_state", "")),
        "mu_exec_proposal_sources": str(directive_dict.get("mu_exec_proposal_sources", "")),
        "mu_exec_grounding_basis": str(directive_dict.get("mu_exec_grounding_basis", "")),
        "mu_exec_interaction_shape": str(directive_dict.get("mu_exec_interaction_shape", "")),
        "mu_exec_invariant_codes": str(directive_dict.get("mu_exec_invariant_codes", "")),
        "mu_exec_reason_codes": str(directive_dict.get("mu_exec_reason_codes", "")),
        "mu_exec_summary": str(directive_dict.get("mu_exec_summary", "")),
    }
