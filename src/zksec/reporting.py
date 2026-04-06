"""Minimal deterministic reporting helpers for routed actions."""

from __future__ import annotations


def execution_audit_record(*, operator: str, directive: dict[str, str] | object) -> dict[str, str]:
    """Create a stable audit record payload."""

    if isinstance(directive, dict):
        directive_dict = directive
    else:
        # Fallback for non-mapping directive objects, keeping output deterministic.
        directive_dict = {
            "adapter": getattr(directive, "adapter", "unknown"),
            "action": getattr(directive, "action", "unknown"),
            "status": getattr(directive, "status", "unknown"),
            "reason_code": getattr(directive, "reason_code", "unknown"),
            "reason_message": getattr(directive, "reason_message", "unknown"),
            "command": getattr(directive, "command", ""),
        }

    return {
        "operator": operator,
        "adapter": directive_dict.get("adapter", "unknown"),
        "action": directive_dict.get("action", "unknown"),
        "execution_status": directive_dict.get("status", "unknown"),
        "reason_code": directive_dict.get("reason_code", "unknown"),
        "reason_message": directive_dict.get("reason_message", "unknown"),
        "command": str(directive_dict.get("command", "")),
    }

