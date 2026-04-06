"""Adjacent system contracts for bounded zkSEC integration."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AdapterContract:
    """Contract describing how an adjacent system is integrated."""

    name: str
    system_path: str
    integration_mode: str
    allowed_actions: tuple[str, ...]
    risk_surface: str
    trust_gate: str


@dataclass(frozen=True)
class AdapterCheckResult:
    """Validation result for an action against an adapter contract."""

    adapter: str
    action: str
    allowed: bool
    reason_code: str
    reason_message: str


def zos_server_contract() -> AdapterContract:
    """Contract for `../zos-server` interactions."""

    return AdapterContract(
        name="zos_server",
        system_path="../zos-server",
        integration_mode="managed",
        allowed_actions=("read", "review", "plan", "patch", "deploy"),
        risk_surface="peer-sync and artifact convergence operations",
        trust_gate="managed-host gate + reason-code receipt required",
    )


def kant_zk_pastebin_contract() -> AdapterContract:
    """Contract for `../kant-zk-pastebin` interactions."""

    return AdapterContract(
        name="kant_zk_pastebin",
        system_path="../kant-zk-pastebin",
        integration_mode="managed",
        allowed_actions=("read", "review", "plan", "deploy"),
        risk_surface="ZOS-related deployment and IPFS surface discovery",
        trust_gate=(
            "public discovery only when unauthenticated; high-impact requires confirmation"
        ),
    )


def validate_action_against_adapter(
    *,
    adapter: AdapterContract,
    action: str,
) -> AdapterCheckResult:
    """Return a compact allow/deny decision for a candidate action."""

    if action in adapter.allowed_actions:
        return AdapterCheckResult(
            adapter=adapter.name,
            action=action,
            allowed=True,
            reason_code="adapter_action_allowed",
            reason_message=f"'{action}' is in {adapter.name} contract action set",
        )

    return AdapterCheckResult(
        adapter=adapter.name,
        action=action,
        allowed=False,
        reason_code="adapter_action_blocked",
        reason_message=f"'{action}' is not allowed for adapter {adapter.name}",
    )
