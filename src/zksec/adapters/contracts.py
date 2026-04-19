"""Adjacent system contracts for bounded zkSEC integration."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class AdapterContract:
    """Contract describing how an adjacent system is integrated."""

    name: str
    system_path: str
    integration_mode: str
    allowed_actions: tuple[str, ...]
    risk_surface: str
    trust_gate: str
    resource_roots: tuple[str, ...]
    allowed_capabilities: tuple[str, ...]
    allowed_rings: tuple[str, ...]
    allowed_channels: tuple[str, ...]
    allowed_destinations: tuple[str, ...]
    action_capability_policies: AdapterCapabilityPolicy


ChannelClass = Literal["proposal", "confirmed", "autonomous"]
RingClass = Literal["sovereign", "bounded", "remote"]
CapabilityClass = Literal[
    "read",
    "write",
    "execute",
    "network_egress",
    "identity_mutation",
    "policy_mutation",
]
ExecutionChannelClass = Literal["local", "self", "trusted_peer", "public", "remote_api"]


@dataclass(frozen=True)
class AdapterActionCapability:
    """Per-action capability/ring/channel constraints."""

    action: str
    capabilities: tuple[CapabilityClass, ...]
    channels: tuple[ChannelClass, ...]
    execution_channels: tuple[ExecutionChannelClass, ...]
    destination_channels: tuple[ExecutionChannelClass, ...]
    rings: tuple[RingClass, ...]
    destinations: tuple[str, ...]
    transforms: tuple[str, ...] = ()


@dataclass(frozen=True)
class AdapterCapabilityPolicy:
    """Capability policy envelope for an adapter."""

    action_profiles: tuple[AdapterActionCapability, ...]


def _profile_for(
    action: str,
    *,
    profiles: tuple[AdapterActionCapability, ...],
) -> AdapterActionCapability:
    for item in profiles:
        if item.action == action:
            return item
    raise KeyError(action)


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
        resource_roots=(
            "../zos-server",
            "../zkperf",
            "../ipfs-dasl",
            "../ITIR-suite",
        ),
        allowed_capabilities=("read", "write", "execute", "network_egress"),
        allowed_rings=("sovereign", "bounded", "remote"),
        allowed_channels=("proposal", "confirmed"),
        allowed_destinations=("local", "peer"),
        action_capability_policies=AdapterCapabilityPolicy(
        action_profiles=(
                AdapterActionCapability(
                    action="read",
                    capabilities=("read",),
                    channels=("proposal", "confirmed"),
                    execution_channels=("local", "trusted_peer"),
                    destination_channels=("local",),
                    rings=("sovereign", "bounded"),
                    destinations=("local",),
                    transforms=("read",),
                ),
                AdapterActionCapability(
                    action="review",
                    capabilities=("read",),
                    channels=("confirmed",),
                    execution_channels=("trusted_peer",),
                    destination_channels=("local",),
                    rings=("bounded",),
                    destinations=("local",),
                    transforms=("review",),
                ),
                AdapterActionCapability(
                    action="plan",
                    capabilities=("execute",),
                    channels=("confirmed",),
                    execution_channels=("trusted_peer",),
                    destination_channels=("local",),
                    rings=("bounded",),
                    destinations=("local",),
                    transforms=("plan",),
                ),
                AdapterActionCapability(
                    action="patch",
                    capabilities=("write", "execute"),
                    channels=("confirmed",),
                    execution_channels=("trusted_peer",),
                    destination_channels=("local",),
                    rings=("bounded",),
                    destinations=("local",),
                    transforms=("patch", "transform"),
                ),
                AdapterActionCapability(
                    action="deploy",
                    capabilities=("write", "network_egress"),
                    channels=("confirmed",),
                    execution_channels=("trusted_peer",),
                    destination_channels=("trusted_peer",),
                    rings=("bounded",),
                    destinations=("peer",),
                    transforms=("deploy", "sync"),
                ),
            )
        ),
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
        resource_roots=("../kant-zk-pastebin",),
        allowed_capabilities=("read", "execute"),
        allowed_rings=("sovereign", "bounded"),
        allowed_channels=("proposal", "confirmed"),
        allowed_destinations=("local",),
        action_capability_policies=AdapterCapabilityPolicy(
            action_profiles=(
                AdapterActionCapability(
                    action="read",
                    capabilities=("read",),
                    channels=("proposal", "confirmed"),
                    execution_channels=("local", "trusted_peer"),
                    destination_channels=("local",),
                    rings=("sovereign", "bounded"),
                    destinations=("local",),
                    transforms=("read",),
                ),
                AdapterActionCapability(
                    action="review",
                    capabilities=("read", "execute"),
                    channels=("confirmed",),
                    execution_channels=("trusted_peer",),
                    destination_channels=("local",),
                    rings=("bounded",),
                    destinations=("local",),
                    transforms=("review",),
                ),
                AdapterActionCapability(
                    action="plan",
                    capabilities=("execute",),
                    channels=("confirmed",),
                    execution_channels=("trusted_peer",),
                    destination_channels=("local",),
                    rings=("bounded",),
                    destinations=("local",),
                    transforms=("plan",),
                ),
                AdapterActionCapability(
                    action="deploy",
                    capabilities=("execute", "write"),
                    channels=("confirmed",),
                    execution_channels=("trusted_peer",),
                    destination_channels=("local",),
                    rings=("bounded",),
                    destinations=("local",),
                    transforms=("deploy",),
                ),
            )
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


def action_capability_policy(
    *,
    adapter: AdapterContract,
    action: str,
) -> AdapterActionCapability:
    """Return the capability profile for the action."""

    if not hasattr(adapter, "action_capability_policies"):
        raise KeyError(action)
    return _profile_for(action, profiles=adapter.action_capability_policies.action_profiles)
