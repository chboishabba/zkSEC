"""Evaluation routing for adapter-bound actions."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Literal, Mapping

from .adapters import (
    AdapterActionCapability,
    AdapterCheckResult,
    action_capability_policy,
    kant_zk_pastebin_contract,
    validate_action_against_adapter,
    zos_server_contract,
)
from .admissibility import (
    AdmissibilityDecision,
    AdmissibilityInput,
    OntologyDelta,
    evaluate_transform_admissibility,
)
from .mu_exec import MuExecWitness, mu_exec_receipt_fields
from .security import (
    RiskLevel,
    SecurityDecision,
    SourceTrust,
    assess_action,
    assess_data_boundary,
    policy_receipt,
)


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
    capability_profile: AdapterActionCapability | None
    receipt: dict[str, str]
    required_capabilities: tuple[str, ...] = ()
    granted_capabilities: tuple[str, ...] = ()
    source_channel: str = ""
    destination_channel: str = ""
    provenance: str = ""
    artifact_state: str = ""
    transform: str = ""
    requested_capabilities: tuple[str, ...] = ()
    requested_channel: str = ""
    requested_ring: str = ""
    requested_destination: str = ""
    detector_verdict: str = ""
    detector_severity: str = ""
    detector_reason_codes: tuple[str, ...] = ()
    changed_surfaces: tuple[str, ...] = ()
    admissibility_verdict: str = ""
    bridge_status: str = ""
    mu_exec_state: str = ""
    mu_exec_grounding_basis: tuple[str, ...] = ()
    mu_exec_invariant_codes: tuple[str, ...] = ()
    mu_exec_reason_codes: tuple[str, ...] = ()


def _resolve_adapter(name: str):
    if name == "zos_server":
        return zos_server_contract()
    if name == "kant_zk_pastebin":
        return kant_zk_pastebin_contract()
    return None


_CHANNEL_PRECEDENCE: tuple[str, ...] = ("local", "self", "trusted_peer", "public", "remote_api")
_RING_PRECEDENCE: tuple[str, ...] = ("sovereign", "bounded", "remote")


def _normalize_channel(value: str | None) -> str:
    if not value:
        return ""
    normalized = value.strip().lower()
    if normalized == "proposal":
        return "self"
    if normalized == "confirmed":
        return "trusted_peer"
    if normalized == "autonomous":
        return "remote_api"
    if normalized == "peer":
        return "trusted_peer"
    return normalized


def _legacy_to_lattice(value: str | None) -> str:
    normalized = _normalize_channel(value)
    if not normalized:
        return "local"
    return normalized


def _legacy_dest_to_lattice(value: str | None) -> str:
    if not value:
        return "local"
    normalized = value.strip().lower()
    if normalized == "peer":
        return "trusted_peer"
    return normalized


def _normalize_ring(value: str | None) -> str:
    if not value:
        return ""
    normalized = value.strip().lower()
    if normalized in ("local", "local_controlled", "sandbox"):
        return "bounded"
    if normalized == "sovereign_control":
        return "sovereign"
    if normalized == "remote_api":
        return "remote"
    return normalized


def _ring_escalated(previous: str | None, candidate: str) -> bool:
    if previous is None:
        return False
    if previous not in _RING_PRECEDENCE or candidate not in _RING_PRECEDENCE:
        return False
    return _RING_PRECEDENCE.index(candidate) > _RING_PRECEDENCE.index(previous)


def _channel_escalated(previous: str | None, candidate: str) -> bool:
    if previous is None:
        return False
    if previous not in _CHANNEL_PRECEDENCE or candidate not in _CHANNEL_PRECEDENCE:
        return False
    return _CHANNEL_PRECEDENCE.index(candidate) > _CHANNEL_PRECEDENCE.index(previous)


def _coerce_csv_list(value: object) -> tuple[str, ...]:
    if not value:
        return ()
    if isinstance(value, tuple):
        return tuple(str(item).strip() for item in value if str(item).strip())
    if isinstance(value, str):
        return tuple(item.strip() for item in value.split(",") if item.strip())
    return tuple(str(item).strip() for item in value if str(item).strip())


def _artifact_fingerprint(
    *,
    artifact_state: str,
    transform: str,
    capabilities: tuple[str, ...],
) -> str:
    payload = f"{artifact_state}|{transform}|{','.join(capabilities)}"
    return sha256(payload.encode("utf-8")).hexdigest()[:20]


def _missing_capability_decision(action: str, reason_code: str, reason_message: str) -> SecurityDecision:
    return SecurityDecision(
        action=action,
        decision="deny",
        reason_code=reason_code,
        reason_message=reason_message,
    )


def _with_receipt(
    *,
    security_decision: SecurityDecision,
    actor_role: str,
    actor_identity: str | None,
    adapter_name: str,
    scope: str | None,
    plan_ref: str | None,
    resource: str | None,
    request_payload: str | None,
    requested_capabilities: tuple[str, ...],
    required_capabilities: tuple[str, ...],
    granted_capabilities: tuple[str, ...],
    source_channel: str,
    destination_channel: str,
    provenance: str,
    artifact_state: str,
    transform: str,
    requested_channel: str,
    requested_ring: str,
    requested_destination: str,
    requested_artifact_hash: str | None = None,
    previous_artifact_hash: str | None = None,
    admissibility_verdict: str | None = None,
    detector_verdict: str | None = None,
    detector_severity: str | None = None,
    detector_reason_codes: tuple[str, ...] | None = None,
    changed_surfaces: tuple[str, ...] | None = None,
    bridge_status: str | None = None,
    mu_exec_witness: MuExecWitness | None = None,
) -> dict[str, str]:
    computed_requested_hash = requested_artifact_hash
    if not computed_requested_hash:
        computed_requested_hash = _artifact_fingerprint(
            artifact_state=artifact_state,
            transform=transform,
            capabilities=(),
        )

    receipt = policy_receipt(
        security_decision,
        actor=actor_role,
        actor_identity=actor_identity,
        source_ref=adapter_name,
        scope=scope,
        plan_ref=plan_ref,
        resource=resource,
        request_payload=request_payload,
        required_capabilities=required_capabilities,
        granted_capabilities=granted_capabilities,
        source_channel=source_channel,
        destination_channel=destination_channel,
        provenance=provenance,
        artifact_state=artifact_state,
        transform=transform,
        requested_capabilities=requested_capabilities,
        requested_channel=requested_channel,
        requested_ring=requested_ring,
        requested_destination=requested_destination,
        requested_artifact_hash=computed_requested_hash,
        previous_artifact_hash=previous_artifact_hash,
    )
    if admissibility_verdict:
        receipt["admissibility_verdict"] = admissibility_verdict
    if detector_verdict:
        receipt["detector_verdict"] = detector_verdict
    if detector_severity:
        receipt["detector_severity"] = detector_severity
    if detector_reason_codes:
        receipt["detector_reason_codes"] = ",".join(detector_reason_codes)
    if changed_surfaces:
        receipt["changed_surfaces"] = ",".join(changed_surfaces)
    if bridge_status:
        receipt["bridge_status"] = bridge_status
    receipt.update(mu_exec_receipt_fields(witness=mu_exec_witness))
    return receipt


def _deny_with_metadata(
    *,
    adapter_name: str,
    action: str,
    reason_code: str,
    reason_message: str,
    security_decision: SecurityDecision,
    actor_role: str,
    actor_identity: str | None,
    adapter: str,
    scope: str | None,
    plan_ref: str | None,
    resource: str | None,
    request_payload: str | None,
    required_capabilities: tuple[str, ...],
    granted_capabilities: tuple[str, ...],
    source_channel: str,
    destination_channel: str,
    provenance: str,
    artifact_state: str,
    transform: str,
    requested_capabilities: tuple[str, ...],
    requested_channel: str,
    requested_ring: str,
    requested_destination: str,
    requested_artifact_hash: str | None = None,
    previous_artifact_hash: str | None = None,
    adapter_check: AdapterCheckResult | None = None,
    capability_profile: AdapterActionCapability | None = None,
    admissibility: AdmissibilityDecision | None = None,
    mu_exec_witness: MuExecWitness | None = None,
) -> RoutedActionDecision:
    denied = _missing_capability_decision(action=action, reason_code=reason_code, reason_message=reason_message)
    return RoutedActionDecision(
        adapter=adapter,
        action=action,
        status="deny",
        reason_code=denied.reason_code,
        reason_message=denied.reason_message,
        required_capabilities=required_capabilities,
        granted_capabilities=granted_capabilities,
        source_channel=source_channel,
        destination_channel=destination_channel,
        provenance=provenance,
        artifact_state=artifact_state,
        transform=transform,
        security_decision=security_decision,
        adapter_check=adapter_check,
        capability_profile=capability_profile,
        requested_capabilities=requested_capabilities,
        requested_channel=requested_channel,
        requested_ring=requested_ring,
        requested_destination=requested_destination,
        detector_verdict=admissibility.detector.verdict if admissibility else "",
        detector_severity=admissibility.detector.severity if admissibility else "",
        detector_reason_codes=admissibility.detector.reason_codes if admissibility else (),
        changed_surfaces=admissibility.detector.changed_surfaces if admissibility else (),
        admissibility_verdict=admissibility.verdict if admissibility else "",
        bridge_status=admissibility.bridge.status if admissibility else "",
        mu_exec_state=mu_exec_witness.state if mu_exec_witness else "",
        mu_exec_grounding_basis=mu_exec_witness.grounding_basis if mu_exec_witness else (),
        mu_exec_invariant_codes=mu_exec_witness.invariant_codes if mu_exec_witness else (),
        mu_exec_reason_codes=mu_exec_witness.reason_codes if mu_exec_witness else (),
        receipt=_with_receipt(
            security_decision=denied,
            actor_role=actor_role,
            actor_identity=actor_identity,
            adapter_name=adapter_name,
            scope=scope,
            plan_ref=plan_ref,
            resource=resource,
            request_payload=request_payload,
            requested_capabilities=requested_capabilities,
            required_capabilities=required_capabilities,
            granted_capabilities=granted_capabilities,
            source_channel=source_channel,
            destination_channel=destination_channel,
            provenance=provenance,
            artifact_state=artifact_state,
            transform=transform,
            requested_channel=requested_channel,
            requested_ring=requested_ring,
            requested_destination=requested_destination,
            requested_artifact_hash=requested_artifact_hash,
            previous_artifact_hash=previous_artifact_hash,
            admissibility_verdict=admissibility.verdict if admissibility else None,
            detector_verdict=admissibility.detector.verdict if admissibility else None,
            detector_severity=admissibility.detector.severity if admissibility else None,
            detector_reason_codes=admissibility.detector.reason_codes if admissibility else None,
            changed_surfaces=admissibility.detector.changed_surfaces if admissibility else None,
            bridge_status=admissibility.bridge.status if admissibility else None,
            mu_exec_witness=mu_exec_witness,
        ),
    )


def _build_artifact_state(adapter: str, action: str, resource: str | None, requested_artifact_state: str | None) -> str:
    if requested_artifact_state:
        return requested_artifact_state
    if resource:
        normalized_resource = resource.strip().rstrip("/")
        if normalized_resource:
            return f"{adapter}:{action}:{normalized_resource}"
    return f"{adapter}:{action}"


def evaluate_adapter_action(
    *,
    adapter_name: str,
    action: str,
    actor_role: str,
    actor_identity: str | None = None,
    scope: str | None = None,
    plan_ref: str | None = None,
    resource: str | None = None,
    request_payload: str | None = None,
    source: SourceTrust,
    risk_level: RiskLevel = "low",
    confirmed: bool = False,
    requested_capabilities: tuple[str, ...] | str | None = None,
    requested_channel: str | None = None,
    requested_ring: str | None = None,
    requested_destination: str | None = None,
    source_channel: str | None = None,
    destination_channel: str | None = None,
    requested_artifact_state: str | None = None,
    requested_transform: str | None = None,
    requested_artifact_hash: str | None = None,
    previous_artifact_hash: str | None = None,
    previous_capabilities: tuple[str, ...] | str | None = None,
    previous_source_channel: str | None = None,
    previous_destination_channel: str | None = None,
    previous_ring: str | None = None,
    previous_artifact_state: str | None = None,
    previous_transform: str | None = None,
    payload_sanitized: bool = False,
    proposal_state: str = "proposal",
    artifact_class: str = "unknown",
    zos_proposal: Mapping[str, object] | None = None,
    ontology_delta: OntologyDelta | None = None,
    mu_exec_witness: MuExecWitness | None = None,
) -> RoutedActionDecision:
    """Return a deterministic routing decision for a candidate adapter action."""

    adapter = _resolve_adapter(adapter_name)
    requested_caps = _coerce_csv_list(requested_capabilities)
    source_channel_value = _normalize_channel(source_channel)
    if not source_channel_value:
        source_channel_value = _legacy_to_lattice(requested_channel)
    destination_channel_value = _normalize_channel(destination_channel)
    if not destination_channel_value:
        if requested_destination:
            destination_channel_value = _legacy_dest_to_lattice(requested_destination)
        else:
            destination_channel_value = ""

    previous_source_channel_value = _normalize_channel(previous_source_channel)
    previous_destination_channel_value = (
        _legacy_dest_to_lattice(previous_destination_channel) if previous_destination_channel else ""
    )
    previous_ring_value = _normalize_ring(previous_ring)
    previous_caps = _coerce_csv_list(previous_capabilities)
    requested_artifact_state_value = _build_artifact_state(adapter_name, action, resource, requested_artifact_state)
    computed_previous_artifact_hash = previous_artifact_hash
    if previous_artifact_state and not previous_artifact_hash:
        computed_previous_artifact_hash = _artifact_fingerprint(
            artifact_state=previous_artifact_state,
            transform=previous_transform or action,
            capabilities=previous_caps or (),
        )

    if adapter is None:
        security_decision = SecurityDecision(
            action=action,
            decision="deny",
            reason_code="unknown_adapter",
            reason_message=f"No adapter contract registered for '{adapter_name}'",
        )
        return _deny_with_metadata(
            adapter_name=adapter_name,
            action=action,
            reason_code=security_decision.reason_code,
            reason_message=security_decision.reason_message,
            security_decision=security_decision,
            actor_role=actor_role,
            actor_identity=actor_identity,
            adapter=adapter_name,
            scope=scope,
            plan_ref=plan_ref,
            resource=resource,
            request_payload=request_payload,
            required_capabilities=(),
            granted_capabilities=requested_caps,
            source_channel=source_channel_value or "local",
            destination_channel=destination_channel_value or "local",
            provenance=source,
            artifact_state=requested_artifact_state_value,
            transform=requested_transform or "",
            requested_capabilities=requested_caps,
            requested_channel=requested_channel or "",
            requested_ring=_normalize_ring(requested_ring) or "",
            requested_destination=requested_destination or "",
            requested_artifact_hash=requested_artifact_hash,
            previous_artifact_hash=computed_previous_artifact_hash,
        )

    security_decision = assess_action(
        action=action,
        actor_role=actor_role,
        actor_identity=actor_identity,
        scope=scope,
        plan_ref=plan_ref,
        source=source,
        risk_level=risk_level,
        confirmed=confirmed,
    )

    if security_decision.decision != "deny":
        boundary_decision = assess_data_boundary(
            action=action,
            adapter=adapter.name,
            resource=resource,
            request_payload=request_payload,
            allowed_resource_roots=adapter.resource_roots,
        )
        if boundary_decision is not None:
            return _deny_with_metadata(
                adapter_name=adapter.system_path,
                action=action,
                reason_code=boundary_decision.reason_code,
                reason_message=boundary_decision.reason_message,
                security_decision=security_decision,
                actor_role=actor_role,
                actor_identity=actor_identity,
                adapter=adapter.name,
                scope=scope,
                plan_ref=plan_ref,
                resource=resource,
                request_payload=request_payload,
                required_capabilities=(),
                granted_capabilities=requested_caps,
                source_channel=source_channel_value or "local",
                destination_channel=destination_channel_value or "local",
                provenance=source,
                artifact_state=requested_artifact_state_value,
                transform=requested_transform or "",
                requested_capabilities=requested_caps,
                requested_channel=requested_channel or "",
                requested_ring=_normalize_ring(requested_ring) or "",
                requested_destination=requested_destination or "",
                requested_artifact_hash=requested_artifact_hash,
                previous_artifact_hash=computed_previous_artifact_hash,
            )

    if security_decision.decision == "deny":
        return _deny_with_metadata(
            adapter_name=adapter.system_path,
            action=action,
            reason_code=security_decision.reason_code,
            reason_message=security_decision.reason_message,
            security_decision=security_decision,
            actor_role=actor_role,
            actor_identity=actor_identity,
            adapter=adapter.name,
            scope=scope,
            plan_ref=plan_ref,
            resource=resource,
            request_payload=request_payload,
            required_capabilities=(),
            granted_capabilities=requested_caps,
            source_channel=source_channel_value or "local",
            destination_channel=destination_channel_value or "local",
            provenance=source,
            artifact_state=requested_artifact_state_value,
            transform=requested_transform or "",
            requested_capabilities=requested_caps,
            requested_channel=requested_channel or "",
            requested_ring=_normalize_ring(requested_ring) or "",
            requested_destination=requested_destination or "",
            requested_artifact_hash=requested_artifact_hash,
            previous_artifact_hash=computed_previous_artifact_hash,
        )

    adapter_check = validate_action_against_adapter(adapter=adapter, action=action)
    if not adapter_check.allowed:
        return _deny_with_metadata(
            adapter_name=adapter.system_path,
            action=action,
            reason_code=adapter_check.reason_code,
            reason_message=adapter_check.reason_message,
            security_decision=security_decision,
            actor_role=actor_role,
            actor_identity=actor_identity,
            adapter=adapter.name,
            scope=scope,
            plan_ref=plan_ref,
            resource=resource,
            request_payload=request_payload,
            required_capabilities=(),
            granted_capabilities=requested_caps,
            source_channel=source_channel_value or "local",
            destination_channel=destination_channel_value or "local",
            provenance=source,
            artifact_state=requested_artifact_state_value,
            transform=requested_transform or "",
            requested_capabilities=requested_caps,
            requested_channel=requested_channel or "",
            requested_ring=_normalize_ring(requested_ring) or "",
            requested_destination=requested_destination or "",
            adapter_check=adapter_check,
            requested_artifact_hash=requested_artifact_hash,
            previous_artifact_hash=computed_previous_artifact_hash,
        )

    try:
        capability_profile = action_capability_policy(adapter=adapter, action=action)
    except KeyError:
        return _deny_with_metadata(
            adapter_name=adapter.system_path,
            action=action,
            reason_code="missing_action_capability_profile",
            reason_message=f"Adapter '{adapter.name}' has no capability profile for '{action}'",
            security_decision=security_decision,
            actor_role=actor_role,
            actor_identity=actor_identity,
            adapter=adapter.name,
            scope=scope,
            plan_ref=plan_ref,
            resource=resource,
            request_payload=request_payload,
            required_capabilities=(),
            granted_capabilities=requested_caps,
            source_channel=source_channel_value or "local",
            destination_channel=destination_channel_value or "local",
            provenance=source,
            artifact_state=requested_artifact_state_value,
            transform=requested_transform or "",
            requested_capabilities=requested_caps,
            requested_channel=requested_channel or "",
            requested_ring=_normalize_ring(requested_ring) or "",
            requested_destination=requested_destination or "",
            adapter_check=adapter_check,
            capability_profile=None,
            requested_artifact_hash=requested_artifact_hash,
            previous_artifact_hash=computed_previous_artifact_hash,
        )

    requested_capability_tuple = requested_caps or tuple(capability_profile.capabilities)
    required_capability_tuple = tuple(capability_profile.capabilities)
    requested_channel_value = requested_channel or capability_profile.channels[0]
    requested_channel_lattice = _legacy_to_lattice(requested_channel_value)
    requested_ring_value = _normalize_ring(requested_ring) or _normalize_ring(capability_profile.rings[0])
    resolved_transform = requested_transform or (capability_profile.transforms[0] if capability_profile.transforms else action)
    requested_destination_value = requested_destination or capability_profile.destinations[0]
    artifact_state = _build_artifact_state(adapter.name, action, resource, requested_artifact_state)
    computed_requested_artifact_hash = requested_artifact_hash or _artifact_fingerprint(
        artifact_state=artifact_state,
        transform=resolved_transform,
        capabilities=requested_capability_tuple,
    )

    allowed_source_channels = tuple(_legacy_to_lattice(c) for c in capability_profile.channels)
    allowed_destination_channels = tuple(_legacy_dest_to_lattice(c) for c in capability_profile.destinations)
    requested_source_channel = source_channel_value or _legacy_to_lattice(requested_channel_value)
    requested_dest_channel = destination_channel_value or _legacy_dest_to_lattice(requested_destination_value)
    proposal_state_value = proposal_state if proposal_state in {"proposal", "control", "sovereign"} else "proposal"
    admissibility = evaluate_transform_admissibility(
        candidate=AdmissibilityInput(
            prior_state=previous_artifact_state or artifact_state,
            proposed_state=artifact_state,
            artifact_class=artifact_class,
            delta_surface=(
                "changed"
                if (
                    (previous_artifact_state and previous_artifact_state != artifact_state)
                    or (
                        computed_previous_artifact_hash is not None
                        and computed_requested_artifact_hash != computed_previous_artifact_hash
                    )
                )
                else "unchanged"
            ),
            capability_delta=tuple(sorted(set(requested_capability_tuple) - set(previous_caps))),
            channel_delta=tuple(
                item
                for item in (requested_source_channel, requested_dest_channel)
                if item and item not in (previous_source_channel_value, previous_destination_channel_value)
            ),
            semantic_delta=ontology_delta,
            proposal_state=proposal_state_value,
            source=source,
            ring=requested_ring_value,
            expected_capabilities=required_capability_tuple,
            observed_capabilities=requested_capability_tuple,
            previous_capabilities=previous_caps,
            expected_source_channels=allowed_source_channels,
            observed_source_channel=requested_channel_lattice,
            previous_source_channel=previous_source_channel_value,
            expected_destination_channels=allowed_destination_channels,
            observed_destination_channel=requested_dest_channel,
            previous_destination_channel=previous_destination_channel_value,
            expected_transforms=capability_profile.transforms,
            observed_transform=resolved_transform,
            previous_transform=previous_transform or "",
            expected_destinations=capability_profile.destinations,
            observed_destination=requested_destination_value,
            expected_rings=capability_profile.rings,
            previous_ring=previous_ring_value,
            request_payload_present=bool(request_payload),
            payload_sanitized=payload_sanitized,
            zos_proposal=zos_proposal,
            witness=None,
            mu_exec_witness=mu_exec_witness,
        )
    )
    if admissibility.verdict != "allow":
        primary_reason_code = admissibility.reason_codes[0] if admissibility.reason_codes else "transform_inadmissible"
        if admissibility.verdict == "allow_with_confirmation":
            confirmation_decision = SecurityDecision(
                action=action,
                decision="requires_confirmation",
                reason_code=primary_reason_code,
                reason_message=admissibility.reason_message,
            )
            return RoutedActionDecision(
                adapter=adapter.name,
                action=action,
                status="requires_confirmation",
                reason_code=primary_reason_code,
                reason_message=admissibility.reason_message,
                required_capabilities=required_capability_tuple,
                granted_capabilities=requested_capability_tuple,
                source_channel=requested_source_channel,
                destination_channel=requested_dest_channel,
                provenance=source,
                artifact_state=artifact_state,
                transform=resolved_transform,
                security_decision=confirmation_decision,
                adapter_check=adapter_check,
                capability_profile=capability_profile,
                requested_capabilities=requested_capability_tuple,
                requested_channel=requested_channel_value,
                requested_ring=requested_ring_value,
                requested_destination=requested_destination_value,
                detector_verdict=admissibility.detector.verdict,
                detector_severity=admissibility.detector.severity,
                detector_reason_codes=admissibility.detector.reason_codes,
                changed_surfaces=admissibility.detector.changed_surfaces,
                admissibility_verdict=admissibility.verdict,
                bridge_status=admissibility.bridge.status,
                mu_exec_state=mu_exec_witness.state if mu_exec_witness else "",
                mu_exec_grounding_basis=mu_exec_witness.grounding_basis if mu_exec_witness else (),
                mu_exec_invariant_codes=mu_exec_witness.invariant_codes if mu_exec_witness else (),
                mu_exec_reason_codes=mu_exec_witness.reason_codes if mu_exec_witness else (),
                receipt=_with_receipt(
                    security_decision=confirmation_decision,
                    actor_role=actor_role,
                    actor_identity=actor_identity,
                    adapter_name=adapter.system_path,
                    scope=scope,
                    plan_ref=plan_ref,
                    resource=resource,
                    request_payload=request_payload,
                    requested_capabilities=requested_capability_tuple,
                    required_capabilities=required_capability_tuple,
                    granted_capabilities=requested_capability_tuple,
                    source_channel=requested_source_channel,
                    destination_channel=requested_dest_channel,
                    provenance=source,
                    artifact_state=artifact_state,
                    transform=resolved_transform,
                    requested_channel=requested_channel_value,
                    requested_ring=requested_ring_value,
                    requested_destination=requested_destination_value,
                    requested_artifact_hash=computed_requested_artifact_hash,
                    previous_artifact_hash=computed_previous_artifact_hash,
                    admissibility_verdict=admissibility.verdict,
                    detector_verdict=admissibility.detector.verdict,
                    detector_severity=admissibility.detector.severity,
                    detector_reason_codes=admissibility.detector.reason_codes,
                    changed_surfaces=admissibility.detector.changed_surfaces,
                    bridge_status=admissibility.bridge.status,
                    mu_exec_witness=mu_exec_witness,
                ),
            )
        return _deny_with_metadata(
            adapter_name=adapter.system_path,
            action=action,
            reason_code=primary_reason_code,
            reason_message=admissibility.reason_message,
            security_decision=security_decision,
            actor_role=actor_role,
            actor_identity=actor_identity,
            adapter=adapter.name,
            scope=scope,
            plan_ref=plan_ref,
            resource=resource,
            request_payload=request_payload,
            required_capabilities=required_capability_tuple,
            granted_capabilities=requested_capability_tuple,
            source_channel=requested_source_channel,
            destination_channel=requested_dest_channel,
            provenance=source,
            artifact_state=artifact_state,
            transform=resolved_transform,
            requested_capabilities=requested_capability_tuple,
            requested_channel=requested_channel_value,
            requested_ring=requested_ring_value,
            requested_destination=requested_destination_value,
            requested_artifact_hash=computed_requested_artifact_hash,
            previous_artifact_hash=computed_previous_artifact_hash,
            adapter_check=adapter_check,
            capability_profile=capability_profile,
            admissibility=admissibility,
            mu_exec_witness=mu_exec_witness,
        )

    if previous_caps and set(requested_capability_tuple) - set(previous_caps):
        return _deny_with_metadata(
            adapter_name=adapter.system_path,
            action=action,
            reason_code="capability_expansion_detected",
            reason_message=(
                f"Requested capabilities {requested_capability_tuple} expand prior state {previous_caps}"
            ),
            security_decision=security_decision,
            actor_role=actor_role,
            actor_identity=actor_identity,
            adapter=adapter.name,
            scope=scope,
            plan_ref=plan_ref,
            resource=resource,
            request_payload=request_payload,
            required_capabilities=required_capability_tuple,
            granted_capabilities=tuple(requested_capability_tuple),
            source_channel=requested_source_channel,
            destination_channel=requested_dest_channel,
            provenance=source,
            artifact_state=artifact_state,
            transform=resolved_transform,
            requested_capabilities=requested_capability_tuple,
            requested_channel=requested_channel_value,
            requested_ring=requested_ring_value,
            requested_destination=requested_destination_value,
            adapter_check=adapter_check,
            capability_profile=capability_profile,
        )

    if any(cap not in adapter.allowed_capabilities for cap in requested_capability_tuple) or any(
        cap not in capability_profile.capabilities for cap in requested_capability_tuple
    ):
        return _deny_with_metadata(
            adapter_name=adapter.system_path,
            action=action,
            reason_code="capability_widening_detected",
            reason_message=(
                f"Requested capability set {requested_capability_tuple} is not "
                f"covered by {adapter.name} action geometry"
            ),
            security_decision=security_decision,
            actor_role=actor_role,
            actor_identity=actor_identity,
            adapter=adapter.name,
            scope=scope,
            plan_ref=plan_ref,
            resource=resource,
            request_payload=request_payload,
            required_capabilities=required_capability_tuple,
            granted_capabilities=requested_capability_tuple,
            source_channel=requested_source_channel,
            destination_channel=requested_dest_channel,
            provenance=source,
            artifact_state=artifact_state,
            transform=resolved_transform,
            requested_capabilities=requested_capability_tuple,
            requested_channel=requested_channel_value,
            requested_ring=requested_ring_value,
            requested_destination=requested_destination_value,
            adapter_check=adapter_check,
            capability_profile=capability_profile,
        )

    if requested_transform and requested_transform not in capability_profile.transforms:
        return _deny_with_metadata(
            adapter_name=adapter.system_path,
            action=action,
            reason_code="transform_drift_detected",
            reason_message=(
                f"Requested transform '{requested_transform}' is outside action transform profile"
            ),
            security_decision=security_decision,
            actor_role=actor_role,
            actor_identity=actor_identity,
            adapter=adapter.name,
            scope=scope,
            plan_ref=plan_ref,
            resource=resource,
            request_payload=request_payload,
            required_capabilities=required_capability_tuple,
            granted_capabilities=requested_capability_tuple,
            source_channel=requested_source_channel,
            destination_channel=requested_dest_channel,
            provenance=source,
            artifact_state=artifact_state,
            transform=resolved_transform,
            requested_capabilities=requested_capability_tuple,
            requested_channel=requested_channel_value,
            requested_ring=requested_ring_value,
            requested_destination=requested_destination_value,
            adapter_check=adapter_check,
            capability_profile=capability_profile,
        )

    if previous_transform and requested_transform and requested_transform != previous_transform:
        return _deny_with_metadata(
            adapter_name=adapter.system_path,
            action=action,
            reason_code="transform_drift_detected",
            reason_message=(
                f"Requested transform '{requested_transform}' drifts from prior transform '{previous_transform}'"
            ),
            security_decision=security_decision,
            actor_role=actor_role,
            actor_identity=actor_identity,
            adapter=adapter.name,
            scope=scope,
            plan_ref=plan_ref,
            resource=resource,
            request_payload=request_payload,
            required_capabilities=required_capability_tuple,
            granted_capabilities=requested_capability_tuple,
            source_channel=requested_source_channel,
            destination_channel=requested_dest_channel,
            provenance=source,
            artifact_state=artifact_state,
            transform=resolved_transform,
            requested_capabilities=requested_capability_tuple,
            requested_channel=requested_channel_value,
            requested_ring=requested_ring_value,
            requested_destination=requested_destination_value,
            adapter_check=adapter_check,
            capability_profile=capability_profile,
        )

    if previous_artifact_state and artifact_state != previous_artifact_state:
        return _deny_with_metadata(
            adapter_name=adapter.system_path,
            action=action,
            reason_code="structural_anomaly_detected",
            reason_message=(
                f"Requested artifact state '{artifact_state}' changes prior state '{previous_artifact_state}'"
            ),
            security_decision=security_decision,
            actor_role=actor_role,
            actor_identity=actor_identity,
            adapter=adapter.name,
            scope=scope,
            plan_ref=plan_ref,
            resource=resource,
            request_payload=request_payload,
            required_capabilities=required_capability_tuple,
            granted_capabilities=requested_capability_tuple,
            source_channel=requested_source_channel,
            destination_channel=requested_dest_channel,
            provenance=source,
            artifact_state=artifact_state,
            transform=resolved_transform,
            requested_capabilities=requested_capability_tuple,
            requested_channel=requested_channel_value,
            requested_ring=requested_ring_value,
            requested_destination=requested_destination_value,
            adapter_check=adapter_check,
            capability_profile=capability_profile,
        )

    if (
        requested_channel_value not in adapter.allowed_channels
        or _legacy_to_lattice(requested_channel_value) not in allowed_source_channels
    ):
        return _deny_with_metadata(
            adapter_name=adapter.system_path,
            action=action,
            reason_code="channel_widening_detected",
            reason_message=(
                f"Requested channel '{requested_channel_value}' is outside declared channel space"
                f" for '{adapter.name}:{action}'"
            ),
            security_decision=security_decision,
            actor_role=actor_role,
            actor_identity=actor_identity,
            adapter=adapter.name,
            scope=scope,
            plan_ref=plan_ref,
            resource=resource,
            request_payload=request_payload,
            required_capabilities=required_capability_tuple,
            granted_capabilities=requested_capability_tuple,
            source_channel=requested_source_channel,
            destination_channel=requested_dest_channel,
            provenance=source,
            artifact_state=artifact_state,
            transform=resolved_transform,
            requested_capabilities=requested_capability_tuple,
            requested_channel=requested_channel_value,
            requested_ring=requested_ring_value,
            requested_destination=requested_destination_value,
            adapter_check=adapter_check,
            capability_profile=capability_profile,
        )

    if _channel_escalated(previous_source_channel_value, requested_source_channel):
        return _deny_with_metadata(
            adapter_name=adapter.system_path,
            action=action,
            reason_code="channel_escalation_detected",
            reason_message=(
                f"Requested source channel '{requested_source_channel}' escalates from"
                f" '{previous_source_channel_value}'"
            ),
            security_decision=security_decision,
            actor_role=actor_role,
            actor_identity=actor_identity,
            adapter=adapter.name,
            scope=scope,
            plan_ref=plan_ref,
            resource=resource,
            request_payload=request_payload,
            required_capabilities=required_capability_tuple,
            granted_capabilities=requested_capability_tuple,
            source_channel=requested_source_channel,
            destination_channel=requested_dest_channel,
            provenance=source,
            artifact_state=artifact_state,
            transform=resolved_transform,
            requested_capabilities=requested_capability_tuple,
            requested_channel=requested_channel_value,
            requested_ring=requested_ring_value,
            requested_destination=requested_destination_value,
            adapter_check=adapter_check,
            capability_profile=capability_profile,
        )

    if requested_destination_value not in adapter.allowed_destinations:
        return _deny_with_metadata(
            adapter_name=adapter.system_path,
            action=action,
            reason_code="destination_widening_detected",
            reason_message=(
                f"Requested destination '{requested_destination_value}' is outside declared destinations "
                f"for '{adapter.name}:{action}'"
            ),
            security_decision=security_decision,
            actor_role=actor_role,
            actor_identity=actor_identity,
            adapter=adapter.name,
            scope=scope,
            plan_ref=plan_ref,
            resource=resource,
            request_payload=request_payload,
            required_capabilities=required_capability_tuple,
            granted_capabilities=requested_capability_tuple,
            source_channel=requested_source_channel,
            destination_channel=requested_dest_channel,
            provenance=source,
            artifact_state=artifact_state,
            transform=resolved_transform,
            requested_capabilities=requested_capability_tuple,
            requested_channel=requested_channel_value,
            requested_ring=requested_ring_value,
            requested_destination=requested_destination_value,
            adapter_check=adapter_check,
            capability_profile=capability_profile,
        )

    if requested_dest_channel not in allowed_destination_channels:
        return _deny_with_metadata(
            adapter_name=adapter.system_path,
            action=action,
            reason_code="channel_escalation_detected",
            reason_message=(
                f"Requested destination channel '{requested_dest_channel}' is outside declared destination lattice"
            ),
            security_decision=security_decision,
            actor_role=actor_role,
            actor_identity=actor_identity,
            adapter=adapter.name,
            scope=scope,
            plan_ref=plan_ref,
            resource=resource,
            request_payload=request_payload,
            required_capabilities=required_capability_tuple,
            granted_capabilities=requested_capability_tuple,
            source_channel=requested_source_channel,
            destination_channel=requested_dest_channel,
            provenance=source,
            artifact_state=artifact_state,
            transform=resolved_transform,
            requested_capabilities=requested_capability_tuple,
            requested_channel=requested_channel_value,
            requested_ring=requested_ring_value,
            requested_destination=requested_destination_value,
            adapter_check=adapter_check,
            capability_profile=capability_profile,
        )

    if _channel_escalated(previous_destination_channel_value, requested_dest_channel):
        return _deny_with_metadata(
            adapter_name=adapter.system_path,
            action=action,
            reason_code="channel_escalation_detected",
            reason_message=(
                f"Requested destination channel '{requested_dest_channel}' escalates from"
                f" '{previous_destination_channel_value}'"
            ),
            security_decision=security_decision,
            actor_role=actor_role,
            actor_identity=actor_identity,
            adapter=adapter.name,
            scope=scope,
            plan_ref=plan_ref,
            resource=resource,
            request_payload=request_payload,
            required_capabilities=required_capability_tuple,
            granted_capabilities=requested_capability_tuple,
            source_channel=requested_source_channel,
            destination_channel=requested_dest_channel,
            provenance=source,
            artifact_state=artifact_state,
            transform=resolved_transform,
            requested_capabilities=requested_capability_tuple,
            requested_channel=requested_channel_value,
            requested_ring=requested_ring_value,
            requested_destination=requested_destination_value,
            adapter_check=adapter_check,
            capability_profile=capability_profile,
        )

    if _ring_escalated(previous_ring_value, requested_ring_value):
        return _deny_with_metadata(
            adapter_name=adapter.system_path,
            action=action,
            reason_code="ring_escalation_detected",
            reason_message=(
                f"Requested ring '{requested_ring_value}' escalates from '{previous_ring_value}'"
            ),
            security_decision=security_decision,
            actor_role=actor_role,
            actor_identity=actor_identity,
            adapter=adapter.name,
            scope=scope,
            plan_ref=plan_ref,
            resource=resource,
            request_payload=request_payload,
            required_capabilities=required_capability_tuple,
            granted_capabilities=requested_capability_tuple,
            source_channel=requested_source_channel,
            destination_channel=requested_dest_channel,
            provenance=source,
            artifact_state=artifact_state,
            transform=resolved_transform,
            requested_capabilities=requested_capability_tuple,
            requested_channel=requested_channel_value,
            requested_ring=requested_ring_value,
            requested_destination=requested_destination_value,
            adapter_check=adapter_check,
            capability_profile=capability_profile,
        )

    if requested_ring_value not in adapter.allowed_rings or requested_ring_value not in capability_profile.rings:
        return _deny_with_metadata(
            adapter_name=adapter.system_path,
            action=action,
            reason_code="ring_widening_detected",
            reason_message=(
                f"Requested ring '{requested_ring_value}' is outside declared ring "
                f"space for '{adapter.name}:{action}'"
            ),
            security_decision=security_decision,
            actor_role=actor_role,
            actor_identity=actor_identity,
            adapter=adapter.name,
            scope=scope,
            plan_ref=plan_ref,
            resource=resource,
            request_payload=request_payload,
            required_capabilities=required_capability_tuple,
            granted_capabilities=requested_capability_tuple,
            source_channel=requested_source_channel,
            destination_channel=requested_dest_channel,
            provenance=source,
            artifact_state=artifact_state,
            transform=resolved_transform,
            requested_capabilities=requested_capability_tuple,
            requested_channel=requested_channel_value,
            requested_ring=requested_ring_value,
            requested_destination=requested_destination_value,
            adapter_check=adapter_check,
            capability_profile=capability_profile,
        )

    if requested_ring_value == "remote" and source == "public":
        return _deny_with_metadata(
            adapter_name=adapter.system_path,
            action=action,
            reason_code="proposal_ring_violation",
            reason_message=(
                "Public/proposal contexts cannot request remote ring execution without explicit managed handoff"
            ),
            security_decision=security_decision,
            actor_role=actor_role,
            actor_identity=actor_identity,
            adapter=adapter.name,
            scope=scope,
            plan_ref=plan_ref,
            resource=resource,
            request_payload=request_payload,
            required_capabilities=required_capability_tuple,
            granted_capabilities=requested_capability_tuple,
            source_channel=requested_source_channel,
            destination_channel=requested_dest_channel,
            provenance=source,
            artifact_state=artifact_state,
            transform=resolved_transform,
            requested_capabilities=requested_capability_tuple,
            requested_channel=requested_channel_value,
            requested_ring=requested_ring_value,
            requested_destination=requested_destination_value,
            adapter_check=adapter_check,
            capability_profile=capability_profile,
        )

    if requested_ring_value == "remote" and request_payload and not payload_sanitized:
        return _deny_with_metadata(
            adapter_name=adapter.system_path,
            action=action,
            reason_code="unsanitized_remote_request",
            reason_message=(
                "Remote requests must use sanitized payload and explicit channel classification"
            ),
            security_decision=security_decision,
            actor_role=actor_role,
            actor_identity=actor_identity,
            adapter=adapter.name,
            scope=scope,
            plan_ref=plan_ref,
            resource=resource,
            request_payload=request_payload,
            required_capabilities=required_capability_tuple,
            granted_capabilities=requested_capability_tuple,
            source_channel=requested_source_channel,
            destination_channel=requested_dest_channel,
            provenance=source,
            artifact_state=artifact_state,
            transform=resolved_transform,
            requested_capabilities=requested_capability_tuple,
            requested_channel=requested_channel_value,
            requested_ring=requested_ring_value,
            requested_destination=requested_destination_value,
            adapter_check=adapter_check,
            capability_profile=capability_profile,
        )

    if security_decision.decision == "requires_confirmation":
        confirmation_context = [
            f"risk={risk_level}",
            f"requested_channel={requested_source_channel}/{requested_dest_channel}",
            f"requested_ring={requested_ring_value}",
        ]
        if previous_caps:
            confirmation_context.append(f"previous_capabilities={previous_caps}")
            confirmation_context.append(f"requested_capabilities={requested_capability_tuple}")
        return RoutedActionDecision(
            adapter=adapter.name,
            action=action,
            status="requires_confirmation",
            reason_code=security_decision.reason_code,
            reason_message=(
                f"{security_decision.reason_message} "
                f"(confirmation context: {', '.join(confirmation_context)})"
            ),
            required_capabilities=required_capability_tuple,
            granted_capabilities=requested_capability_tuple,
            source_channel=requested_source_channel,
            destination_channel=requested_dest_channel,
            provenance=source,
            artifact_state=artifact_state,
            transform=resolved_transform,
            security_decision=security_decision,
            adapter_check=adapter_check,
            capability_profile=capability_profile,
            requested_capabilities=requested_capability_tuple,
            requested_channel=requested_channel_value,
            requested_ring=requested_ring_value,
            requested_destination=requested_destination_value,
            detector_verdict=admissibility.detector.verdict,
            detector_severity=admissibility.detector.severity,
            detector_reason_codes=admissibility.detector.reason_codes,
            changed_surfaces=admissibility.detector.changed_surfaces,
            admissibility_verdict=admissibility.verdict,
            bridge_status=admissibility.bridge.status,
            mu_exec_state=mu_exec_witness.state if mu_exec_witness else "",
            mu_exec_grounding_basis=mu_exec_witness.grounding_basis if mu_exec_witness else (),
            mu_exec_invariant_codes=mu_exec_witness.invariant_codes if mu_exec_witness else (),
            mu_exec_reason_codes=mu_exec_witness.reason_codes if mu_exec_witness else (),
            receipt=_with_receipt(
                security_decision=security_decision,
                actor_role=actor_role,
                actor_identity=actor_identity,
                adapter_name=adapter.system_path,
                scope=scope,
                plan_ref=plan_ref,
                resource=resource,
                request_payload=request_payload,
                requested_capabilities=requested_capability_tuple,
                required_capabilities=required_capability_tuple,
                granted_capabilities=requested_capability_tuple,
                source_channel=requested_source_channel,
                destination_channel=requested_dest_channel,
                provenance=source,
                artifact_state=artifact_state,
                transform=resolved_transform,
                requested_channel=requested_channel_value,
                requested_ring=requested_ring_value,
                requested_destination=requested_destination_value,
                requested_artifact_hash=computed_requested_artifact_hash,
                previous_artifact_hash=computed_previous_artifact_hash,
                admissibility_verdict=admissibility.verdict,
                detector_verdict=admissibility.detector.verdict,
                detector_severity=admissibility.detector.severity,
                detector_reason_codes=admissibility.detector.reason_codes,
                changed_surfaces=admissibility.detector.changed_surfaces,
                bridge_status=admissibility.bridge.status,
                mu_exec_witness=mu_exec_witness,
            ),
        )

    return RoutedActionDecision(
        adapter=adapter.name,
        action=action,
        status="allow",
        reason_code="policy_allow",
        reason_message="Adapter and policy checks passed.",
        required_capabilities=required_capability_tuple,
        granted_capabilities=requested_capability_tuple,
        source_channel=requested_source_channel,
        destination_channel=requested_dest_channel,
        provenance=source,
        artifact_state=artifact_state,
        transform=resolved_transform,
        security_decision=security_decision,
        adapter_check=adapter_check,
        capability_profile=capability_profile,
        requested_capabilities=requested_capability_tuple,
        requested_channel=requested_channel_value,
        requested_ring=requested_ring_value,
        requested_destination=requested_destination_value,
        detector_verdict=admissibility.detector.verdict,
        detector_severity=admissibility.detector.severity,
        detector_reason_codes=admissibility.detector.reason_codes,
        changed_surfaces=admissibility.detector.changed_surfaces,
        admissibility_verdict=admissibility.verdict,
        bridge_status=admissibility.bridge.status,
        mu_exec_state=mu_exec_witness.state if mu_exec_witness else "",
        mu_exec_grounding_basis=mu_exec_witness.grounding_basis if mu_exec_witness else (),
        mu_exec_invariant_codes=mu_exec_witness.invariant_codes if mu_exec_witness else (),
        mu_exec_reason_codes=mu_exec_witness.reason_codes if mu_exec_witness else (),
        receipt=_with_receipt(
            security_decision=security_decision,
            actor_role=actor_role,
            actor_identity=actor_identity,
            adapter_name=adapter.system_path,
            scope=scope,
            plan_ref=plan_ref,
            resource=resource,
            request_payload=request_payload,
            requested_capabilities=requested_capability_tuple,
            required_capabilities=required_capability_tuple,
            granted_capabilities=requested_capability_tuple,
            source_channel=requested_source_channel,
            destination_channel=requested_dest_channel,
            provenance=source,
            artifact_state=artifact_state,
            transform=resolved_transform,
            requested_channel=requested_channel_value,
            requested_ring=requested_ring_value,
            requested_destination=requested_destination_value,
            requested_artifact_hash=computed_requested_artifact_hash,
            previous_artifact_hash=computed_previous_artifact_hash,
            admissibility_verdict=admissibility.verdict,
            detector_verdict=admissibility.detector.verdict,
            detector_severity=admissibility.detector.severity,
            detector_reason_codes=admissibility.detector.reason_codes,
            changed_surfaces=admissibility.detector.changed_surfaces,
            bridge_status=admissibility.bridge.status,
            mu_exec_witness=mu_exec_witness,
        ),
    )
