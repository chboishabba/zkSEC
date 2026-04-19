"""Transform admissibility, bridge, and detector primitives for zkSEC."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Mapping

from .mu_exec import MuExecWitness


DetectorVerdict = Literal["allow", "requires_confirmation", "quarantine", "reject"]
Severity = Literal["none", "low", "medium", "high", "critical"]
AdmissibilityVerdict = Literal[
    "allow",
    "allow_with_confirmation",
    "quarantine",
    "sandbox",
    "reject",
]
ProposalState = Literal["proposal", "control", "sovereign"]
BridgeStatus = Literal["not_applicable", "proposal_only", "rejected"]
AttackScenarioVerdict = Literal["allow", "blocked"]

CAPABILITY_CLASSES: tuple[str, ...] = (
    "read",
    "write",
    "execute",
    "network_egress",
    "identity_mutation",
    "policy_mutation",
)
CHANNEL_CLASSES: tuple[str, ...] = ("local", "self", "trusted_peer", "public", "remote_api")
RING_CLASSES: tuple[str, ...] = ("sovereign", "bounded", "remote")
ARTIFACT_CLASSES: tuple[str, ...] = (
    "config",
    "document",
    "embedding",
    "image",
    "report",
    "runtime_witness",
    "semantic_map",
    "unknown",
)
TRANSFORM_CLASSES: tuple[str, ...] = (
    "classify",
    "deploy",
    "ingest",
    "normalize",
    "patch",
    "plan",
    "publish",
    "read",
    "review",
    "summarize",
    "sync",
    "transform",
    "update",
)
PROPOSAL_STATES: tuple[ProposalState, ...] = ("proposal", "control", "sovereign")

ALLOWED_ZOS_INBOUND_FIELDS: tuple[str, ...] = (
    "alias_hints",
    "embedding_neighborhood",
    "factor_coordinates",
    "normalization_hints",
    "provenance",
    "resonance",
    "semantic_clusters",
    "structural_similarity",
)
FORBIDDEN_ZOS_AUTHORITY_FIELDS: tuple[str, ...] = (
    "capability_decision",
    "channel_elevation",
    "execute_authority",
    "policy_mutation",
    "publish_authority",
    "truth_promotion",
)


def _clip_axis(value: float) -> int:
    if value <= 0:
        return 0
    if value >= 25:
        return 25
    return round(value)


def _normalize_labels(values: tuple[str, ...] | None) -> tuple[str, ...]:
    if not values:
        return ()
    return tuple(sorted({item.strip().lower() for item in values if item and item.strip()}))


def _severity_rank(value: Severity) -> int:
    order: tuple[Severity, ...] = ("none", "low", "medium", "high", "critical")
    return order.index(value)


@dataclass(frozen=True)
class DetectorSignal:
    """Normalized output for one detector surface."""

    surface: str
    verdict: DetectorVerdict
    severity: Severity
    changed_surfaces: tuple[str, ...]
    expected: dict[str, str]
    observed: dict[str, str]
    reason_codes: tuple[str, ...]
    reason_message: str


@dataclass(frozen=True)
class UnifiedDetectorOutput:
    """Detector output spanning capability, channel, delta, and ontology surfaces."""

    verdict: DetectorVerdict
    severity: Severity
    changed_surfaces: tuple[str, ...]
    reason_codes: tuple[str, ...]
    capability: DetectorSignal
    channel: DetectorSignal
    delta: DetectorSignal
    ontology: DetectorSignal


@dataclass(frozen=True)
class OntologyDelta:
    """Compact semantic poisoning surface for proposal-only evaluation."""

    canonical_terms: tuple[str, ...] = ()
    alias_terms: tuple[str, ...] = ()
    new_canonical_terms: tuple[str, ...] = ()
    new_alias_terms: tuple[str, ...] = ()
    affected_clusters: tuple[str, ...] = ()
    control_terms: tuple[str, ...] = ()
    supporting_refs_count: int = 0
    weak_refs_count: int = 0
    compression_gain: float = 0.0
    groundedness_loss: float = 0.0
    resonance_lift: float = 0.0
    provenance_weakness: float = 0.0
    cluster_pull: float = 0.0
    control_inconsistency: float = 0.0
    alias_pressure: float = 0.0

    def normalized(self) -> "OntologyDelta":
        return OntologyDelta(
            canonical_terms=_normalize_labels(self.canonical_terms),
            alias_terms=_normalize_labels(self.alias_terms),
            new_canonical_terms=_normalize_labels(self.new_canonical_terms),
            new_alias_terms=_normalize_labels(self.new_alias_terms),
            affected_clusters=_normalize_labels(self.affected_clusters),
            control_terms=_normalize_labels(self.control_terms),
            supporting_refs_count=max(0, self.supporting_refs_count),
            weak_refs_count=max(0, self.weak_refs_count),
            compression_gain=min(max(self.compression_gain, 0.0), 1.0),
            groundedness_loss=min(max(self.groundedness_loss, 0.0), 1.0),
            resonance_lift=min(max(self.resonance_lift, 0.0), 1.0),
            provenance_weakness=min(max(self.provenance_weakness, 0.0), 1.0),
            cluster_pull=min(max(self.cluster_pull, 0.0), 1.0),
            control_inconsistency=min(max(self.control_inconsistency, 0.0), 1.0),
            alias_pressure=min(max(self.alias_pressure, 0.0), 1.0),
        )


@dataclass(frozen=True)
class WitnessExpectation:
    """Expected witness geometry for a transform before activation."""

    declared_ring: str
    expected_capabilities: tuple[str, ...]
    expected_source_channels: tuple[str, ...]
    expected_destination_channels: tuple[str, ...]


@dataclass(frozen=True)
class ZOSBridgeResult:
    """Normalized bridge output for inbound ZOS semantic proposals."""

    status: BridgeStatus
    proposal_state: ProposalState
    ring: str
    allowed_fields: tuple[str, ...]
    forbidden_fields: tuple[str, ...]
    proposal_metadata: dict[str, str]
    reason_codes: tuple[str, ...]
    reason_message: str


@dataclass(frozen=True)
class AdmissibilityInput:
    """Tuple defining whether a transform may activate."""

    prior_state: str
    proposed_state: str
    artifact_class: str
    delta_surface: str
    capability_delta: tuple[str, ...]
    channel_delta: tuple[str, ...]
    semantic_delta: OntologyDelta | None
    proposal_state: ProposalState
    source: str
    ring: str
    expected_capabilities: tuple[str, ...]
    observed_capabilities: tuple[str, ...]
    previous_capabilities: tuple[str, ...]
    expected_source_channels: tuple[str, ...]
    observed_source_channel: str
    previous_source_channel: str
    expected_destination_channels: tuple[str, ...]
    observed_destination_channel: str
    previous_destination_channel: str
    expected_transforms: tuple[str, ...]
    observed_transform: str
    previous_transform: str
    expected_destinations: tuple[str, ...]
    observed_destination: str
    expected_rings: tuple[str, ...]
    previous_ring: str
    request_payload_present: bool = False
    payload_sanitized: bool = False
    zos_proposal: Mapping[str, object] | None = None
    witness: WitnessExpectation | None = None
    mu_exec_witness: MuExecWitness | None = None


@dataclass(frozen=True)
class AdmissibilityDecision:
    """Final transform admissibility decision."""

    verdict: AdmissibilityVerdict
    reason_codes: tuple[str, ...]
    reason_message: str
    detector: UnifiedDetectorOutput
    bridge: ZOSBridgeResult


@dataclass(frozen=True)
class AttackStep:
    """One admissibility evaluation inside a chain harness."""

    name: str
    candidate: AdmissibilityInput


@dataclass(frozen=True)
class AttackChainResult:
    """Outcome of a multi-step attack scenario evaluation."""

    verdict: AttackScenarioVerdict
    blocking_step: str
    reason_codes: tuple[str, ...]
    decisions: tuple[AdmissibilityDecision, ...]


def bridge_zos_proposal(
    *,
    metadata: Mapping[str, object] | None,
    proposal_state: ProposalState,
    ring: str,
) -> ZOSBridgeResult:
    """Accept ZOS metadata only as proposal-side inputs."""

    if not metadata:
        return ZOSBridgeResult(
            status="not_applicable",
            proposal_state=proposal_state,
            ring=ring,
            allowed_fields=ALLOWED_ZOS_INBOUND_FIELDS,
            forbidden_fields=(),
            proposal_metadata={},
            reason_codes=(),
            reason_message="No ZOS proposal metadata supplied.",
        )

    forbidden = tuple(sorted(key for key in metadata if key in FORBIDDEN_ZOS_AUTHORITY_FIELDS))
    normalized = {
        key: str(metadata[key])
        for key in sorted(metadata)
        if key in ALLOWED_ZOS_INBOUND_FIELDS
    }
    if forbidden:
        return ZOSBridgeResult(
            status="rejected",
            proposal_state="proposal",
            ring=ring,
            allowed_fields=ALLOWED_ZOS_INBOUND_FIELDS,
            forbidden_fields=forbidden,
            proposal_metadata=normalized,
            reason_codes=("forbidden_authority_crossing_detected",),
            reason_message=(
                "ZOS inputs may contribute proposal metadata only; authority fields are blocked."
            ),
        )

    return ZOSBridgeResult(
        status="proposal_only",
        proposal_state="proposal",
        ring=ring,
        allowed_fields=ALLOWED_ZOS_INBOUND_FIELDS,
        forbidden_fields=(),
        proposal_metadata=normalized,
        reason_codes=("proposal_metadata_only",),
        reason_message="ZOS inputs were accepted as proposal metadata only.",
    )


def assess_ontology_surface(
    *,
    ontology: OntologyDelta | None,
    source: str,
    proposal_state: ProposalState,
) -> DetectorSignal:
    """Evaluate ontology poisoning pressure without promoting authority."""

    if ontology is None:
        return DetectorSignal(
            surface="F_onto",
            verdict="allow",
            severity="none",
            changed_surfaces=(),
            expected={"proposal_state": proposal_state},
            observed={"proposal_state": proposal_state},
            reason_codes=("ontology_surface_allow",),
            reason_message="No ontology delta supplied.",
        )

    normalized = ontology.normalized()
    axis_compression = _clip_axis(
        25 * max(0.0, normalized.compression_gain - (normalized.groundedness_loss * 0.6))
    )
    axis_resonance = _clip_axis(
        25 * max(0.0, normalized.resonance_lift - (normalized.provenance_weakness * 0.6))
    )
    axis_cluster = _clip_axis(
        25 * max(0.0, normalized.cluster_pull - (normalized.control_inconsistency * 0.6))
    )
    axis_alias = _clip_axis(25 * normalized.alias_pressure)
    score = axis_compression + axis_resonance + axis_cluster + axis_alias

    reason_codes: list[str] = []
    changed_surfaces = ["semantic_delta"]
    verdict: DetectorVerdict = "allow"
    severity: Severity = "low" if score else "none"
    message = "Ontology surface is grounded and within declared control vocabulary."

    if (
        source == "public"
        and normalized.new_canonical_terms
        and normalized.control_terms
        and proposal_state != "control"
    ):
        verdict = "reject"
        severity = "critical"
        reason_codes.append("public_ontology_promotion_blocked")
        message = "Public ontology proposals cannot alter control vocabulary without managed promotion."

    if normalized.compression_gain >= 0.7 and normalized.groundedness_loss >= 0.5:
        verdict = "reject"
        severity = "high"
        reason_codes.append("compression_without_grounding")
        message = "Compression gain outruns grounded support."
    elif normalized.resonance_lift >= 0.7 and normalized.provenance_weakness >= 0.6:
        verdict = "reject"
        severity = "high"
        reason_codes.append("resonance_without_provenance")
        message = "Resonance rose without strong provenance."
    elif normalized.cluster_pull >= 0.6 and normalized.control_inconsistency >= 0.5:
        verdict = "reject"
        severity = "high"
        reason_codes.append("cluster_pull_control_conflict")
        message = "Semantic cluster pull conflicts with control vocabulary."
    elif normalized.alias_pressure >= 0.8 and normalized.new_alias_terms:
        verdict = "reject"
        severity = "high"
        reason_codes.append("alias_pressure_detected")
        message = "Alias pressure exceeds safe canonicalization bounds."
    elif score >= 70:
        verdict = "reject"
        severity = "high"
        reason_codes.append("ontology_poisoning_suspected")
        message = "Ontology surface matches a poisoning profile."
    elif score >= 50:
        verdict = "requires_confirmation"
        severity = "medium"
        reason_codes.append("ontology_drift_requires_confirmation")
        message = "Ontology drift needs managed confirmation before promotion."
    elif score >= 25 and source != "managed":
        verdict = "requires_confirmation"
        severity = "medium"
        reason_codes.append("ontology_drift_requires_confirmation")
        message = "Undercertain ontology drift requires confirmation."

    if not reason_codes:
        reason_codes.append("ontology_surface_allow")

    return DetectorSignal(
        surface="F_onto",
        verdict=verdict,
        severity=severity,
        changed_surfaces=tuple(changed_surfaces if score or normalized.new_alias_terms or normalized.new_canonical_terms else ()),
        expected={"proposal_state": proposal_state, "supporting_refs": str(normalized.supporting_refs_count)},
        observed={
            "score": str(score),
            "compression_gain": f"{normalized.compression_gain:.2f}",
            "groundedness_loss": f"{normalized.groundedness_loss:.2f}",
            "resonance_lift": f"{normalized.resonance_lift:.2f}",
            "provenance_weakness": f"{normalized.provenance_weakness:.2f}",
            "cluster_pull": f"{normalized.cluster_pull:.2f}",
            "control_inconsistency": f"{normalized.control_inconsistency:.2f}",
            "alias_pressure": f"{normalized.alias_pressure:.2f}",
        },
        reason_codes=tuple(reason_codes),
        reason_message=message,
    )


def _build_signal(
    *,
    surface: str,
    expected: dict[str, str],
    observed: dict[str, str],
    changed_surfaces: tuple[str, ...],
    reason_codes: tuple[str, ...],
    reason_message: str,
) -> DetectorSignal:
    if not reason_codes:
        return DetectorSignal(
            surface=surface,
            verdict="allow",
            severity="none",
            changed_surfaces=(),
            expected=expected,
            observed=observed,
            reason_codes=(f"{surface}_allow",),
            reason_message=f"{surface} is within declared bounds.",
        )

    verdict: DetectorVerdict = "reject"
    severity: Severity = "high"
    if any(code.endswith("requires_confirmation") for code in reason_codes):
        verdict = "requires_confirmation"
        severity = "medium"
    return DetectorSignal(
        surface=surface,
        verdict=verdict,
        severity=severity,
        changed_surfaces=changed_surfaces,
        expected=expected,
        observed=observed,
        reason_codes=reason_codes,
        reason_message=reason_message,
    )


def evaluate_unified_detector(*, candidate: AdmissibilityInput) -> UnifiedDetectorOutput:
    """Return a normalized detector signal spanning the four core surfaces."""

    capability_codes: list[str] = []
    capability_message = "Capability surface matches declared geometry."
    requested_caps = tuple(candidate.observed_capabilities)
    previous_caps = tuple(candidate.previous_capabilities)
    expected_caps = tuple(candidate.expected_capabilities)
    if previous_caps and set(requested_caps) - set(previous_caps):
        capability_codes.append("capability_expansion_detected")
        capability_message = (
            f"Requested capabilities {requested_caps} expand prior state {previous_caps}"
        )
    elif any(cap not in CAPABILITY_CLASSES for cap in requested_caps) or any(
        cap not in expected_caps for cap in requested_caps
    ):
        capability_codes.append("capability_widening_detected")
        capability_message = (
            f"Requested capability set {requested_caps} is not covered by declared action geometry"
        )
    capability_signal = _build_signal(
        surface="F_cap",
        expected={"required_capabilities": ",".join(expected_caps)},
        observed={"requested_capabilities": ",".join(requested_caps)},
        changed_surfaces=("capability",) if capability_codes else (),
        reason_codes=tuple(capability_codes),
        reason_message=capability_message,
    )

    channel_codes: list[str] = []
    channel_message = "Channel surface matches declared geometry."
    if candidate.observed_source_channel not in candidate.expected_source_channels:
        channel_codes.append("channel_widening_detected")
        channel_message = (
            f"Requested source channel '{candidate.observed_source_channel}' is outside declared channel space"
        )
    elif (
        candidate.previous_source_channel
        and candidate.previous_source_channel in CHANNEL_CLASSES
        and candidate.observed_source_channel in CHANNEL_CLASSES
        and CHANNEL_CLASSES.index(candidate.observed_source_channel)
        > CHANNEL_CLASSES.index(candidate.previous_source_channel)
    ):
        channel_codes.append("channel_escalation_detected")
        channel_message = (
            f"Requested source channel '{candidate.observed_source_channel}' escalates from "
            f"'{candidate.previous_source_channel}'"
        )
    elif (
        candidate.observed_destination in candidate.expected_destinations
        and candidate.observed_destination_channel not in candidate.expected_destination_channels
    ):
        channel_codes.append("channel_escalation_detected")
        channel_message = (
            f"Requested destination channel '{candidate.observed_destination_channel}' is outside declared destination lattice"
        )
    elif (
        candidate.previous_destination_channel
        and candidate.previous_destination_channel in CHANNEL_CLASSES
        and candidate.observed_destination_channel in CHANNEL_CLASSES
        and CHANNEL_CLASSES.index(candidate.observed_destination_channel)
        > CHANNEL_CLASSES.index(candidate.previous_destination_channel)
    ):
        channel_codes.append("channel_escalation_detected")
        channel_message = (
            f"Requested destination channel '{candidate.observed_destination_channel}' escalates from "
            f"'{candidate.previous_destination_channel}'"
        )
    channel_signal = _build_signal(
        surface="F_channel",
        expected={
            "source_channels": ",".join(candidate.expected_source_channels),
            "destination_channels": ",".join(candidate.expected_destination_channels),
        },
        observed={
            "source_channel": candidate.observed_source_channel,
            "destination_channel": candidate.observed_destination_channel,
        },
        changed_surfaces=("channel",) if channel_codes else (),
        reason_codes=tuple(channel_codes),
        reason_message=channel_message,
    )

    delta_codes: list[str] = []
    delta_message = "Transform and structure remain within the declared class."
    if candidate.observed_transform not in candidate.expected_transforms:
        delta_codes.append("transform_drift_detected")
        delta_message = (
            f"Requested transform '{candidate.observed_transform}' is outside action transform profile"
        )
    elif (
        candidate.previous_transform
        and candidate.observed_transform != candidate.previous_transform
    ):
        delta_codes.append("transform_drift_detected")
        delta_message = (
            f"Requested transform '{candidate.observed_transform}' drifts from prior transform "
            f"'{candidate.previous_transform}'"
        )
    elif candidate.prior_state and candidate.proposed_state != candidate.prior_state:
        delta_codes.append("structural_anomaly_detected")
        delta_message = (
            f"Requested artifact state '{candidate.proposed_state}' changes prior state '{candidate.prior_state}'"
        )
    elif candidate.observed_destination not in candidate.expected_destinations:
        delta_codes.append("destination_widening_detected")
        delta_message = (
            f"Requested destination '{candidate.observed_destination}' is outside declared destinations"
        )
    elif (
        candidate.previous_ring
        and candidate.previous_ring in RING_CLASSES
        and candidate.ring in RING_CLASSES
        and RING_CLASSES.index(candidate.ring) > RING_CLASSES.index(candidate.previous_ring)
    ):
        delta_codes.append("ring_escalation_detected")
        delta_message = (
            f"Requested ring '{candidate.ring}' escalates from '{candidate.previous_ring}'"
        )
    elif candidate.ring not in candidate.expected_rings:
        delta_codes.append("ring_widening_detected")
        delta_message = f"Requested ring '{candidate.ring}' is outside declared ring space"
    elif candidate.ring == "remote" and candidate.request_payload_present and not candidate.payload_sanitized:
        delta_codes.append("unsanitized_remote_request")
        delta_message = "Remote requests must use sanitized payload and explicit channel classification"
    delta_signal = _build_signal(
        surface="F_delta",
        expected={
            "transforms": ",".join(candidate.expected_transforms),
            "destinations": ",".join(candidate.expected_destinations),
            "rings": ",".join(candidate.expected_rings),
        },
        observed={
            "transform": candidate.observed_transform,
            "destination": candidate.observed_destination,
            "ring": candidate.ring,
            "prior_state": candidate.prior_state,
            "proposed_state": candidate.proposed_state,
        },
        changed_surfaces=("transform", "structure") if delta_codes else (),
        reason_codes=tuple(delta_codes),
        reason_message=delta_message,
    )

    ontology_signal = assess_ontology_surface(
        ontology=candidate.semantic_delta,
        source=candidate.source,
        proposal_state=candidate.proposal_state,
    )

    signals = (capability_signal, channel_signal, delta_signal, ontology_signal)
    severity = max((signal.severity for signal in signals), key=_severity_rank)
    verdict = "allow"
    if any(signal.verdict == "reject" for signal in signals):
        verdict = "reject"
    elif any(signal.verdict == "quarantine" for signal in signals):
        verdict = "quarantine"
    elif any(signal.verdict == "requires_confirmation" for signal in signals):
        verdict = "requires_confirmation"
    reason_codes = tuple(
        code
        for signal in signals
        for code in signal.reason_codes
        if not code.endswith("_allow") and code != "ontology_surface_allow"
    )
    changed_surfaces = tuple(
        sorted({changed for signal in signals for changed in signal.changed_surfaces})
    )
    return UnifiedDetectorOutput(
        verdict=verdict,
        severity=severity,
        changed_surfaces=changed_surfaces,
        reason_codes=reason_codes,
        capability=capability_signal,
        channel=channel_signal,
        delta=delta_signal,
        ontology=ontology_signal,
    )


def evaluate_transform_admissibility(*, candidate: AdmissibilityInput) -> AdmissibilityDecision:
    """Evaluate whether a transform may activate."""

    bridge = bridge_zos_proposal(
        metadata=candidate.zos_proposal,
        proposal_state=candidate.proposal_state,
        ring=candidate.ring,
    )
    detector = evaluate_unified_detector(candidate=candidate)
    reason_codes: list[str] = list(detector.reason_codes)
    if bridge.status == "rejected":
        reason_codes = list(bridge.reason_codes) + reason_codes
        return AdmissibilityDecision(
            verdict="reject",
            reason_codes=tuple(reason_codes),
            reason_message=bridge.reason_message,
            detector=detector,
            bridge=bridge,
        )

    if candidate.source == "public" and candidate.ring == "remote":
        reason_codes.append("proposal_ring_violation")
        return AdmissibilityDecision(
            verdict="reject",
            reason_codes=tuple(reason_codes),
            reason_message=(
                "Public/proposal contexts cannot request remote ring execution without explicit managed handoff"
            ),
            detector=detector,
            bridge=bridge,
        )

    if candidate.witness is not None:
        if candidate.ring != candidate.witness.declared_ring:
            reason_codes.append("witness_ring_violation")
            return AdmissibilityDecision(
                verdict="reject",
                reason_codes=tuple(reason_codes),
                reason_message="Runtime witness expectation does not match the declared ring.",
                detector=detector,
                bridge=bridge,
            )
        if set(candidate.observed_capabilities) - set(candidate.witness.expected_capabilities):
            reason_codes.append("witness_capability_violation")
            return AdmissibilityDecision(
                verdict="reject",
                reason_codes=tuple(reason_codes),
                reason_message="Runtime witness expectation does not match requested capabilities.",
                detector=detector,
                bridge=bridge,
            )

    if candidate.mu_exec_witness is not None:
        mu_exec_witness = candidate.mu_exec_witness.normalized()
        if mu_exec_witness.state == "invariant_failure":
            reason_codes.extend(mu_exec_witness.reason_codes or mu_exec_witness.invariant_codes)
            return AdmissibilityDecision(
                verdict="reject",
                reason_codes=tuple(reason_codes),
                reason_message=(
                    "Grounded mu_exec witness failed execution invariants."
                ),
                detector=detector,
                bridge=bridge,
            )
        if mu_exec_witness.state == "proposal_only":
            reason_codes.extend(mu_exec_witness.reason_codes or ("mu_exec_grounding_required",))
            return AdmissibilityDecision(
                verdict="allow_with_confirmation",
                reason_codes=tuple(reason_codes),
                reason_message=(
                    "mu_exec evidence is still proposal-only and requires grounding before authority-bearing conclusions."
                ),
                detector=detector,
                bridge=bridge,
            )

    if detector.verdict == "reject":
        primary_message = next(
            (
                signal.reason_message
                for signal in (
                    detector.capability,
                    detector.channel,
                    detector.delta,
                    detector.ontology,
                )
                if signal.verdict == "reject"
            ),
            "Transform is not admissible.",
        )
        return AdmissibilityDecision(
            verdict="reject",
            reason_codes=tuple(reason_codes),
            reason_message=primary_message,
            detector=detector,
            bridge=bridge,
        )

    if detector.verdict == "requires_confirmation":
        return AdmissibilityDecision(
            verdict="allow_with_confirmation",
            reason_codes=tuple(reason_codes),
            reason_message="Transform is admissible only with managed confirmation.",
            detector=detector,
            bridge=bridge,
        )

    return AdmissibilityDecision(
        verdict="allow",
        reason_codes=tuple(reason_codes),
        reason_message="Transform is admissible within declared capability, channel, and semantic bounds.",
        detector=detector,
        bridge=bridge,
    )


def evaluate_attack_chain(*, steps: tuple[AttackStep, ...]) -> AttackChainResult:
    """Evaluate a multi-step attack scenario and stop on the first inadmissible step."""

    decisions: list[AdmissibilityDecision] = []
    for step in steps:
        decision = evaluate_transform_admissibility(candidate=step.candidate)
        decisions.append(decision)
        if decision.verdict != "allow":
            return AttackChainResult(
                verdict="blocked",
                blocking_step=step.name,
                reason_codes=decision.reason_codes,
                decisions=tuple(decisions),
            )

    return AttackChainResult(
        verdict="allow",
        blocking_step="",
        reason_codes=(),
        decisions=tuple(decisions),
    )
