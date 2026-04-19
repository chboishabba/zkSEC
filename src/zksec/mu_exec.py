"""Grounded execution witness helpers for zkSEC."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


MuExecState = Literal["proposal_only", "grounded", "invariant_failure"]
MuExecLinkState = Literal["unresolved", "proposal_only", "grounded"]


def _normalize_items(values: tuple[str, ...] | None) -> tuple[str, ...]:
    if not values:
        return ()
    return tuple(sorted({item.strip() for item in values if item and item.strip()}))


def _normalize_labels(values: tuple[str, ...] | None) -> tuple[str, ...]:
    if not values:
        return ()
    return tuple(
        sorted(
            {
                item.strip().lower()
                for item in values
                if item and item.strip()
            }
        )
    )


def _normalize_text(value: str) -> str:
    return value.strip()


@dataclass(frozen=True)
class MuExecWitness:
    """Grounded execution interaction witness.

    Trace-like inputs may propose a witness, but only a grounded witness may
    carry invariant results.
    """

    state: MuExecState
    proposal_sources: tuple[str, ...] = ()
    grounding_basis: tuple[str, ...] = ()
    interaction_shape: tuple[str, ...] = ()
    invariant_codes: tuple[str, ...] = ()
    reason_codes: tuple[str, ...] = ()
    summary: str = ""

    def normalized(self) -> "MuExecWitness":
        return MuExecWitness(
            state=self.state,
            proposal_sources=_normalize_items(self.proposal_sources),
            grounding_basis=_normalize_items(self.grounding_basis),
            interaction_shape=_normalize_items(self.interaction_shape),
            invariant_codes=_normalize_items(self.invariant_codes),
            reason_codes=_normalize_items(self.reason_codes),
            summary=self.summary.strip(),
        )


@dataclass(frozen=True)
class MuExecTraceProposalFact:
    """Proposal-only trace fact captured during ingest."""

    trace_source: str
    trace_id: str = ""
    event_index: str = ""
    pid: str = ""
    tid: str = ""
    observed_op: str = ""
    candidate_anchor: str = ""
    candidate_span: str = ""
    proposal_notes: str = ""

    def normalized(self) -> "MuExecTraceProposalFact":
        return MuExecTraceProposalFact(
            trace_source=_normalize_text(self.trace_source).lower(),
            trace_id=_normalize_text(self.trace_id),
            event_index=_normalize_text(self.event_index),
            pid=_normalize_text(self.pid),
            tid=_normalize_text(self.tid),
            observed_op=_normalize_text(self.observed_op).lower(),
            candidate_anchor=_normalize_text(self.candidate_anchor).lower(),
            candidate_span=_normalize_text(self.candidate_span).lower(),
            proposal_notes=_normalize_text(self.proposal_notes),
        )

    def fact_id(self) -> str:
        normalized = self.normalized()
        if normalized.trace_id and normalized.event_index:
            return f"{normalized.trace_id}:{normalized.event_index}"
        if normalized.trace_id:
            return normalized.trace_id
        if normalized.event_index:
            return normalized.event_index
        return ""


@dataclass(frozen=True)
class MuExecGhidraGroundingFact:
    """Authoritative grounding fact derived from IR/disassembly analysis."""

    ghidra_project: str = ""
    binary_id: str = ""
    function_name: str = ""
    entry_address: str = ""
    address_range: str = ""
    ir_node_id: str = ""
    ir_kind: str = ""
    semantic_role: str = ""
    grounding_hash: str = ""

    def normalized(self) -> "MuExecGhidraGroundingFact":
        return MuExecGhidraGroundingFact(
            ghidra_project=_normalize_text(self.ghidra_project),
            binary_id=_normalize_text(self.binary_id),
            function_name=_normalize_text(self.function_name),
            entry_address=_normalize_text(self.entry_address),
            address_range=_normalize_text(self.address_range),
            ir_node_id=_normalize_text(self.ir_node_id),
            ir_kind=_normalize_text(self.ir_kind).lower(),
            semantic_role=_normalize_text(self.semantic_role).lower(),
            grounding_hash=_normalize_text(self.grounding_hash).lower(),
        )

    def fact_id(self) -> str:
        normalized = self.normalized()
        if normalized.grounding_hash:
            return normalized.grounding_hash
        if normalized.ir_node_id:
            return normalized.ir_node_id
        return ""


@dataclass(frozen=True)
class MuExecIngestBundle:
    """Library-only ingest envelope for first mu_exec extractor inputs."""

    sample_id: str = ""
    binary_id: str = ""
    proposal_facts: tuple[MuExecTraceProposalFact, ...] = ()
    grounding_facts: tuple[MuExecGhidraGroundingFact, ...] = ()
    ingest_source: str = ""
    summary: str = ""

    def normalized(self) -> "MuExecIngestBundle":
        return MuExecIngestBundle(
            sample_id=_normalize_text(self.sample_id),
            binary_id=_normalize_text(self.binary_id),
            proposal_facts=tuple(item.normalized() for item in self.proposal_facts),
            grounding_facts=tuple(item.normalized() for item in self.grounding_facts),
            ingest_source=_normalize_text(self.ingest_source).lower(),
            summary=_normalize_text(self.summary),
        )


@dataclass(frozen=True)
class MuExecLinkResolution:
    """Normalized proposal-to-grounding link resolution."""

    link_state: MuExecLinkState
    proposal_fact_ids: tuple[str, ...] = ()
    grounding_fact_ids: tuple[str, ...] = ()
    grounding_basis: tuple[str, ...] = ()
    interaction_shape: tuple[str, ...] = ()
    summary: str = ""

    def normalized(self) -> "MuExecLinkResolution":
        return MuExecLinkResolution(
            link_state=self.link_state,
            proposal_fact_ids=_normalize_labels(self.proposal_fact_ids),
            grounding_fact_ids=_normalize_labels(self.grounding_fact_ids),
            grounding_basis=_normalize_labels(self.grounding_basis),
            interaction_shape=_normalize_labels(self.interaction_shape),
            summary=_normalize_text(self.summary),
        )


def build_mu_exec_witness(
    *,
    proposal_sources: tuple[str, ...] = (),
    grounding_basis: tuple[str, ...] = (),
    interaction_shape: tuple[str, ...] = (),
    summary: str = "",
) -> MuExecWitness:
    """Build a witness from proposal and grounding inputs.

    A witness without grounding remains proposal-only.
    """

    state: MuExecState = "grounded" if _normalize_items(grounding_basis) else "proposal_only"
    return MuExecWitness(
        state=state,
        proposal_sources=proposal_sources,
        grounding_basis=grounding_basis,
        interaction_shape=interaction_shape,
        summary=summary,
    ).normalized()


def normalize_mu_exec_ingest(
    *,
    bundle: MuExecIngestBundle,
    link_resolution: MuExecLinkResolution | None = None,
) -> MuExecLinkResolution:
    """Normalize first-pass ingest inputs into a deterministic link surface."""

    normalized_bundle = bundle.normalized()
    if link_resolution is not None:
        normalized_link = link_resolution.normalized()
        if normalized_link.link_state == "grounded" and not normalized_link.grounding_basis:
            return MuExecLinkResolution(
                link_state="grounded",
                proposal_fact_ids=normalized_link.proposal_fact_ids,
                grounding_fact_ids=normalized_link.grounding_fact_ids,
                grounding_basis=("ghidra_ir",),
                interaction_shape=normalized_link.interaction_shape,
                summary=normalized_link.summary or normalized_bundle.summary,
            )
        return MuExecLinkResolution(
            link_state=normalized_link.link_state,
            proposal_fact_ids=normalized_link.proposal_fact_ids,
            grounding_fact_ids=normalized_link.grounding_fact_ids,
            grounding_basis=normalized_link.grounding_basis,
            interaction_shape=normalized_link.interaction_shape,
            summary=normalized_link.summary or normalized_bundle.summary,
        )

    proposal_fact_ids = _normalize_labels(
        tuple(
            item.fact_id()
            for item in normalized_bundle.proposal_facts
            if item.fact_id()
        )
    )
    grounding_fact_ids = _normalize_labels(
        tuple(
            item.fact_id()
            for item in normalized_bundle.grounding_facts
            if item.fact_id()
        )
    )
    proposal_ops = _normalize_labels(
        tuple(item.observed_op for item in normalized_bundle.proposal_facts if item.observed_op)
    )
    grounding_basis_values = _normalize_labels(
        tuple(
            value
            for item in normalized_bundle.grounding_facts
            for value in ("ghidra_ir", item.ir_kind, item.semantic_role)
            if value
        )
    )
    link_state: MuExecLinkState = "proposal_only"
    if grounding_basis_values:
        link_state = "grounded"
    elif proposal_fact_ids:
        link_state = "unresolved"
    return MuExecLinkResolution(
        link_state=link_state,
        proposal_fact_ids=proposal_fact_ids,
        grounding_fact_ids=grounding_fact_ids,
        grounding_basis=grounding_basis_values,
        interaction_shape=proposal_ops,
        summary=normalized_bundle.summary,
    )


def build_mu_exec_witness_from_ingest(
    *,
    bundle: MuExecIngestBundle,
    link_resolution: MuExecLinkResolution | None = None,
    invariant_codes: tuple[str, ...] = (),
    reason_codes: tuple[str, ...] = (),
) -> MuExecWitness:
    """Build a witness from normalized ingest facts plus optional invariant checks."""

    normalized_bundle = bundle.normalized()
    normalized_link = normalize_mu_exec_ingest(
        bundle=normalized_bundle,
        link_resolution=link_resolution,
    )
    proposal_sources = _normalize_labels(
        tuple(
            value
            for value in (
                normalized_bundle.ingest_source,
                *(item.trace_source for item in normalized_bundle.proposal_facts),
            )
            if value
        )
    )
    if normalized_link.link_state == "grounded":
        witness = build_mu_exec_witness(
            proposal_sources=proposal_sources,
            grounding_basis=normalized_link.grounding_basis,
            interaction_shape=normalized_link.interaction_shape,
            summary=normalized_link.summary or normalized_bundle.summary,
        )
    else:
        witness = MuExecWitness(
            state="proposal_only",
            proposal_sources=proposal_sources,
            grounding_basis=(),
            interaction_shape=normalized_link.interaction_shape,
            reason_codes=("mu_exec_grounding_required",),
            summary=normalized_link.summary or normalized_bundle.summary,
        ).normalized()
    return evaluate_mu_exec_invariants(
        witness=witness,
        invariant_codes=invariant_codes,
        reason_codes=reason_codes,
    )


def evaluate_mu_exec_invariants(
    *,
    witness: MuExecWitness,
    invariant_codes: tuple[str, ...] = (),
    reason_codes: tuple[str, ...] = (),
) -> MuExecWitness:
    """Attach invariant results to a grounded witness.

    Proposal-only witnesses remain non-authoritative and do not promote
    invariant results into violations.
    """

    normalized = witness.normalized()
    if normalized.state == "proposal_only":
        return normalized
    normalized_invariants = _normalize_items(invariant_codes)
    normalized_reasons = _normalize_items(reason_codes)
    if normalized_invariants:
        return MuExecWitness(
            state="invariant_failure",
            proposal_sources=normalized.proposal_sources,
            grounding_basis=normalized.grounding_basis,
            interaction_shape=normalized.interaction_shape,
            invariant_codes=normalized_invariants,
            reason_codes=normalized_reasons or normalized_invariants,
            summary=normalized.summary,
        )
    return MuExecWitness(
        state="grounded",
        proposal_sources=normalized.proposal_sources,
        grounding_basis=normalized.grounding_basis,
        interaction_shape=normalized.interaction_shape,
        invariant_codes=(),
        reason_codes=normalized_reasons,
        summary=normalized.summary,
    )


def mu_exec_receipt_fields(*, witness: MuExecWitness | None) -> dict[str, str]:
    """Return deterministic receipt fields for a witness."""

    if witness is None:
        return {}
    normalized = witness.normalized()
    return {
        "mu_exec_state": normalized.state,
        "mu_exec_proposal_sources": ",".join(normalized.proposal_sources),
        "mu_exec_grounding_basis": ",".join(normalized.grounding_basis),
        "mu_exec_interaction_shape": ",".join(normalized.interaction_shape),
        "mu_exec_invariant_codes": ",".join(normalized.invariant_codes),
        "mu_exec_reason_codes": ",".join(normalized.reason_codes),
        "mu_exec_summary": normalized.summary,
    }
