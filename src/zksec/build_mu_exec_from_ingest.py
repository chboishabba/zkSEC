"""Fixture-backed builder for the pinned V1 mu_exec ingest contract."""

from __future__ import annotations

import json
from pathlib import Path

from .ingest_types import IRGroundingFact, LinkageWitness, TraceProposalFact
from .mu_exec import MuExecWitness, build_mu_exec_witness, evaluate_mu_exec_invariants


def _normalize_sources(trace_facts: tuple[TraceProposalFact, ...]) -> tuple[str, ...]:
    return tuple(sorted({fact.tool for fact in trace_facts}))


def _derive_invariant_families(ir_facts: tuple[IRGroundingFact, ...]) -> tuple[str, ...]:
    families: set[str] = set()
    for fact in ir_facts:
        if (
            fact.capacity is not None
            or fact.field_offset is not None
            or fact.field_width is not None
            or fact.obj_kind in {"buffer", "struct_field"}
        ):
            families.add("buffer_extent")
        if fact.lifetime_kind:
            families.add("lifetime")
        if fact.authority_kind or fact.carrier_kind:
            families.add("authority_boundary")
    return tuple(sorted(families))


def _grounding_basis(ir_facts: tuple[IRGroundingFact, ...]) -> tuple[str, ...]:
    basis = {"ghidra_ir"}
    for family in _derive_invariant_families(ir_facts):
        if family == "buffer_extent":
            basis.add("extent")
        elif family == "lifetime":
            basis.add("lifetime")
        elif family == "authority_boundary":
            basis.add("authority")
        else:
            basis.add(family)
    if any(fact.carrier_kind for fact in ir_facts):
        basis.add("carrier")
    return tuple(sorted(basis))


def _build_summary(
    *,
    trace_facts: tuple[TraceProposalFact, ...],
    ir_facts: tuple[IRGroundingFact, ...],
    invariant_families: tuple[str, ...],
) -> str:
    ops = " -> ".join(dict.fromkeys(fact.op for fact in trace_facts if fact.op))
    obj = next((fact.obj_id for fact in ir_facts if fact.obj_id), "")
    family_text = ",".join(invariant_families)
    return f"{ops or 'trace'} grounded on {obj or 'ir object'} [{family_text}]".strip()


def resolve_linkage_witness(
    *,
    trace_facts: list[TraceProposalFact] | tuple[TraceProposalFact, ...],
    ir_facts: list[IRGroundingFact] | tuple[IRGroundingFact, ...],
) -> LinkageWitness:
    """Resolve the narrow proposal-to-grounding seam for a single ingest slice."""

    normalized_trace = tuple(fact.normalized() for fact in trace_facts)
    normalized_ir = tuple(fact.normalized() for fact in ir_facts)
    relation_chain = tuple(dict.fromkeys(fact.op for fact in normalized_trace if fact.op))
    trace_ids = tuple(fact.fact_id for fact in normalized_trace)
    ir_ids = tuple(fact.fact_id for fact in normalized_ir)
    src_obj = next((fact.obj_hint for fact in normalized_trace if fact.obj_hint), None)
    dst_obj = next((fact.obj_id for fact in normalized_ir if fact.obj_id), None)
    carrier_obj = next((fact.obj_id for fact in normalized_ir if fact.carrier_kind), None)
    link_id_parts = trace_ids + ir_ids
    link_id = ":".join(link_id_parts) if link_id_parts else ""
    return LinkageWitness(
        link_id=link_id,
        trace_fact_ids=trace_ids,
        ir_fact_ids=ir_ids,
        relation_chain=relation_chain,
        src_obj=src_obj,
        dst_obj=dst_obj,
        carrier_obj=carrier_obj,
        proposal_score=1.0 if normalized_trace else 0.0,
        grounding_score=1.0 if normalized_ir else 0.0,
    ).normalized()


def build_mu_exec_witness_from_ingest(
    *,
    trace_facts: list[TraceProposalFact] | tuple[TraceProposalFact, ...],
    ir_facts: list[IRGroundingFact] | tuple[IRGroundingFact, ...],
    linkage_witness: LinkageWitness | None = None,
    theta_p: float = 0.5,
    theta_g: float = 0.5,
    invariant_codes: tuple[str, ...] = (),
    reason_codes: tuple[str, ...] = (),
) -> MuExecWitness:
    """Build a mu_exec witness from one trace proposal slice and one IR slice."""

    normalized_trace = tuple(fact.normalized() for fact in trace_facts)
    normalized_ir = tuple(fact.normalized() for fact in ir_facts)
    linkage = (
        linkage_witness.normalized()
        if linkage_witness is not None
        else resolve_linkage_witness(trace_facts=normalized_trace, ir_facts=normalized_ir)
    )
    invariant_families = _derive_invariant_families(normalized_ir)
    grounded = (
        linkage.proposal_score >= theta_p
        and linkage.grounding_score >= theta_g
        and bool(invariant_families)
    )
    if not grounded:
        return MuExecWitness(
            state="proposal_only",
            proposal_sources=_normalize_sources(normalized_trace),
            grounding_basis=(),
            interaction_shape=linkage.relation_chain,
            reason_codes=("mu_exec_grounding_required",),
            summary="proposal-only execution facts; grounding incomplete",
        ).normalized()

    witness = build_mu_exec_witness(
        proposal_sources=_normalize_sources(normalized_trace),
        grounding_basis=_grounding_basis(normalized_ir),
        interaction_shape=linkage.relation_chain,
        summary=_build_summary(
            trace_facts=normalized_trace,
            ir_facts=normalized_ir,
            invariant_families=invariant_families,
        ),
    )
    return evaluate_mu_exec_invariants(
        witness=witness,
        invariant_codes=invariant_codes,
        reason_codes=reason_codes,
    )


def load_trace_proposal_facts(path: str | Path) -> tuple[TraceProposalFact, ...]:
    """Load pinned trace proposal facts from a local JSON fixture."""

    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    facts = payload["trace_facts"] if isinstance(payload, dict) else payload
    return tuple(TraceProposalFact(**fact).normalized() for fact in facts)


def load_ir_grounding_facts(path: str | Path) -> tuple[IRGroundingFact, ...]:
    """Load pinned IR grounding facts from a local JSON fixture."""

    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    facts = payload["ir_facts"] if isinstance(payload, dict) else payload
    return tuple(IRGroundingFact(**fact).normalized() for fact in facts)
