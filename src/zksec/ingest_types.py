"""Pinned V1 producer contracts for mu_exec ingest."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


def _normalize_text(value: str | None) -> str:
    if value is None:
        return ""
    return value.strip()


def _normalize_label(value: str | None) -> str:
    return _normalize_text(value).lower()


def _normalize_labels(values: tuple[str, ...] | None) -> tuple[str, ...]:
    if not values:
        return ()
    return tuple(sorted({_normalize_label(value) for value in values if _normalize_text(value)}))


def _canonical_id(*parts: str) -> str:
    normalized = tuple(part for part in (_normalize_label(part) for part in parts) if part)
    return ":".join(normalized)


TraceTool = Literal["zkperf"]
GroundingProducer = Literal["ghidra"]


@dataclass(frozen=True)
class TraceProposalFact:
    """Proposal-only execution observation from a trace producer."""

    fact_id: str
    run_id: str
    tool: TraceTool
    t_index: int
    timestamp_ns: int | None
    pid: int | None
    tid: int | None
    actor: str
    op: str
    obj_hint: str | None
    value_int: int | None
    value_str: str | None
    quals: tuple[str, ...] = ()
    provenance: tuple[str, ...] = ()

    def normalized(self) -> "TraceProposalFact":
        fact_id = _normalize_text(self.fact_id)
        run_id = _normalize_text(self.run_id)
        normalized = TraceProposalFact(
            fact_id=fact_id or _canonical_id(run_id, str(self.t_index), self.actor, self.op),
            run_id=run_id,
            tool=self.tool,
            t_index=self.t_index,
            timestamp_ns=self.timestamp_ns,
            pid=self.pid,
            tid=self.tid,
            actor=_normalize_label(self.actor),
            op=_normalize_label(self.op),
            obj_hint=_normalize_label(self.obj_hint),
            value_int=self.value_int,
            value_str=_normalize_text(self.value_str),
            quals=_normalize_labels(self.quals),
            provenance=_normalize_labels(self.provenance),
        )
        return normalized


@dataclass(frozen=True)
class IRGroundingFact:
    """Pinned V1 grounding envelope from Ghidra-derived IR exports."""

    fact_id: str
    producer: GroundingProducer
    artifact_id: str
    fn: str | None
    obj_id: str
    obj_kind: str
    capacity: int | None
    field_offset: int | None
    field_width: int | None
    lifetime_kind: str | None
    authority_kind: str | None
    carrier_kind: str | None
    aliases: tuple[str, ...] = ()
    provenance: tuple[str, ...] = ()

    def normalized(self) -> "IRGroundingFact":
        artifact_id = _normalize_text(self.artifact_id)
        obj_id = _normalize_label(self.obj_id)
        fact_id = _normalize_text(self.fact_id)
        normalized = IRGroundingFact(
            fact_id=fact_id or _canonical_id(artifact_id, obj_id),
            producer=self.producer,
            artifact_id=artifact_id,
            fn=_normalize_text(self.fn),
            obj_id=obj_id,
            obj_kind=_normalize_label(self.obj_kind),
            capacity=self.capacity,
            field_offset=self.field_offset,
            field_width=self.field_width,
            lifetime_kind=_normalize_label(self.lifetime_kind),
            authority_kind=_normalize_label(self.authority_kind),
            carrier_kind=_normalize_label(self.carrier_kind),
            aliases=_normalize_labels(self.aliases),
            provenance=_normalize_labels(self.provenance),
        )
        return normalized


@dataclass(frozen=True)
class LinkageWitness:
    """Narrow seam between proposal facts and grounded object semantics."""

    link_id: str
    trace_fact_ids: tuple[str, ...]
    ir_fact_ids: tuple[str, ...]
    relation_chain: tuple[str, ...]
    src_obj: str | None
    dst_obj: str | None
    carrier_obj: str | None
    proposal_score: float
    grounding_score: float

    def normalized(self) -> "LinkageWitness":
        normalized = LinkageWitness(
            link_id=_normalize_text(self.link_id)
            or _canonical_id(*(self.trace_fact_ids + self.ir_fact_ids)),
            trace_fact_ids=_normalize_labels(self.trace_fact_ids),
            ir_fact_ids=_normalize_labels(self.ir_fact_ids),
            relation_chain=_normalize_labels(self.relation_chain),
            src_obj=_normalize_label(self.src_obj),
            dst_obj=_normalize_label(self.dst_obj),
            carrier_obj=_normalize_label(self.carrier_obj),
            proposal_score=max(0.0, min(1.0, self.proposal_score)),
            grounding_score=max(0.0, min(1.0, self.grounding_score)),
        )
        return normalized
