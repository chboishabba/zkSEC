"""Grounded execution witness helpers for zkSEC."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


MuExecState = Literal["proposal_only", "grounded", "invariant_failure"]


def _normalize_items(values: tuple[str, ...] | None) -> tuple[str, ...]:
    if not values:
        return ()
    return tuple(sorted({item.strip() for item in values if item and item.strip()}))


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
