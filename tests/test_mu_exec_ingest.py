from pathlib import Path

from zksec import AdmissibilityInput, evaluate_transform_admissibility
from zksec.build_mu_exec_from_ingest import (
    build_mu_exec_witness_from_ingest,
    load_ir_grounding_facts,
    load_trace_proposal_facts,
    resolve_linkage_witness,
)


FIXTURES = Path(__file__).parent / "fixtures"


def _base_candidate(*, mu_exec_witness):
    return AdmissibilityInput(
        prior_state="zos:artifact@v1",
        proposed_state="zos:artifact@v1",
        artifact_class="document",
        delta_surface="unchanged",
        capability_delta=(),
        channel_delta=(),
        semantic_delta=None,
        proposal_state="proposal",
        source="managed",
        ring="bounded",
        expected_capabilities=("read",),
        observed_capabilities=("read",),
        previous_capabilities=("read",),
        expected_source_channels=("local",),
        observed_source_channel="local",
        previous_source_channel="local",
        expected_destination_channels=("local",),
        observed_destination_channel="local",
        previous_destination_channel="local",
        expected_transforms=("read",),
        observed_transform="read",
        previous_transform="read",
        expected_destinations=("local",),
        observed_destination="local",
        expected_rings=("bounded",),
        previous_ring="bounded",
        mu_exec_witness=mu_exec_witness,
    )


def test_fixture_pair_materializes_grounded_mu_exec() -> None:
    trace_facts = load_trace_proposal_facts(FIXTURES / "zkperf_trace_min.json")
    ir_facts = load_ir_grounding_facts(FIXTURES / "ghidra_grounding_min.json")

    linkage = resolve_linkage_witness(trace_facts=trace_facts, ir_facts=ir_facts)
    witness = build_mu_exec_witness_from_ingest(
        trace_facts=trace_facts,
        ir_facts=ir_facts,
        linkage_witness=linkage,
    )

    assert linkage.proposal_score == 1.0
    assert linkage.grounding_score == 1.0
    assert linkage.relation_chain == ("alloc", "free", "read")
    assert witness.state == "grounded"
    assert witness.invariant_codes == ()
    assert witness.grounding_basis == ("authority", "carrier", "extent", "ghidra_ir", "lifetime")


def test_grounded_fixture_requires_explicit_invariant_evaluation_to_block() -> None:
    trace_facts = load_trace_proposal_facts(FIXTURES / "zkperf_trace_min.json")
    ir_facts = load_ir_grounding_facts(FIXTURES / "ghidra_grounding_min.json")

    witness = build_mu_exec_witness_from_ingest(trace_facts=trace_facts, ir_facts=ir_facts)
    decision = evaluate_transform_admissibility(candidate=_base_candidate(mu_exec_witness=witness))

    assert witness.state == "grounded"
    assert decision.verdict == "allow"

    failed = build_mu_exec_witness_from_ingest(
        trace_facts=trace_facts,
        ir_facts=ir_facts,
        invariant_codes=("mu_exec_inv_lifetime",),
    )
    failed_decision = evaluate_transform_admissibility(candidate=_base_candidate(mu_exec_witness=failed))

    assert failed.state == "invariant_failure"
    assert "mu_exec_inv_lifetime" in failed_decision.reason_codes
    assert failed_decision.verdict == "reject"


def test_trace_only_fixture_stays_proposal_only() -> None:
    trace_facts = load_trace_proposal_facts(FIXTURES / "zkperf_trace_min.json")

    witness = build_mu_exec_witness_from_ingest(trace_facts=trace_facts, ir_facts=())
    decision = evaluate_transform_admissibility(candidate=_base_candidate(mu_exec_witness=witness))

    assert witness.state == "proposal_only"
    assert witness.grounding_basis == ()
    assert witness.invariant_codes == ()
    assert decision.verdict == "allow_with_confirmation"
