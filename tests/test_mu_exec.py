from zksec import AdmissibilityInput, evaluate_transform_admissibility
from zksec.mu_exec import (
    MuExecGhidraGroundingFact,
    MuExecIngestBundle,
    MuExecLinkResolution,
    MuExecTraceProposalFact,
    build_mu_exec_witness_from_ingest,
    mu_exec_receipt_fields,
    normalize_mu_exec_ingest,
)


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


def test_normalize_ingest_and_receipt_are_deterministic() -> None:
    bundle = MuExecIngestBundle(
        sample_id=" sample-1 ",
        binary_id=" binary-a ",
        ingest_source=" ZKPERF ",
        summary="  copy path by fixture  ",
        proposal_facts=(
            MuExecTraceProposalFact(
                trace_source=" STRACE ",
                trace_id="trace-9",
                event_index="2",
                observed_op=" Copy ",
            ),
            MuExecTraceProposalFact(
                trace_source="strace",
                trace_id="trace-9",
                event_index="2",
                observed_op="copy",
            ),
        ),
        grounding_facts=(
            MuExecGhidraGroundingFact(
                ir_kind=" CFG ",
                semantic_role=" COPY ",
                grounding_hash=" HASH-1 ",
            ),
        ),
    )
    link = normalize_mu_exec_ingest(bundle=bundle)
    witness = build_mu_exec_witness_from_ingest(bundle=bundle, link_resolution=link)

    assert link.link_state == "grounded"
    assert link.grounding_basis == ("cfg", "copy", "ghidra_ir")
    assert link.interaction_shape == ("copy",)
    assert witness.proposal_sources == ("strace", "zkperf")
    assert witness.grounding_basis == ("cfg", "copy", "ghidra_ir")
    assert witness.interaction_shape == ("copy",)
    assert witness.summary == "copy path by fixture"

    receipt = mu_exec_receipt_fields(witness=witness)
    assert receipt["mu_exec_proposal_sources"] == "strace,zkperf"
    assert receipt["mu_exec_grounding_basis"] == "cfg,copy,ghidra_ir"
    assert receipt["mu_exec_interaction_shape"] == "copy"


def test_unresolved_link_stays_proposal_only_and_requires_confirmation() -> None:
    bundle = MuExecIngestBundle(
        ingest_source="zkperf",
        summary="trace-only sample",
        proposal_facts=(
            MuExecTraceProposalFact(
                trace_source="strace",
                trace_id="trace-1",
                event_index="1",
                observed_op="copy",
            ),
        ),
    )
    link = MuExecLinkResolution(
        link_state="unresolved",
        proposal_fact_ids=("trace-1:1",),
        grounding_basis=(),
        interaction_shape=("copy",),
        summary="trace-only sample",
    )
    witness = build_mu_exec_witness_from_ingest(bundle=bundle, link_resolution=link)
    decision = evaluate_transform_admissibility(candidate=_base_candidate(mu_exec_witness=witness))

    assert witness.state == "proposal_only"
    assert witness.grounding_basis == ()
    assert witness.reason_codes == ("mu_exec_grounding_required",)
    assert decision.verdict == "allow_with_confirmation"
    assert "mu_exec_grounding_required" in decision.reason_codes


def test_grounded_link_materializes_from_ir_facts() -> None:
    bundle = MuExecIngestBundle(
        ingest_source="zkperf",
        summary="grounded from ir",
        proposal_facts=(MuExecTraceProposalFact(trace_source="strace", observed_op="copy"),),
        grounding_facts=(
            MuExecGhidraGroundingFact(
                ir_kind="cfg",
                semantic_role="copy",
                grounding_hash="hash-abc",
            ),
        ),
    )
    witness = build_mu_exec_witness_from_ingest(bundle=bundle)
    decision = evaluate_transform_admissibility(candidate=_base_candidate(mu_exec_witness=witness))

    assert witness.state == "grounded"
    assert witness.grounding_basis == ("cfg", "copy", "ghidra_ir")
    assert decision.verdict == "allow"


def test_grounded_invariant_failure_materializes_and_blocks() -> None:
    grounded_bundle = MuExecIngestBundle(
        ingest_source="zkperf",
        proposal_facts=(MuExecTraceProposalFact(trace_source="strace", observed_op="copy"),),
        grounding_facts=(MuExecGhidraGroundingFact(ir_kind="cfg", semantic_role="copy"),),
        summary="grounded",
    )
    grounded_failure = build_mu_exec_witness_from_ingest(
        bundle=grounded_bundle,
        invariant_codes=("mu_exec_inv_copy_path",),
    )
    grounded_decision = evaluate_transform_admissibility(
        candidate=_base_candidate(mu_exec_witness=grounded_failure)
    )

    proposal_only_bundle = MuExecIngestBundle(
        ingest_source="zkperf",
        proposal_facts=(MuExecTraceProposalFact(trace_source="strace", observed_op="copy"),),
        summary="proposal-only",
    )
    proposal_only = build_mu_exec_witness_from_ingest(
        bundle=proposal_only_bundle,
        invariant_codes=("mu_exec_inv_copy_path",),
    )

    assert grounded_failure.state == "invariant_failure"
    assert grounded_failure.invariant_codes == ("mu_exec_inv_copy_path",)
    assert grounded_decision.verdict == "reject"
    assert "mu_exec_inv_copy_path" in grounded_decision.reason_codes
    assert proposal_only.state == "proposal_only"
    assert proposal_only.invariant_codes == ()
