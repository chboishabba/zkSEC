from zksec import (
    AdmissibilityInput,
    AttackStep,
    OntologyDelta,
    WitnessExpectation,
    assess_ontology_surface,
    build_mu_exec_witness,
    bridge_zos_proposal,
    evaluate_adapter_action,
    evaluate_attack_chain,
    evaluate_mu_exec_invariants,
    evaluate_transform_admissibility,
)


def test_bridge_accepts_zos_metadata_as_proposal_only() -> None:
    result = bridge_zos_proposal(
        metadata={
            "resonance": 0.82,
            "embedding_neighborhood": ("cluster-a", "cluster-b"),
            "publish_authority": True,
        },
        proposal_state="proposal",
        ring="bounded",
    )
    assert result.status == "rejected"
    assert result.reason_codes == ("forbidden_authority_crossing_detected",)
    assert result.proposal_metadata["resonance"] == "0.82"


def test_ontology_surface_rejects_compression_without_grounding() -> None:
    signal = assess_ontology_surface(
        ontology=OntologyDelta(
            canonical_terms=("trusted finding",),
            new_canonical_terms=("trusted finding",),
            control_terms=("deploy", "patch"),
            compression_gain=0.8,
            groundedness_loss=0.6,
            resonance_lift=0.4,
            provenance_weakness=0.2,
        ),
        source="managed",
        proposal_state="proposal",
    )
    assert signal.verdict == "reject"
    assert signal.reason_codes[0] == "compression_without_grounding"


def test_benign_admissible_delta_allows_same_profile_with_hash_change_only() -> None:
    decision = evaluate_adapter_action(
        adapter_name="kant_zk_pastebin",
        action="read",
        actor_role="operator",
        actor_identity="ops-2026",
        scope="sandbox",
        plan_ref="plan-2026-04-07",
        source="managed",
        risk_level="low",
        requested_artifact_state="kant:read:state",
        requested_artifact_hash="hash-a",
        previous_artifact_hash="hash-b",
    )
    assert decision.status == "allow"
    assert decision.admissibility_verdict == "allow"
    assert decision.detector_verdict == "allow"
    assert decision.receipt["artifact_hash_delta"] == "changed"
    assert decision.receipt["admissibility_verdict"] == "allow"


def test_zos_authority_crossing_is_denied_before_activation() -> None:
    decision = evaluate_adapter_action(
        adapter_name="zos_server",
        action="read",
        actor_role="operator",
        actor_identity="ops-2026",
        scope="sandbox",
        plan_ref="plan-2026-04-07",
        source="managed",
        risk_level="low",
        zos_proposal={
            "resonance": 0.91,
            "semantic_clusters": ("zk", "sec"),
            "publish_authority": True,
        },
    )
    assert decision.status == "deny"
    assert decision.reason_code == "forbidden_authority_crossing_detected"
    assert decision.bridge_status == "rejected"


def test_ontology_poison_candidate_is_denied() -> None:
    decision = evaluate_adapter_action(
        adapter_name="zos_server",
        action="read",
        actor_role="operator",
        actor_identity="ops-2026",
        scope="sandbox",
        plan_ref="plan-2026-04-07",
        source="managed",
        risk_level="low",
        ontology_delta=OntologyDelta(
            canonical_terms=("prod",),
            alias_terms=("production", "public-safe", "canonical"),
            new_alias_terms=("production", "public-safe"),
            affected_clusters=("artifact", "authority"),
            control_terms=("deploy", "policy"),
            compression_gain=0.78,
            groundedness_loss=0.55,
            resonance_lift=0.72,
            provenance_weakness=0.62,
            cluster_pull=0.5,
            control_inconsistency=0.2,
            alias_pressure=0.85,
        ),
    )
    assert decision.status == "deny"
    assert decision.reason_code == "compression_without_grounding"
    assert decision.admissibility_verdict == "reject"
    assert "compression_without_grounding" in decision.detector_reason_codes


def test_multi_step_attack_chain_blocks_capability_expansion() -> None:
    step_one = AttackStep(
        name="read",
        candidate=AdmissibilityInput(
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
            expected_source_channels=("local", "trusted_peer"),
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
            witness=WitnessExpectation(
                declared_ring="bounded",
                expected_capabilities=("read",),
                expected_source_channels=("local", "trusted_peer"),
                expected_destination_channels=("local",),
            ),
        ),
    )
    step_two = AttackStep(
        name="publish-ready-transform",
        candidate=AdmissibilityInput(
            prior_state="zos:artifact@v1",
            proposed_state="zos:artifact@v2",
            artifact_class="document",
            delta_surface="changed",
            capability_delta=("write",),
            channel_delta=("remote_api",),
            semantic_delta=None,
            proposal_state="proposal",
            source="managed",
            ring="bounded",
            expected_capabilities=("read",),
            observed_capabilities=("read", "write"),
            previous_capabilities=("read",),
            expected_source_channels=("local", "trusted_peer"),
            observed_source_channel="remote_api",
            previous_source_channel="local",
            expected_destination_channels=("local",),
            observed_destination_channel="local",
            previous_destination_channel="local",
            expected_transforms=("read", "transform"),
            observed_transform="transform",
            previous_transform="read",
            expected_destinations=("local",),
            observed_destination="local",
            expected_rings=("bounded",),
            previous_ring="bounded",
            witness=WitnessExpectation(
                declared_ring="bounded",
                expected_capabilities=("read",),
                expected_source_channels=("local", "trusted_peer"),
                expected_destination_channels=("local",),
            ),
        ),
    )

    result = evaluate_attack_chain(steps=(step_one, step_two))
    assert result.verdict == "blocked"
    assert result.blocking_step == "publish-ready-transform"
    assert result.reason_codes[0] == "capability_expansion_detected"


def test_transform_admissibility_requires_confirmation_for_public_ontology_drift() -> None:
    decision = evaluate_transform_admissibility(
        candidate=AdmissibilityInput(
            prior_state="zos:map@v1",
            proposed_state="zos:map@v1",
            artifact_class="semantic_map",
            delta_surface="unchanged",
            capability_delta=(),
            channel_delta=(),
            semantic_delta=OntologyDelta(
                canonical_terms=("review",),
                new_canonical_terms=("review",),
                control_terms=("review",),
                compression_gain=0.45,
                groundedness_loss=0.1,
                resonance_lift=0.5,
                provenance_weakness=0.2,
                cluster_pull=0.2,
                control_inconsistency=0.1,
                alias_pressure=0.1,
            ),
            proposal_state="proposal",
            source="public",
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
        )
    )
    assert decision.verdict == "allow_with_confirmation"
    assert "ontology_drift_requires_confirmation" in decision.reason_codes


def test_mu_exec_grounded_witness_allows_when_invariants_hold() -> None:
    witness = evaluate_mu_exec_invariants(
        witness=build_mu_exec_witness(
            proposal_sources=("strace", "zkperf"),
            grounding_basis=("cfg", "ghidra_ir"),
            interaction_shape=("copy", "userspace"),
            summary="copy path resolved through IR",
        )
    )
    decision = evaluate_transform_admissibility(
        candidate=AdmissibilityInput(
            prior_state="zos:artifact@v1",
            proposed_state="zos:artifact@v1",
            artifact_class="runtime_witness",
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
            mu_exec_witness=witness,
        )
    )
    assert witness.state == "grounded"
    assert decision.verdict == "allow"


def test_mu_exec_invariant_failure_rejects_grounded_execution_witness() -> None:
    witness = evaluate_mu_exec_invariants(
        witness=build_mu_exec_witness(
            proposal_sources=("strace",),
            grounding_basis=("ghidra_ir",),
            interaction_shape=("copy", "kernel"),
        ),
        invariant_codes=("memory_violation",),
        reason_codes=("memory_violation",),
    )
    decision = evaluate_transform_admissibility(
        candidate=AdmissibilityInput(
            prior_state="zos:artifact@v1",
            proposed_state="zos:artifact@v1",
            artifact_class="runtime_witness",
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
            mu_exec_witness=witness,
        )
    )
    assert witness.state == "invariant_failure"
    assert decision.verdict == "reject"
    assert "memory_violation" in decision.reason_codes


def test_mu_exec_proposal_only_requires_confirmation() -> None:
    witness = build_mu_exec_witness(
        proposal_sources=("strace", "zkperf"),
        interaction_shape=("copy",),
        summary="trace-only proposal",
    )
    decision = evaluate_transform_admissibility(
        candidate=AdmissibilityInput(
            prior_state="zos:artifact@v1",
            proposed_state="zos:artifact@v1",
            artifact_class="runtime_witness",
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
            mu_exec_witness=witness,
        )
    )
    assert witness.state == "proposal_only"
    assert decision.verdict == "allow_with_confirmation"
    assert "mu_exec_grounding_required" in decision.reason_codes
