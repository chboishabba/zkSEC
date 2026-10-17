import pytest

from zksec.da51_provenance import (
    Da51EvidenceEnvelope,
    EvidenceKind,
    FormalRuntimeEvidenceLink,
)


def test_envelope_keeps_identity_producer_and_artifact_separate() -> None:
    envelope = Da51EvidenceEnvelope.build(
        address="0xDA51853000A00000",
        producer="zkperf",
        artifact="sha256:0123456789abcdef",
        kind=EvidenceKind.TRACE,
    )

    assert envelope.ref.address == "0xDA51853000A00000"
    assert envelope.ref.producer == "zkperf"
    assert envelope.artifact == "sha256:0123456789abcdef"
    assert envelope.kind is EvidenceKind.TRACE
    assert envelope.identity_token == "da51:0xda51853000a00000"


def test_envelope_requires_explicit_producer_and_artifact() -> None:
    with pytest.raises(ValueError, match="producer"):
        Da51EvidenceEnvelope.build(
            address="0xDA51853000A00000",
            producer=" ",
            artifact="receipt:1",
            kind=EvidenceKind.RECEIPT,
        )

    with pytest.raises(ValueError, match="artifact"):
        Da51EvidenceEnvelope.build(
            address="0xDA51853000A00000",
            producer="zkperf",
            artifact=" ",
            kind=EvidenceKind.RECEIPT,
        )


def test_runtime_evidence_link_does_not_become_formal_or_security_authority() -> None:
    envelope = Da51EvidenceEnvelope.build(
        address="0xDA51853000A00000",
        producer="zkperf",
        artifact="benchmark:1",
        kind=EvidenceKind.BENCHMARK,
    )
    link = FormalRuntimeEvidenceLink.build(
        evidence=envelope,
        demand_ref="formal-demand:1",
        obligation_ref="proof-obligation:1",
        statement_digest="sha256:statement-a",
        artifact_revision="run:1",
    )
    assert link.establishes_formal_proof is False
    assert link.establishes_security_conclusion is False
    assert link.authorizes_action is False


def test_da51_proof_metadata_never_implies_vulnerability() -> None:
    envelope = Da51EvidenceEnvelope.build(
        address="0xDA51831100800000",
        producer="lean-kernel",
        artifact="proof:1",
        kind=EvidenceKind.PROOF,
    )
    link = FormalRuntimeEvidenceLink.build(
        evidence=envelope,
        demand_ref="formal-demand:1",
        obligation_ref="proof-obligation:1",
        statement_digest="sha256:statement-a",
    )
    assert link.establishes_security_conclusion is False
    assert link.security_severity is None
