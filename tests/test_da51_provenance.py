import pytest

from zksec.da51_provenance import Da51EvidenceEnvelope, EvidenceKind


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
