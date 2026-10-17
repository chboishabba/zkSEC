import pytest

from zksec.da51 import Da51EvidenceRef, Da51ValidationError
from zksec.ingest_types import TraceProposalFact


def _trace(*, da51: Da51EvidenceRef) -> TraceProposalFact:
    return TraceProposalFact(
        fact_id="trace-1",
        run_id="run-1",
        tool="zkperf",
        t_index=0,
        timestamp_ns=None,
        pid=None,
        tid=None,
        actor="worker",
        op="read",
        obj_hint="buf",
        value_int=None,
        value_str=None,
        da51=da51,
    )


def test_da51_identity_is_appended_to_provenance_only() -> None:
    ref = Da51EvidenceRef.parse("0xDA51800100000000", producer="zkperf")
    fact = _trace(da51=ref).normalized()

    assert fact.da51 == ref
    assert "da51:0xda51800100000000" in fact.provenance
    assert fact.op == "read"


def test_da51_producer_must_match_trace_producer() -> None:
    ref = Da51EvidenceRef.parse("0xDA51800100000000", producer="other")

    with pytest.raises(Da51ValidationError, match="does not match trace producer"):
        _trace(da51=ref).normalized()
