"""Authority-neutral provenance envelopes for DA51 evidence.

A DA51 address identifies an object.  The envelope names a producer-owned
artifact about that object.  It deliberately contains no field for theorem
truth, security severity, exploitability, authorization, or verification.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from zksec.da51 import Da51EvidenceRef


class EvidenceKind(str, Enum):
    PROOF = "proof"
    TRACE = "trace"
    BENCHMARK = "benchmark"
    SOURCE = "source"
    RECEIPT = "receipt"


@dataclass(frozen=True)
class Da51EvidenceEnvelope:
    ref: Da51EvidenceRef
    artifact: str
    kind: EvidenceKind

    @classmethod
    def build(
        cls,
        *,
        address: str,
        producer: str,
        artifact: str,
        kind: EvidenceKind,
        provenance: tuple[str, ...] = (),
    ) -> "Da51EvidenceEnvelope":
        artifact = artifact.strip()
        if not artifact:
            raise ValueError("DA51 evidence artifact must not be empty")
        producer = producer.strip()
        if not producer:
            raise ValueError("DA51 evidence producer must not be empty")
        return cls(
            ref=Da51EvidenceRef.parse(
                address,
                producer=producer,
                provenance=provenance,
            ),
            artifact=artifact,
            kind=kind,
        )

    @property
    def identity_token(self) -> str:
        return self.ref.provenance_token()
