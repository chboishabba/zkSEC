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


@dataclass(frozen=True)
class FormalRuntimeEvidenceLink:
    """Cross-system linkage for evidence related to a formal demand.

    The linkage is navigation/provenance only.  Even a linked proof artifact
    does not by itself establish a security finding, severity, exploitability,
    authorization, or an SLR payment.  Runtime traces/benchmarks likewise never
    become formal theorem certificates through DA51 linkage.
    """

    evidence: Da51EvidenceEnvelope
    demand_ref: str | None = None
    obligation_ref: str | None = None
    statement_digest: str | None = None
    artifact_revision: str | None = None

    @classmethod
    def build(
        cls,
        *,
        evidence: Da51EvidenceEnvelope,
        demand_ref: str | None = None,
        obligation_ref: str | None = None,
        statement_digest: str | None = None,
        artifact_revision: str | None = None,
    ) -> "FormalRuntimeEvidenceLink":
        values = {
            "demand_ref": demand_ref,
            "obligation_ref": obligation_ref,
            "statement_digest": statement_digest,
            "artifact_revision": artifact_revision,
        }
        cleaned: dict[str, str | None] = {}
        for name, value in values.items():
            if value is None:
                cleaned[name] = None
                continue
            item = value.strip()
            if not item:
                raise ValueError(f"{name} must not be empty when present")
            cleaned[name] = item
        return cls(evidence=evidence, **cleaned)

    @property
    def establishes_formal_proof(self) -> bool:
        return False

    @property
    def establishes_security_conclusion(self) -> bool:
        return False

    @property
    def authorizes_action(self) -> bool:
        return False

    @property
    def security_severity(self) -> None:
        return None
