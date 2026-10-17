"""Canonical 0xDA51 evidence identity parsing for zkSEC.

DA51 is an identity/provenance carrier only.  Parsing an address never grants
vulnerability, severity, exploitability, authorization, proof, or admissibility.
"""

from __future__ import annotations

from dataclasses import dataclass


DA51_PREFIX = 0xDA51
DATA_MASK = (1 << 44) - 1
KNOWN_TYPE_CODES = frozenset(range(9))
ATLAS_TYPE = 8

LEVEL_CODES = frozenset(range(6))
BIOME_CODES = frozenset(range(9))
STATUS_CODES = frozenset(range(5))
ASCII_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


class Da51ValidationError(ValueError):
    """Raised when a DA51 evidence identity is syntactically non-canonical."""


@dataclass(frozen=True)
class AtlasCoordinateRef:
    level_code: int
    biome_code: int
    status_code: int
    serial: int


@dataclass(frozen=True)
class Da51EvidenceRef:
    """Proposal/evidence identity carried across producer boundaries."""

    address: str
    type_code: int
    producer: str
    provenance: tuple[str, ...] = ()
    known_type: bool = True

    @classmethod
    def parse(
        cls,
        address: str,
        *,
        producer: str,
        provenance: tuple[str, ...] = (),
        allow_unknown_type: bool = False,
    ) -> "Da51EvidenceRef":
        text = address.strip()
        body = text[2:] if text[:2].lower() == "0x" else text
        if len(body) != 16:
            raise Da51ValidationError("DA51 address must contain exactly 16 hexadecimal digits")
        if not body.isascii() or any(ch not in ASCII_HEX_DIGITS for ch in body):
            raise Da51ValidationError("DA51 address contains non-ASCII hexadecimal characters")
        try:
            raw = int(body, 16)
        except ValueError as exc:
            raise Da51ValidationError("DA51 address contains non-hexadecimal characters") from exc

        prefix = raw >> 48
        if prefix != DA51_PREFIX:
            raise Da51ValidationError(f"wrong DA51 prefix: 0x{prefix:04X}")

        type_code = (raw >> 44) & 0xF
        known = type_code in KNOWN_TYPE_CODES
        if not known and not allow_unknown_type:
            raise Da51ValidationError(f"unassigned DA51 type code {type_code}")

        ref = cls(
            address=f"0x{raw:016X}",
            type_code=type_code,
            producer=producer.strip().lower(),
            provenance=tuple(sorted({item.strip().lower() for item in provenance if item.strip()})),
            known_type=known,
        )
        # Type 8 is canonical only when all atlas fields are recognized and
        # the low reserved bits are zero.  This validation does not assert the
        # truth of the status nibble.
        if type_code == ATLAS_TYPE:
            ref.atlas_coordinate()
        return ref

    @property
    def raw(self) -> int:
        return int(self.address[2:], 16)

    @property
    def data(self) -> int:
        return self.raw & DATA_MASK

    def atlas_coordinate(self) -> AtlasCoordinateRef | None:
        if self.type_code != ATLAS_TYPE:
            return None

        data = self.data
        reserved = data & ((1 << 20) - 1)
        if reserved:
            raise Da51ValidationError(f"atlas reserved bits are nonzero: 0x{reserved:05X}")

        level = (data >> 40) & 0xF
        biome = (data >> 36) & 0xF
        status = (data >> 32) & 0xF
        serial = (data >> 20) & 0xFFF
        if level not in LEVEL_CODES:
            raise Da51ValidationError(f"invalid atlas level code {level}")
        if biome not in BIOME_CODES:
            raise Da51ValidationError(f"invalid atlas biome code {biome}")
        if status not in STATUS_CODES:
            raise Da51ValidationError(f"invalid atlas status code {status}")
        return AtlasCoordinateRef(
            level_code=level,
            biome_code=biome,
            status_code=status,
            serial=serial,
        )

    def normalized(self) -> "Da51EvidenceRef":
        return Da51EvidenceRef.parse(
            self.address,
            producer=self.producer,
            provenance=self.provenance,
            allow_unknown_type=not self.known_type,
        )

    def provenance_token(self) -> str:
        return f"da51:{self.address.lower()}"
