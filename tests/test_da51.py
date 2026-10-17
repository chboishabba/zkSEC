import json
from pathlib import Path

import pytest

from zksec.da51 import Da51EvidenceRef, Da51ValidationError


MANIFEST = Path(__file__).parents[1] / "fixtures" / "da51_v1.json"


def test_legacy_da51_identity_is_accepted_without_atlas_semantics() -> None:
    ref = Da51EvidenceRef.parse("da5113c01b0a55f4", producer="zkperf")

    assert ref.address == "0xDA5113C01B0A55F4"
    assert ref.type_code == 1
    assert ref.known_type is True
    assert ref.atlas_coordinate() is None


def test_unknown_type_requires_explicit_allowance() -> None:
    with pytest.raises(Da51ValidationError, match="unassigned DA51 type code 9"):
        Da51EvidenceRef.parse("0xDA51900000000000", producer="zkperf")

    ref = Da51EvidenceRef.parse(
        "0xDA51900000000000",
        producer="zkperf",
        allow_unknown_type=True,
    )
    assert ref.type_code == 9
    assert ref.known_type is False


def test_atlas_fixture_decodes_exact_fields() -> None:
    ref = Da51EvidenceRef.parse("0xDA51853000A00000", producer="zkperf")
    coord = ref.atlas_coordinate()

    assert coord is not None
    assert coord.level_code == 5
    assert coord.biome_code == 3
    assert coord.status_code == 0
    assert coord.serial == 10


def test_all_shared_atlas_addresses_are_canonical() -> None:
    payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    addresses = payload["atlas_addresses"]

    assert len(addresses) == 23
    refs = [Da51EvidenceRef.parse(address, producer="zkperf") for address in addresses]
    coords = [ref.atlas_coordinate() for ref in refs]
    assert all(coord is not None for coord in coords)
    assert [coord.serial for coord in coords if coord is not None] == list(range(23))
    assert len({ref.address for ref in refs}) == 23


def test_atlas_reserved_bits_are_rejected() -> None:
    with pytest.raises(Da51ValidationError, match="reserved bits"):
        Da51EvidenceRef.parse("0xDA51800100000001", producer="zkperf")


def test_invalid_atlas_codes_are_rejected() -> None:
    with pytest.raises(Da51ValidationError, match="level code 6"):
        Da51EvidenceRef.parse("0xDA51860100000000", producer="zkperf")
    with pytest.raises(Da51ValidationError, match="biome code 9"):
        Da51EvidenceRef.parse("0xDA51809100000000", producer="zkperf")
    with pytest.raises(Da51ValidationError, match="status code 5"):
        Da51EvidenceRef.parse("0xDA51800500000000", producer="zkperf")


def test_max_serial_manifest_fixture_is_canonical() -> None:
    payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    ref = Da51EvidenceRef.parse(payload["max_serial_address"], producer="zkperf")
    coord = ref.atlas_coordinate()

    assert coord is not None
    assert coord.serial == 4095


def test_wrong_prefix_is_rejected() -> None:
    with pytest.raises(Da51ValidationError, match="wrong DA51 prefix"):
        Da51EvidenceRef.parse("0xCAFE800100000000", producer="zkperf")
