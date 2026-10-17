import json
from pathlib import Path

from zksec.da51 import Da51EvidenceRef


MANIFEST = Path(__file__).parents[1] / "fixtures" / "da51_v1.json"


def test_shared_manifest_vectors_match_decoder_fields() -> None:
    payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    vectors = payload["atlas_vectors"]
    assert len(vectors) == 23

    for vector in vectors:
        ref = Da51EvidenceRef.parse(vector["address"], producer="zkperf")
        coord = ref.atlas_coordinate()
        assert coord is not None
        assert ref.type_code == vector["type"]
        assert coord.level_code == vector["level"]
        assert coord.biome_code == vector["biome"]
        assert coord.status_code == vector["status"]
        assert coord.serial == vector["serial"]
        assert ref.data & ((1 << 20) - 1) == vector["reserved"]


def test_shared_manifest_declares_authority_boundary() -> None:
    payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert payload["authority"] == {
        "address_is_identity_only": True,
        "provenance_is_separate": True,
        "status_nibble_is_not_external_authority": True,
    }
