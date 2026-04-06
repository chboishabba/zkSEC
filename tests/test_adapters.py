from zksec.adapters import (
    AdapterCheckResult,
    AdapterContract,
    kant_zk_pastebin_contract,
    validate_action_against_adapter,
    zos_server_contract,
)


def test_zos_contract_has_expected_actions() -> None:
    adapter = zos_server_contract()
    assert adapter.name == "zos_server"
    assert "patch" in adapter.allowed_actions
    assert adapter.integration_mode == "managed"


def test_kant_contract_disallows_unlisted_highrisk_action() -> None:
    adapter = kant_zk_pastebin_contract()
    result = validate_action_against_adapter(adapter=adapter, action="remediate")
    assert isinstance(result, AdapterCheckResult)
    assert result.allowed is False
    assert result.reason_code == "adapter_action_blocked"
