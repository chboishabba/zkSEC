from zksec.adapters import (
    AdapterCheckResult,
    AdapterContract,
    AdapterActionCapability,
    action_capability_policy,
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


def test_contract_resource_roots_are_scoped() -> None:
    zos_adapter = zos_server_contract()
    pastebin_adapter = kant_zk_pastebin_contract()

    assert "../zos-server" in zos_adapter.resource_roots
    assert "../kant-zk-pastebin" in pastebin_adapter.resource_roots


def test_capability_profiles_cover_known_actions() -> None:
    for action in ("read", "review", "plan", "patch", "deploy"):
        profile = action_capability_policy(adapter=zos_server_contract(), action=action)
        assert isinstance(profile, AdapterActionCapability)
        assert profile.action == action
        assert profile.capabilities
        assert profile.channels
        assert profile.rings
        assert profile.destinations


def test_kant_contract_exposes_sync_as_local_only() -> None:
    profile = action_capability_policy(adapter=kant_zk_pastebin_contract(), action="deploy")
    assert "write" in profile.capabilities
    assert "execute" in profile.capabilities
    assert "peer" not in profile.destinations
