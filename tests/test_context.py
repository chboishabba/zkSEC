from zksec import SECURITY_CONTEXT_VERSION, known_adjacent_surfaces, load_security_context


def test_security_context_version_non_empty() -> None:
    assert isinstance(SECURITY_CONTEXT_VERSION, str)
    assert SECURITY_CONTEXT_VERSION


def test_load_security_context_has_expected_keys() -> None:
    context = load_security_context()
    expected_keys = {
        "version",
        "project",
        "chat_thread_title",
        "chat_thread_online_uuid",
        "chat_thread_canonical_id",
        "source",
    }
    assert expected_keys.issubset(context.keys())


def test_known_adjacent_surfaces_contains_primary_and_kant() -> None:
    surfaces = known_adjacent_surfaces()
    assert "../ITIR-suite" in surfaces
    assert "../zos-server" in surfaces
    assert "../zkperf" in surfaces
    assert "../ipfs-dasl" in surfaces
    assert "../kant-zk-pastebin" in surfaces
