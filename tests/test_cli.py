import json

from zksec.cli import run


def test_cli_ready_path_outputs_json_and_returns_zero(capsys: object) -> None:
    status = run(
        [
            "--adapter",
            "kant_zk_pastebin",
            "--action",
            "read",
            "--actor",
            "operator",
            "--source",
            "managed",
            "--risk",
            "low",
            "--format",
            "json",
            "--operator",
            "ops",
        ]
    )
    assert status == 0

    captured = capsys.readouterr().out.strip()
    assert captured
    payload = json.loads(captured)
    assert payload["execution_status"] == "ready"
    assert payload["adapter"] == "kant_zk_pastebin"
    assert payload["command"] == "sandbox://ops@kant_zk_pastebin/read"


def test_cli_requires_confirmation_path(capsys: object) -> None:
    status = run(
        [
            "--adapter",
            "zos_server",
            "--action",
            "patch",
            "--actor",
            "operator",
            "--source",
            "managed",
            "--risk",
            "high",
            "--format",
            "json",
            "--operator",
            "ops",
        ]
    )
    assert status == 2
    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["execution_status"] == "requires_confirmation"


def test_cli_blocked_path_returns_code_three(capsys: object) -> None:
    status = run(
        [
            "--adapter",
            "mystery_adapter",
            "--action",
            "read",
            "--actor",
            "operator",
            "--source",
            "managed",
            "--format",
            "json",
            "--operator",
            "ops",
        ]
    )
    assert status == 3
    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["execution_status"] == "blocked"
    assert payload["reason_code"] == "unknown_adapter"
