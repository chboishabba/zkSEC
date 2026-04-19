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
            "--requested-artifact-hash",
            "hash-a",
            "--previous-artifact-hash",
            "hash-b",
        ]
    )
    assert status == 0

    captured = capsys.readouterr().out.strip()
    assert captured
    payload = json.loads(captured)
    assert payload["execution_status"] == "ready"
    assert payload["adapter"] == "kant_zk_pastebin"
    assert payload["command"] == "sandbox://ops@kant_zk_pastebin/read"
    assert payload["requested_artifact_hash"] == "hash-a"
    assert payload["previous_artifact_hash"] == "hash-b"


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
            "--actor-identity",
            "ops-123",
            "--scope",
            "sandbox",
            "--plan-ref",
            "plan-2026-04-07",
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


def test_cli_blocks_high_authority_without_plan_ref(capsys: object) -> None:
    status = run(
        [
            "--adapter",
            "zos_server",
            "--action",
            "patch",
            "--actor",
            "operator",
            "--actor-identity",
            "ops-123",
            "--scope",
            "sandbox",
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
    assert status == 3
    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["execution_status"] == "blocked"
    assert payload["reason_code"] == "missing_plan_receipt"


def test_cli_blocks_secret_payload(capsys: object) -> None:
    status = run(
        [
            "--adapter",
            "zos_server",
            "--action",
            "read",
            "--actor",
            "operator",
            "--actor-identity",
            "ops-123",
            "--scope",
            "sandbox",
            "--plan-ref",
            "plan-2026-04-07",
            "--request-payload",
            "AKIAABCDEFGHIJKLMNOP",
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
    assert status == 3
    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["execution_status"] == "blocked"
    assert payload["reason_code"] == "secret_material_detected"


def test_cli_blocks_capability_geometry_violation(capsys: object) -> None:
    status = run(
        [
            "--adapter",
            "zos_server",
            "--action",
            "read",
            "--actor",
            "operator",
            "--actor-identity",
            "ops-123",
            "--scope",
            "sandbox",
            "--plan-ref",
            "plan-2026-04-07",
            "--requested-capability",
            "artifact_publish",
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
    assert status == 3
    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["execution_status"] == "blocked"
    assert payload["reason_code"] == "capability_widening_detected"
    assert payload["reason_message"].startswith("Requested capability set")
