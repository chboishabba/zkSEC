"""CLI facade for zkSEC policy/execution reporting."""

from __future__ import annotations

import argparse
import json
from typing import Sequence

from .execution import AdapterExecutionDirective, build_execution_directive
from .reporting import execution_audit_record
from .routing import evaluate_adapter_action


EXIT_STATUS_READY = 0
EXIT_STATUS_CONFIRMATION_REQUIRED = 2
EXIT_STATUS_BLOCKED = 3


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""

    parser = argparse.ArgumentParser(description="Evaluate an adapter action with zkSEC policy checks.")
    parser.add_argument("--adapter", required=True, help="Adapter name to evaluate.")
    parser.add_argument("--action", required=True, help="Action to evaluate.")
    parser.add_argument("--actor", default="operator", help="Actor role requesting action.")
    parser.add_argument(
        "--actor-identity",
        default=None,
        help="Stable actor identity for high-authority execution.",
    )
    parser.add_argument(
        "--scope",
        default=None,
        help="Execution scope for the action (required for high-authority actions).",
    )
    parser.add_argument(
        "--plan-ref",
        default=None,
        help="Reference to execution plan/receipt for high-authority actions.",
    )
    parser.add_argument(
        "--requested-capability",
        action="append",
        default=None,
        help="Optional request capabilities for this action. Repeat for multiple values.",
    )
    parser.add_argument(
        "--requested-channel",
        choices=["proposal", "confirmed", "autonomous"],
        default=None,
        help="Execution channel class to run under.",
    )
    parser.add_argument(
        "--requested-ring",
        choices=["sovereign", "bounded", "remote"],
        default=None,
        help="Capability ring to target.",
    )
    parser.add_argument(
        "--requested-destination",
        choices=["local", "peer", "public"],
        default=None,
        help="Declared destination class.",
    )
    parser.add_argument(
        "--resource",
        default=None,
        help=(
            "Resource target for the action. Must stay within adapter-scoped paths. "
            "URI-like values are rejected."
        ),
    )
    parser.add_argument(
        "--request-payload",
        default=None,
        help="Optional payload/request text to validate against secret-exposure patterns.",
    )
    parser.add_argument(
        "--requested-artifact-hash",
        default=None,
        help="Optional artifact hash for structural delta bookkeeping.",
    )
    parser.add_argument(
        "--previous-artifact-hash",
        default=None,
        help="Optional previous artifact hash for delta bookkeeping.",
    )
    parser.add_argument(
        "--payload-sanitized",
        action="store_true",
        help="Declare request payload has passed remote-minimization/sanitization checks.",
    )
    parser.add_argument(
        "--source",
        choices=["managed", "public"],
        default="managed",
        help="Source trust level for proposal material.",
    )
    parser.add_argument(
        "--risk",
        choices=["low", "medium", "high"],
        default="low",
        help="Declared risk level for the action.",
    )
    parser.add_argument(
        "--confirmed",
        action="store_true",
        help="Explicitly confirm high-risk actions.",
    )
    parser.add_argument(
        "--operator",
        default="ops",
        help="Operator identifier for execution planning.",
    )
    parser.add_argument(
        "--environment",
        default="sandbox",
        help="Execution environment descriptor.",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format.",
    )
    return parser


def run(argv: Sequence[str] | None = None) -> int:
    """Run one action evaluation and print an execution report.

    Return codes:
    0 -> ready
    2 -> requires_confirmation
    3 -> blocked
    """

    parser = build_parser()
    args = parser.parse_args(args=list(argv) if argv is not None else None)

    routed = evaluate_adapter_action(
        adapter_name=args.adapter,
        action=args.action,
        actor_role=args.actor,
        actor_identity=args.actor_identity,
        scope=args.scope,
        plan_ref=args.plan_ref,
        resource=args.resource,
        request_payload=args.request_payload,
        requested_capabilities=tuple(args.requested_capability) if args.requested_capability else (),
        source=args.source,
        risk_level=args.risk,
        confirmed=args.confirmed,
        requested_channel=args.requested_channel,
        requested_ring=args.requested_ring,
        requested_destination=args.requested_destination,
        requested_artifact_hash=args.requested_artifact_hash,
        previous_artifact_hash=args.previous_artifact_hash,
        payload_sanitized=args.payload_sanitized,
    )
    directive: AdapterExecutionDirective = build_execution_directive(
        routed=routed,
        operator=args.operator,
        environment=args.environment,
    )
    record = execution_audit_record(operator=args.operator, directive=directive)

    if args.format == "json":
        print(json.dumps(record, sort_keys=True))
    else:
        print(f"adapter={record['adapter']}")
        print(f"action={record['action']}")
        print(f"execution_status={record['execution_status']}")
        print(f"reason_code={record['reason_code']}")
        print(f"command={record['command']}")

    if directive.status == "ready":
        return EXIT_STATUS_READY
    if directive.status == "requires_confirmation":
        return EXIT_STATUS_CONFIRMATION_REQUIRED
    return EXIT_STATUS_BLOCKED


def main() -> int:
    """Entrypoint for direct execution."""

    return run()


if __name__ == "__main__":
    raise SystemExit(main())
