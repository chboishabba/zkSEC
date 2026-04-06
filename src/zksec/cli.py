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
        source=args.source,
        risk_level=args.risk,
        confirmed=args.confirmed,
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
