"""Command line interface for the Agent Permission Kernel."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .compiler import CAPABILITY_CATALOGUE, PolicyError, load_policy
from .kernel import Kernel
from .model import NOTICE
from .reporting import render_html, render_markdown
from .runtime import StateStore, load_scenario, make_operation, simulate


PACKAGE_DIR = Path(__file__).resolve().parent
DEFAULT_POLICY = PACKAGE_DIR / "data" / "default_policy.yaml"


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False)


def _runtime_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--policy", type=Path, default=argparse.SUPPRESS, help="YAML policy file")
    parser.add_argument("--state-dir", type=Path, default=argparse.SUPPRESS, help="directory for local audit and ledger state (default: .apk)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="apk",
        description="Compile and enforce capabilities for synthetic agent fixtures.",
        epilog=NOTICE,
    )
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY, help="YAML policy file")
    parser.add_argument("--state-dir", type=Path, default=Path(".apk"), help="directory for local audit and ledger state")
    commands = parser.add_subparsers(dest="command", required=True)

    policy_parser = commands.add_parser("policy", help="show or validate compiled capabilities")
    _runtime_flags(policy_parser)
    policy_commands = policy_parser.add_subparsers(dest="policy_command", required=True)
    show = policy_commands.add_parser("show", help="show compiled agents and capability catalogue")
    _runtime_flags(show)
    validate = policy_commands.add_parser("validate", help="compile and validate the policy")
    _runtime_flags(validate)

    check = commands.add_parser("check", help="decide one operation")
    _runtime_flags(check)
    check.add_argument("--agent", required=True)
    check.add_argument("--op", required=True)
    check.add_argument("--target", default="")
    check.add_argument("--cost", help="dollar amount for spend.charge")

    simulation = commands.add_parser("simulate", help="run scripted synthetic fixture operations")
    _runtime_flags(simulation)
    simulation.add_argument("--scenario", required=True, type=Path)

    escalations = commands.add_parser("escalations", help="inspect and decide human escalation requests")
    _runtime_flags(escalations)
    escalation_commands = escalations.add_subparsers(dest="escalation_command", required=True)
    listing = escalation_commands.add_parser("list", help="list all escalation requests")
    _runtime_flags(listing)
    decide = escalation_commands.add_parser("decide", help="record a human escalation decision")
    _runtime_flags(decide)
    decide.add_argument("id")
    choice = decide.add_mutually_exclusive_group(required=True)
    choice.add_argument("--approve", action="store_true")
    choice.add_argument("--deny", action="store_true")
    decide.add_argument("--evidence", default="", help="brief evidence or rationale for the human decision")

    report = commands.add_parser("report", help="render an audit and policy report")
    _runtime_flags(report)
    report.add_argument("--format", choices=("md", "html"), default="md")
    report.add_argument("--output", type=Path, help="write the report to this path instead of stdout")

    audit = commands.add_parser("audit", help="show ordered decision audit entries")
    _runtime_flags(audit)
    audit.add_argument("--agent")
    audit.add_argument("--decision", choices=("allow", "deny", "escalate"))
    return parser


def _state_and_kernel(args: argparse.Namespace) -> tuple[Kernel, StateStore]:
    policy = load_policy(args.policy)
    store = StateStore(args.state_dir)
    kernel = Kernel(policy, store.load())
    return kernel, store


def _notice_payload(data: dict[str, Any]) -> dict[str, Any]:
    return {"notice": NOTICE, **data}


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "policy":
            policy = load_policy(args.policy)
            if args.policy_command == "validate":
                print(_json(_notice_payload({"valid": True, "agents": sorted(policy.agents), "policy_digest": policy.digest})))
            else:
                print(_json(_notice_payload({
                    "agents": policy.matrix(),
                    "catalogue": CAPABILITY_CATALOGUE,
                    "policy_digest": policy.digest,
                })))
            return 0

        kernel, store = _state_and_kernel(args)
        if args.command == "check":
            operation = make_operation(args.agent, args.op, args.target, args.cost)
            decision = kernel.check(operation)
            store.save(kernel.state)
            print(_json(_notice_payload(decision.as_dict())))
            return 0

        if args.command == "simulate":
            result = simulate(load_scenario(args.scenario), kernel)
            store.save(kernel.state)
            print(_json(_notice_payload(result)))
            return 0 if result["passed"] else 1

        if args.command == "escalations":
            if args.escalation_command == "list":
                print(_json(_notice_payload({"escalations": list(kernel.escalations)})))
                return 0
            result = kernel.decide_escalation(args.id, args.approve, args.evidence)
            store.save(kernel.state)
            print(_json(_notice_payload(result)))
            return 0

        if args.command == "audit":
            events = [
                event for event in kernel.audit
                if (args.agent is None or event["agent"] == args.agent)
                and (args.decision is None or event["decision"] == args.decision)
            ]
            print(_json(_notice_payload({"count": len(events), "events": events})))
            return 0

        if args.command == "report":
            renderer = render_html if args.format == "html" else render_markdown
            content = renderer(kernel.policy, kernel.state)
            if args.output:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(content, encoding="utf-8")
                print(_json(_notice_payload({"format": args.format, "output": str(args.output)})))
            else:
                sys.stdout.write(content)
            return 0
    except PolicyError as exc:
        print(f"policy-error[{exc.code}]: {exc.message}", file=sys.stderr)
        return 2
    except (ValueError, KeyError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0

