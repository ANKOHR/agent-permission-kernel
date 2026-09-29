"""Audit presentation and synthetic fixture reports."""

from __future__ import annotations

import html
from collections import Counter
from decimal import Decimal
from typing import Any

from .model import CompiledPolicy, NOTICE, decimal_text


def report_data(policy: CompiledPolicy, state: dict[str, Any]) -> dict[str, Any]:
    denials = Counter(
        event["reason"]
        for event in state.get("audit", [])
        if event.get("decision") == "deny"
    )
    agents: dict[str, dict[str, Any]] = {}
    for agent_id, agent in sorted(policy.agents.items()):
        spent = Decimal(state.get("spend", {}).get(agent_id, "0"))
        cap = agent.spend_cap
        agents[agent_id] = {
            "capabilities": [cap.token for cap in agent.capabilities],
            "spend": decimal_text(spent),
            "spend_cap": decimal_text(cap) if cap is not None else None,
        }
    return {
        "notice": NOTICE,
        "agents": agents,
        "denials_by_reason": dict(sorted(denials.items())),
        "audit": list(state.get("audit", [])),
        "escalations": list(state.get("escalations", [])),
    }


def render_markdown(policy: CompiledPolicy, state: dict[str, Any]) -> str:
    data = report_data(policy, state)
    lines = [
        "# Agent Permission Kernel report",
        "",
        f"> **HONESTY BOUNDARY:** {NOTICE}",
        "",
        "All timestamps use the fixed deterministic fixture clock. Audit array order is event order.",
        "",
        "## Agent capability matrix",
        "",
        "| Agent | Capabilities | Spend | Cap |",
        "| --- | --- | ---: | ---: |",
    ]
    for agent_id, item in data["agents"].items():
        capabilities = ", ".join(item["capabilities"])
        spend_cap = f"${item['spend_cap']}" if item["spend_cap"] is not None else "none"
        lines.append(f"| {agent_id} | {capabilities} | ${item['spend']} | {spend_cap} |")
    lines.extend(["", "## Denials by reason", ""])
    if data["denials_by_reason"]:
        for reason, count in data["denials_by_reason"].items():
            lines.append(f"- `{reason}`: {count}")
    else:
        lines.append("No denials recorded.")
    lines.extend(["", "## Ordered audit trail", "", "| # | Agent | Operation | Target | Decision | Reason | Timestamp |", "| ---: | --- | --- | --- | --- | --- | --- |"])
    for index, event in enumerate(data["audit"], start=1):
        values = [event.get(key, "") for key in ("agent", "operation", "target", "decision", "reason", "timestamp")]
        lines.append("| " + str(index) + " | " + " | ".join(str(value).replace("|", "\\|") for value in values) + " |")
    lines.extend(["", "## Escalations", ""])
    if data["escalations"]:
        for entry in data["escalations"]:
            lines.append(f"- `{entry['id']}`: {entry['status']} for {entry['agent']} on {entry['target']}")
    else:
        lines.append("No escalations recorded.")
    lines.append("")
    return "\n".join(lines)


def render_html(policy: CompiledPolicy, state: dict[str, Any]) -> str:
    data = report_data(policy, state)
    rows = []
    for agent_id, item in data["agents"].items():
        rows.append(
            "<tr><td>{}</td><td>{}</td><td>${}</td><td>{}</td></tr>".format(
                html.escape(agent_id),
                html.escape(", ".join(item["capabilities"])),
                html.escape(item["spend"]),
                html.escape("$" + item["spend_cap"] if item["spend_cap"] is not None else "none"),
            )
        )
    denial_rows = [
        f"<tr><td>{html.escape(reason)}</td><td>{count}</td></tr>"
        for reason, count in data["denials_by_reason"].items()
    ] or ['<tr><td colspan="2">No denials recorded.</td></tr>']
    audit_rows = []
    for index, event in enumerate(data["audit"], start=1):
        audit_rows.append(
            "<tr><td>{}</td>{}</tr>".format(
                index,
                "".join(f"<td>{html.escape(str(event.get(key, '')))}</td>" for key in
                        ("agent", "operation", "target", "decision", "reason", "timestamp")),
            )
        )
    escalation_rows = [
        f"<tr><td>{html.escape(item['id'])}</td><td>{html.escape(item['agent'])}</td>"
        f"<td>{html.escape(item['target'])}</td><td>{html.escape(item['status'])}</td></tr>"
        for item in data["escalations"]
    ] or ['<tr><td colspan="4">No escalations recorded.</td></tr>']
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Agent Permission Kernel report</title>
  <style>
    body {{ font: 16px/1.5 system-ui, sans-serif; max-width: 1100px; margin: 2rem auto; padding: 0 1rem; color: #17212b; }}
    .banner {{ padding: 1rem; background: #fff1c2; border: 2px solid #9b6811; font-weight: 700; }}
    table {{ border-collapse: collapse; width: 100%; margin: 1rem 0 2rem; }}
    th, td {{ text-align: left; border: 1px solid #bdc7d0; padding: .5rem; vertical-align: top; }}
    th {{ background: #edf2f6; }}
    code {{ overflow-wrap: anywhere; }}
  </style>
</head>
<body>
  <h1>Agent Permission Kernel report</h1>
  <p class="banner">HONESTY BOUNDARY: {notice}</p>
  <p>All timestamps use the fixed deterministic fixture clock. Audit table order is event order.</p>
  <h2>Agent capability matrix</h2>
  <table><thead><tr><th>Agent</th><th>Capabilities</th><th>Spend</th><th>Cap</th></tr></thead><tbody>{agents}</tbody></table>
  <h2>Denials by reason</h2>
  <table><thead><tr><th>Reason</th><th>Count</th></tr></thead><tbody>{denials}</tbody></table>
  <h2>Ordered audit trail</h2>
  <table><thead><tr><th>#</th><th>Agent</th><th>Operation</th><th>Target</th><th>Decision</th><th>Reason</th><th>Timestamp</th></tr></thead><tbody>{audit}</tbody></table>
  <h2>Escalations</h2>
  <table><thead><tr><th>ID</th><th>Agent</th><th>Target</th><th>Status</th></tr></thead><tbody>{escalations}</tbody></table>
</body>
</html>
""".format(
        notice=html.escape(data["notice"]),
        agents="\n".join(rows),
        denials="\n".join(denial_rows),
        audit="\n".join(audit_rows),
        escalations="\n".join(escalation_rows),
    )

