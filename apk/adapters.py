"""Synthetic adapters. These never access the host OS or real accounts."""

from __future__ import annotations

from typing import Any

from .model import AgentPolicy, CompiledPolicy, Decision, Operation, decimal_text


class SyntheticAdapters:
    """In-memory fixture systems used only by simulation."""

    def __init__(self, policy: CompiledPolicy, state: dict[str, Any]):
        self.policy = policy
        self.state = state
        self.gmail_messages = [
            {"id": "msg-001", "from": "fixture@example.test", "subject": "Synthetic sample"}
        ]
        self.gmail_drafts: list[dict[str, Any]] = []
        self.gmail_sent: list[dict[str, Any]] = []
        self.files = {
            "/data/readme.txt": "Synthetic fixture file. No host files are read.",
            "/tmp/notes.txt": "Synthetic temporary fixture file.",
        }
        self.deployments: list[str] = []

    def execute(self, operation: Operation, decision: Decision) -> dict[str, Any] | None:
        if decision.decision != "allow":
            return None
        if operation.op == "gmail.read":
            return {"adapter": "synthetic-gmail", "messages": list(self.gmail_messages)}
        if operation.op == "gmail.draft":
            draft = {"id": f"draft-{len(self.gmail_drafts) + 1:03d}", "target": operation.target}
            self.gmail_drafts.append(draft)
            return {"adapter": "synthetic-gmail", "draft": draft}
        if operation.op == "gmail.send":
            sent = {"id": f"sent-{len(self.gmail_sent) + 1:03d}", "target": operation.target}
            self.gmail_sent.append(sent)
            return {"adapter": "synthetic-gmail", "sent": sent}
        if operation.op == "fs.read":
            return {
                "adapter": "synthetic-filesystem",
                "path": operation.target,
                "content": self.files.get(operation.target, ""),
            }
        if operation.op == "fs.write":
            content = f"Synthetic fixture write to {operation.target}"
            self.files[operation.target] = content
            return {"adapter": "synthetic-filesystem", "path": operation.target, "written": True}
        if operation.op == "spend.charge":
            spent = self.state["spend"].get(operation.agent, "0")
            policy_agent = self.policy.agent(operation.agent)
            return {
                "adapter": "synthetic-spend-ledger",
                "transaction": operation.target,
                "charged": decimal_text(operation.cost or 0),
                "spent": spent,
                "cap": decimal_text(policy_agent.spend_cap) if policy_agent and policy_agent.spend_cap is not None else None,
            }
        if operation.op == "prod.deploy":
            self.deployments.append(operation.target)
            return {
                "adapter": "synthetic-production-deploy",
                "deployment": operation.target,
                "deployed": True,
            }
        return None


def adapter_catalogue() -> dict[str, str]:
    return {
        "gmail": "In-memory Gmail messages, drafts, and sent items.",
        "filesystem": "In-memory paths only; never reads or writes host files.",
        "spend-ledger": "In-memory per-agent decimal accounting against policy caps.",
        "production-deploy": "In-memory deployment records, always held for escalation.",
    }

