"""Deterministic permission evaluation and append-only fixture audit trail."""

from __future__ import annotations

import hashlib
import json
from decimal import Decimal
from typing import Any

from .model import (
    FIXTURE_TIMESTAMP,
    AgentPolicy,
    CompiledPolicy,
    Decision,
    Operation,
    decimal_text,
)


def _stable_hash(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class Kernel:
    """Evaluate synthetic operations and retain their ordered decisions."""

    def __init__(self, policy: CompiledPolicy, state: dict[str, Any] | None = None):
        self.policy = policy
        self.state = state if state is not None else {}
        self.state.setdefault("audit", [])
        self.state.setdefault("spend", {})
        self.state.setdefault("spend_transactions", {})
        self.state.setdefault("escalations", [])

    @property
    def audit(self) -> list[dict[str, Any]]:
        return self.state["audit"]

    @property
    def escalations(self) -> list[dict[str, Any]]:
        return self.state["escalations"]

    def _record(self, decision: Decision) -> Decision:
        self.audit.append(
            {
                "agent": decision.agent,
                "operation": decision.operation,
                "target": decision.target,
                "decision": decision.decision,
                "reason": decision.reason,
                "timestamp": FIXTURE_TIMESTAMP,
            }
        )
        return decision

    def _decision(
        self,
        operation: Operation,
        result: str,
        reason: str,
        *,
        escalation_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> Decision:
        return self._record(
            Decision(
                agent=operation.agent,
                operation=operation.op,
                target=operation.target,
                decision=result,
                reason=reason,
                escalation_id=escalation_id,
                details=details,
            )
        )

    @staticmethod
    def _in_scope(target: str, scope: str) -> bool:
        if not target.startswith("/") or ".." in target.split("/"):
            return False
        normalized = target.rstrip("/") or "/"
        return normalized == scope or normalized.startswith(scope.rstrip("/") + "/")

    def _prior_spend_decision(self, key: str) -> Decision | None:
        cached = self.state["spend_transactions"].get(key)
        if not cached:
            return None
        return Decision(**cached)

    def check(self, operation: Operation) -> Decision:
        """Decide and log one operation. Spend charge IDs are idempotency keys."""
        agent = self.policy.agent(operation.agent)
        if agent is None:
            return self._decision(operation, "deny", "unknown-agent")

        if operation.op in {"gmail.read", "gmail.draft", "gmail.send"}:
            if not agent.has(operation.op):
                return self._decision(operation, "deny", "unknown-capability")
            return self._decision(operation, "allow", "capability-granted")

        if operation.op in {"fs.read", "fs.write"}:
            scopes = agent.scopes(operation.op)
            if not scopes:
                return self._decision(operation, "deny", "unknown-capability")
            if not operation.target or not any(self._in_scope(operation.target, scope) for scope in scopes):
                return self._decision(operation, "deny", "scope-exceeded")
            return self._decision(operation, "allow", "capability-granted")

        if operation.op == "spend.charge":
            transaction_key = _stable_hash(
                {"policy": self.policy.digest, **operation.identity()}
            )
            prior = self._prior_spend_decision(transaction_key)
            if prior is not None:
                return self._record(prior)
            if operation.cost is None or not operation.target:
                decision = self._decision(operation, "deny", "invalid-operation")
            elif agent.spend_cap is None:
                decision = self._decision(operation, "deny", "unknown-capability")
            else:
                spent = Decimal(self.state["spend"].get(operation.agent, "0"))
                projected = spent + operation.cost
                if projected > agent.spend_cap:
                    decision = self._decision(
                        operation,
                        "deny",
                        "spend-cap-hit",
                        details={
                            "spent": decimal_text(spent),
                            "requested": decimal_text(operation.cost),
                            "cap": decimal_text(agent.spend_cap),
                        },
                    )
                else:
                    self.state["spend"][operation.agent] = decimal_text(projected)
                    decision = self._decision(
                        operation,
                        "allow",
                        "capability-granted",
                        details={
                            "spent": decimal_text(projected),
                            "cap": decimal_text(agent.spend_cap),
                        },
                    )
            self.state["spend_transactions"][transaction_key] = {
                "agent": decision.agent,
                "operation": decision.operation,
                "decision": decision.decision,
                "reason": decision.reason,
                "target": decision.target,
                "escalation_id": decision.escalation_id,
                "details": decision.details,
            }
            return decision

        if operation.op == "prod.deploy":
            if not agent.has("prod.ask"):
                return self._decision(operation, "deny", "unknown-capability")
            escalation_id = "esc-" + _stable_hash(
                {"policy": self.policy.digest, **operation.identity()}
            )[:12]
            entry = next((item for item in self.escalations if item["id"] == escalation_id), None)
            if entry and entry["status"] == "approved":
                return self._decision(
                    operation,
                    "allow",
                    "escalation-approved",
                    escalation_id=escalation_id,
                    details={"evidence": entry.get("evidence", "")},
                )
            if entry and entry["status"] == "denied":
                return self._decision(
                    operation,
                    "deny",
                    "escalation-denied",
                    escalation_id=escalation_id,
                    details={"evidence": entry.get("evidence", "")},
                )
            if entry is None:
                self.escalations.append(
                    {
                        "id": escalation_id,
                        "agent": operation.agent,
                        "operation": operation.op,
                        "target": operation.target,
                        "status": "pending",
                        "created_at": FIXTURE_TIMESTAMP,
                        "decision": None,
                        "evidence": "",
                    }
                )
            return self._decision(
                operation,
                "escalate",
                "needs-escalation",
                escalation_id=escalation_id,
            )

        return self._decision(operation, "deny", "unknown-operation")

    def decide_escalation(self, escalation_id: str, approve: bool, evidence: str = "") -> dict[str, Any]:
        entry = next((item for item in self.escalations if item["id"] == escalation_id), None)
        if entry is None:
            raise KeyError(f"unknown escalation {escalation_id}")
        if entry["status"] != "pending":
            raise ValueError(f"escalation {escalation_id} is already {entry['status']}")
        status = "approved" if approve else "denied"
        entry["status"] = status
        entry["decision"] = "approve" if approve else "deny"
        entry["evidence"] = evidence or ("Human approved via CLI." if approve else "Human denied via CLI.")
        entry["decided_at"] = FIXTURE_TIMESTAMP
        self._record(
            Decision(
                agent=entry["agent"],
                operation=entry["operation"],
                target=entry["target"],
                decision="allow" if approve else "deny",
                reason="human-approved" if approve else "human-denied",
            )
        )
        entry["agent_notification"] = (
            "The human approved this production deployment. Retry the operation to apply it."
            if approve
            else "The human denied this production deployment. The operation is blocked."
        )
        return dict(entry)

