"""Shared models and stable JSON helpers."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Any


NOTICE = (
    "Synthetic fixtures only. This is a policy decision engine, not a real OS "
    "sandbox, real Gmail integration, or production security boundary."
)
FIXTURE_TIMESTAMP = "2026-09-29T00:00:00Z"


@dataclass(frozen=True)
class Capability:
    token: str
    kind: str
    scope: str | None = None
    limit: Decimal | None = None


@dataclass(frozen=True)
class AgentPolicy:
    agent_id: str
    capabilities: tuple[Capability, ...]

    @property
    def spend_cap(self) -> Decimal | None:
        caps = [cap.limit for cap in self.capabilities if cap.kind == "spend.cap"]
        return caps[0] if caps else None

    def has(self, kind: str) -> bool:
        return any(cap.kind == kind for cap in self.capabilities)

    def scopes(self, kind: str) -> tuple[str, ...]:
        return tuple(cap.scope for cap in self.capabilities if cap.kind == kind and cap.scope)


@dataclass(frozen=True)
class CompiledPolicy:
    agents: dict[str, AgentPolicy]
    digest: str

    def agent(self, agent_id: str) -> AgentPolicy | None:
        return self.agents.get(agent_id)

    def matrix(self) -> dict[str, list[str]]:
        return {
            agent_id: [cap.token for cap in policy.capabilities]
            for agent_id, policy in sorted(self.agents.items())
        }


@dataclass(frozen=True)
class Operation:
    agent: str
    op: str
    target: str = ""
    cost: Decimal | None = None

    def identity(self) -> dict[str, Any]:
        return {
            "agent": self.agent,
            "op": self.op,
            "target": self.target,
            "cost": decimal_text(self.cost) if self.cost is not None else None,
        }


@dataclass(frozen=True)
class Decision:
    agent: str
    operation: str
    decision: str
    reason: str
    target: str = ""
    escalation_id: str | None = None
    details: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "agent": self.agent,
            "operation": self.operation,
            "target": self.target,
            "decision": self.decision,
            "reason": self.reason,
        }
        if self.escalation_id is not None:
            result["escalation_id"] = self.escalation_id
        if self.details:
            result["details"] = self.details
        return result


def decimal_text(value: Decimal) -> str:
    text = format(value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text or "0"


def parse_amount(value: Any, *, field: str) -> Decimal:
    try:
        amount = Decimal(str(value).replace("$", ""))
    except Exception as exc:
        raise ValueError(f"{field} must be a valid decimal amount") from exc
    if not amount.is_finite() or amount < 0:
        raise ValueError(f"{field} must be a finite non-negative amount")
    return amount

