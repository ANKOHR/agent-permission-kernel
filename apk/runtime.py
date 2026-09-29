"""Persistence and scripted scenario execution."""

from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path
from typing import Any

import yaml

from .adapters import SyntheticAdapters
from .kernel import Kernel
from .model import CompiledPolicy, Operation, parse_amount


class StateStore:
    def __init__(self, directory: str | Path):
        self.directory = Path(directory)
        self.path = self.directory / "state.json"

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {}
        try:
            state = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"cannot read state file {self.path}: {exc}") from exc
        if not isinstance(state, dict):
            raise ValueError(f"state file {self.path} must contain a JSON object")
        return state

    def save(self, state: dict[str, Any]) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(self.path)


def make_operation(agent: str, op: str, target: str = "", cost: Any = None) -> Operation:
    amount = None if cost is None else parse_amount(cost, field="cost")
    return Operation(agent=agent, op=op, target=target, cost=amount)


def load_scenario(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    try:
        document = yaml.safe_load(source.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ValueError(f"cannot load scenario {source}: {exc}") from exc
    if not isinstance(document, dict) or not isinstance(document.get("operations"), list):
        raise ValueError("scenario must be a mapping with an operations list")
    for index, item in enumerate(document["operations"]):
        if not isinstance(item, dict) or not all(key in item for key in ("agent", "op")):
            raise ValueError(f"scenario operation {index + 1} needs agent and op")
    return document


def simulate(scenario: dict[str, Any], kernel: Kernel) -> dict[str, Any]:
    adapters = SyntheticAdapters(kernel.policy, kernel.state)
    results: list[dict[str, Any]] = []
    stop_on_reason = scenario.get("stop_on_reason")
    for index, item in enumerate(scenario["operations"], start=1):
        operation = make_operation(
            str(item["agent"]),
            str(item["op"]),
            str(item.get("target", "")),
            item.get("cost"),
        )
        decision = kernel.check(operation)
        adapter_result = adapters.execute(operation, decision)
        expected = item.get("expect")
        if isinstance(expected, str):
            expected = {"decision": expected}
        if expected is not None and not isinstance(expected, dict):
            raise ValueError(f"scenario operation {index} expect must be a string or mapping")
        matched = expected is None or all(
            getattr(decision, key) == value
            for key, value in expected.items()
            if key in {"decision", "reason"}
        )
        results.append(
            {
                "index": index,
                **decision.as_dict(),
                "expected": expected,
                "matched": matched,
                "adapter_result": adapter_result,
            }
        )
        if stop_on_reason and decision.reason == stop_on_reason:
            break
    return {
        "scenario": scenario.get("name", "unnamed"),
        "passed": all(item["matched"] for item in results),
        "operations_attempted": len(results),
        "results": results,
        "spend": dict(kernel.state["spend"]),
        "pending_escalations": sum(1 for item in kernel.escalations if item["status"] == "pending"),
    }

