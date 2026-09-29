"""Compile and validate capability policies from YAML."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

from .model import AgentPolicy, Capability, CompiledPolicy, parse_amount


class PolicyError(ValueError):
    """A named policy compilation error suitable for CLI display."""

    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


CAPABILITY_CATALOGUE = {
    "gmail.read": "Read synthetic Gmail fixture messages.",
    "gmail.draft": "Create a draft in the synthetic Gmail fixture.",
    "gmail.send": "Send through the synthetic Gmail fixture.",
    "fs.read:<absolute-path>": "Read a synthetic path under the granted directory.",
    "fs.write:<absolute-path>": "Write a synthetic path under the granted directory.",
    "spend.cap:$<amount>": "Maximum cumulative synthetic spend, in dollars.",
    "prod.ask": "Allow production deploy requests to enter human escalation.",
}

_FIXED = {"gmail.read", "gmail.draft", "gmail.send", "prod.ask"}
_SCOPE_RE = re.compile(r"^fs\.(read|write):(.+)$")
_SPEND_RE = re.compile(r"^spend\.cap:\$(.+)$")


def _normalise_scope(scope: str) -> str:
    if not scope.startswith("/") or scope.startswith("//"):
        raise PolicyError("over-broad-scope", f"filesystem scope {scope!r} must be an absolute path")
    raw_parts = scope.split("/")[1:]
    if any(part in {"", ".", ".."} for part in raw_parts):
        raise PolicyError("over-broad-scope", f"filesystem scope {scope!r} must not contain empty or traversal components")
    path = PurePosixPath(scope)
    normal = str(path)
    if normal == "/":
        raise PolicyError("over-broad-scope", "filesystem scope '/' grants access to every fixture path")
    if normal != scope:
        raise PolicyError("over-broad-scope", f"filesystem scope {scope!r} must be canonical")
    return normal


def _parse_capability(token: Any) -> Capability:
    if not isinstance(token, str) or not token:
        raise PolicyError("unknown-capability", f"capability token {token!r} is not a string token")
    if token in _FIXED:
        return Capability(token=token, kind=token)
    match = _SCOPE_RE.fullmatch(token)
    if match:
        kind = f"fs.{match.group(1)}"
        scope = _normalise_scope(match.group(2))
        return Capability(token=f"{kind}:{scope}", kind=kind, scope=scope)
    match = _SPEND_RE.fullmatch(token)
    if match:
        try:
            limit = parse_amount(match.group(1), field="spend cap")
        except ValueError as exc:
            raise PolicyError("unknown-capability", str(exc)) from exc
        return Capability(token=f"spend.cap:${limit:f}", kind="spend.cap", limit=limit)
    raise PolicyError("unknown-capability", f"capability {token!r} is not in the capability catalogue")


def compile_policy(document: Any) -> CompiledPolicy:
    if not isinstance(document, dict):
        raise PolicyError("invalid-policy", "policy document must be a mapping")
    if document.get("version") != 1:
        raise PolicyError("invalid-policy", "policy version must be 1")
    raw_agents = document.get("agents")
    if not isinstance(raw_agents, dict) or not raw_agents:
        raise PolicyError("invalid-policy", "agents must be a non-empty mapping")

    agents: dict[str, AgentPolicy] = {}
    for agent_id, body in raw_agents.items():
        if not isinstance(agent_id, str) or not agent_id.strip():
            raise PolicyError("invalid-policy", "agent IDs must be non-empty strings")
        if not isinstance(body, dict) or not isinstance(body.get("capabilities"), list):
            raise PolicyError("invalid-policy", f"agent {agent_id!r} must have a capabilities list")
        caps: list[Capability] = []
        seen: set[str] = set()
        spend_limits: set[str] = set()
        for raw in body["capabilities"]:
            cap = _parse_capability(raw)
            if cap.token in seen:
                raise PolicyError("conflicting-grants", f"agent {agent_id!r} repeats grant {cap.token!r}")
            seen.add(cap.token)
            if cap.kind == "spend.cap":
                spend_limits.add(str(cap.limit))
            caps.append(cap)
        if len(spend_limits) > 1:
            raise PolicyError("conflicting-grants", f"agent {agent_id!r} has multiple different spend caps")
        agents[agent_id] = AgentPolicy(agent_id, tuple(caps))

    canonical = {
        "version": 1,
        "agents": {
            agent_id: sorted(cap.token for cap in policy.capabilities)
            for agent_id, policy in sorted(agents.items())
        },
    }
    digest = hashlib.sha256(json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return CompiledPolicy(agents=agents, digest=digest)


def load_policy(path: str | Path) -> CompiledPolicy:
    source = Path(path)
    try:
        with source.open("r", encoding="utf-8") as handle:
            document = yaml.safe_load(handle)
    except OSError as exc:
        raise PolicyError("invalid-policy", f"cannot read policy file {source}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise PolicyError("invalid-policy", f"cannot parse policy YAML: {exc}") from exc
    return compile_policy(document)
