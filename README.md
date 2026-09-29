# Agent Permission Kernel

The Agent Permission Kernel (APK) compiles per-agent capabilities, evaluates each proposed fixture operation before it runs, records allow, deny, and escalation decisions, and keeps human escalation evidence in an ordered audit trail.

## Quickstart

Requires Python 3.10 or later. The only runtime dependency is PyYAML. Install the package and test extra in a CPU-only Python environment:

```console
python -m pip install -e ".[test]"
apk policy show
apk policy validate
apk check --agent fixture_writer --op gmail.draft --target weekly-update
apk check --agent fixture_writer --op gmail.send --target reader@example.test
apk simulate --scenario apk/data/scenarios/full_demo.yaml
apk report --format html --output .apk/demo-report.html
apk audit
pytest
```

The CLI stores its ordered audit, synthetic spend ledger, and escalation queue under `.apk/` by default. Set `--state-dir PATH` before or after a command to use another local state directory. Set `--policy PATH` to compile a different YAML policy. `apk report --format md` prints Markdown to standard output; `--format html` prints HTML. Add `--output PATH` to save either format.

To review and decide an escalation, run `apk escalations list`, then `apk escalations decide ESCALATION_ID --approve --evidence "reviewed fixture diff"` or `--deny`. A later retry of the same deployment returns the human decision. The result includes an agent notification. A decision can only be recorded once.

## Architecture

```text
YAML policy ──> Capability compiler ──> Compiled per-agent grants
                                               │
Fixture operation ─────────────────────────────┤
                                               v
                                   Deterministic permission kernel
                                     │          │          │
                               allow / deny   escalate   audit event
                                     │          │          │
                                     v          v          v
                              Synthetic adapters  Human queue  JSON state
                                     │                         │
                                     └──── report and audit ───┘
```

The compiler validates known token types, canonical filesystem scopes, and conflicting duplicate or spend-cap grants. The kernel matches operations to compiled grants, accounts spend using decimal arithmetic, and creates stable escalation IDs. Spend charge targets are transaction IDs. Repeating the same agent, transaction ID, and amount is idempotent and does not charge the ledger twice. Audit entries contain a fixed fixture timestamp so repeated identical decisions serialize identically. Entry order in the audit array is the event order.

## HONESTY BOUNDARY

All operations in this project are SYNTHETIC fixtures: a fake Gmail, a fake filesystem, a fake spend ledger, and a fake production deploy. The kernel is a policy decision engine for these fixtures, NOT a real OS sandbox, NOT a real Gmail integration, and NOT a real security boundary. It does not isolate processes, access real accounts, or protect production systems. The filesystem adapter uses only an in-memory dictionary and never reads or writes host files. Gmail and deployment adapters are also in-memory. CLI output and generated reports repeat this boundary. A green policy decision only authorizes the corresponding synthetic adapter action.

## Capability catalogue

| Token | Scope semantics |
| --- | --- |
| `gmail.read` | Read synthetic Gmail fixture messages. |
| `gmail.draft` | Create a synthetic Gmail draft. This does not grant send. |
| `gmail.send` | Send through the synthetic Gmail fixture. |
| `fs.read:/absolute/path` | Read that synthetic directory and descendants. |
| `fs.write:/absolute/path` | Write that synthetic directory and descendants. |
| `spend.cap:$5` | Set the agent's cumulative synthetic spend ceiling in dollars. A charge at the cap is allowed; a charge above it is denied. |
| `prod.ask` | Permit a production deploy proposal to enter the human escalation queue. A deploy still waits for a human decision. |

Filesystem paths use POSIX-style absolute paths even on Windows. Matching is by directory boundary, so `/data` covers `/data/file` and `/data` itself, but not `/database`. `/`, relative paths, and paths containing traversal components are rejected as over-broad scopes. Grant multiple distinct directory tokens to give access to multiple trees. Distinct spend caps for the same agent conflict.

The default `fixture_writer` policy intentionally grants `gmail.read`, `gmail.draft`, `/data` read, `/tmp` write, a five dollar spend cap, and production escalation. It does not grant `gmail.send` or writes under `/data`.

`examples/demo-simulation.json`, `examples/demo-audit.json`, and `examples/demo-report.html` are generated from a fresh run of the full synthetic scenario. They show the recorded decisions, fixture spend total, pending deploy escalation, and report honesty banner.

## Denial and escalation reason catalogue

| Reason | Meaning |
| --- | --- |
| `unknown-capability` | The agent lacks the required capability, including `gmail.send` or `prod.ask`. |
| `scope-exceeded` | The filesystem operation target is outside every grant for that operation. |
| `spend-cap-hit` | The requested charge would move cumulative synthetic spend above the cap. |
| `needs-escalation` | The operation has a `prod.ask` grant and is waiting for a human decision. Decision value is `escalate`. |
| `escalation-denied` | A human denied the queued production operation. |
| `unknown-agent` | The policy has no entry for the requested agent. |
| `unknown-operation` | The operation name is not implemented by this kernel. |
| `invalid-operation` | A required operation field, such as a spend transaction ID or amount, is missing. |

Compiler errors use named codes: `unknown-capability`, `over-broad-scope`, `conflicting-grants`, and `invalid-policy`.

## Fixture scenarios

`apk/data/scenarios/privilege_escalation.yaml` attempts an ungranted Gmail send, a filesystem write outside the agent's write scope, and a production deploy that waits for escalation. `spend_overflow.yaml` charges three dollars and two dollars, then attempts one more dollar. It stops on the denied attempt and leaves the ledger at exactly the five dollar cap. `full_demo.yaml` combines the Gmail, filesystem, spend, and production cases.

The CLI persists audit and queue state as JSON. Its event timestamp is a fixed fixture time (`2026-09-29T00:00:00Z`) for reproducibility, not a claim about wall-clock time. The audit list order is authoritative when timestamps match.
