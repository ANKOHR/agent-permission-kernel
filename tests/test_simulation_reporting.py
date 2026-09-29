from pathlib import Path

from apk.kernel import Kernel
from apk.reporting import render_html, report_data
from apk.runtime import load_scenario, simulate


ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "apk" / "data" / "scenarios"


def test_privilege_escalation_scenario_matches_named_reasons(policy):
    kernel = Kernel(policy)
    result = simulate(load_scenario(SCENARIOS / "privilege_escalation.yaml"), kernel)
    assert result["passed"] is True
    assert [(row["decision"], row["reason"]) for row in result["results"]] == [
        ("deny", "unknown-capability"),
        ("deny", "scope-exceeded"),
        ("escalate", "needs-escalation"),
    ]
    assert len(kernel.audit) == 3


def test_spend_overflow_stops_at_the_exact_cap(policy):
    kernel = Kernel(policy)
    result = simulate(load_scenario(SCENARIOS / "spend_overflow.yaml"), kernel)
    assert result["passed"] is True
    assert result["operations_attempted"] == 3
    assert result["spend"] == {"fixture_writer": "5"}
    assert result["results"][-1]["reason"] == "spend-cap-hit"


def test_end_to_end_audit_and_html_report_have_banner(policy):
    kernel = Kernel(policy)
    result = simulate(load_scenario(SCENARIOS / "full_demo.yaml"), kernel)
    assert result["passed"] is True
    assert len(kernel.audit) == 9
    report = report_data(policy, kernel.state)
    assert report["denials_by_reason"] == {
        "scope-exceeded": 1,
        "spend-cap-hit": 1,
        "unknown-capability": 1,
    }
    html = render_html(policy, kernel.state)
    assert "HONESTY BOUNDARY" in html
    assert "not a real OS sandbox" in html
    assert "synthetic-production-deploy" not in html


def test_audit_order_is_preserved_and_complete(policy):
    kernel = Kernel(policy)
    simulate(load_scenario(SCENARIOS / "full_demo.yaml"), kernel)
    assert [event["operation"] for event in kernel.audit] == [
        "gmail.read",
        "gmail.draft",
        "gmail.send",
        "fs.read",
        "fs.write",
        "spend.charge",
        "spend.charge",
        "spend.charge",
        "prod.deploy",
    ]
    assert all(event["timestamp"] == "2026-09-29T00:00:00Z" for event in kernel.audit)

