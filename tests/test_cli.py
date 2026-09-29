import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "apk" / "data" / "scenarios"


def apk(*args):
    return subprocess.run(
        [sys.executable, "-m", "apk", *map(str, args)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def json_stdout(result):
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_policy_show_and_validate_smoke():
    shown = json_stdout(apk("policy", "show"))
    validated = json_stdout(apk("policy", "validate"))
    assert "fixture_writer" in shown["agents"]
    assert shown["catalogue"]["gmail.draft"]
    assert validated["valid"] is True


def test_check_smoke_for_allow_and_named_deny(tmp_path):
    allowed = json_stdout(apk("check", "--state-dir", tmp_path / "state", "--agent", "fixture_writer", "--op", "gmail.draft", "--target", "draft-x"))
    denied = json_stdout(apk("check", "--state-dir", tmp_path / "state", "--agent", "fixture_writer", "--op", "gmail.send", "--target", "person@example.test"))
    assert allowed["decision"] == "allow"
    assert denied["reason"] == "unknown-capability"


def test_simulate_smoke_and_expected_outcomes(tmp_path):
    result = json_stdout(apk("simulate", "--state-dir", tmp_path / "state", "--scenario", SCENARIOS / "privilege_escalation.yaml"))
    assert result["passed"] is True
    assert result["operations_attempted"] == 3


def test_escalation_list_decide_and_retry_smoke(tmp_path):
    state = tmp_path / "state"
    initial = json_stdout(apk("check", "--state-dir", state, "--agent", "fixture_writer", "--op", "prod.deploy", "--target", "prod/cli-smoke"))
    listed = json_stdout(apk("escalations", "list", "--state-dir", state))
    assert listed["escalations"][0]["status"] == "pending"
    decided = json_stdout(apk("escalations", "decide", initial["escalation_id"], "--approve", "--evidence", "CLI smoke", "--state-dir", state))
    assert decided["status"] == "approved"
    retry = json_stdout(apk("check", "--state-dir", state, "--agent", "fixture_writer", "--op", "prod.deploy", "--target", "prod/cli-smoke"))
    assert (retry["decision"], retry["reason"]) == ("allow", "escalation-approved")


def test_audit_and_markdown_html_reports_smoke(tmp_path):
    state = tmp_path / "state"
    json_stdout(apk("simulate", "--state-dir", state, "--scenario", SCENARIOS / "full_demo.yaml"))
    audit = json_stdout(apk("audit", "--state-dir", state))
    assert audit["count"] == 9
    markdown = apk("report", "--state-dir", state, "--format", "md")
    assert markdown.returncode == 0
    assert "HONESTY BOUNDARY" in markdown.stdout
    report_path = tmp_path / "fixture-report.html"
    saved = json_stdout(apk("report", "--state-dir", state, "--format", "html", "--output", report_path))
    assert saved["output"] == str(report_path)
    assert "HONESTY BOUNDARY" in report_path.read_text(encoding="utf-8")


def test_scope_and_spend_checks_smoke(tmp_path):
    state = tmp_path / "state"
    scope = json_stdout(apk("check", "--state-dir", state, "--agent", "fixture_writer", "--op", "fs.write", "--target", "/etc/secret"))
    first = json_stdout(apk("check", "--state-dir", state, "--agent", "fixture_writer", "--op", "spend.charge", "--target", "cli-invoice-1", "--cost", "5"))
    overflow = json_stdout(apk("check", "--state-dir", state, "--agent", "fixture_writer", "--op", "spend.charge", "--target", "cli-invoice-2", "--cost", "0.01"))
    assert scope["reason"] == "scope-exceeded"
    assert first["decision"] == "allow"
    assert overflow["reason"] == "spend-cap-hit"


def test_compiler_named_error_surfaces_in_cli(tmp_path):
    bad_policy = tmp_path / "bad.yaml"
    bad_policy.write_text("version: 1\nagents:\n  a:\n    capabilities: [gmail.admin]\n", encoding="utf-8")
    result = apk("--policy", bad_policy, "policy", "show")
    assert result.returncode == 2
    assert "policy-error[unknown-capability]" in result.stderr

