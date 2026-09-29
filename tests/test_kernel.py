import json
from decimal import Decimal

from apk.kernel import Kernel
from apk.model import Operation


def test_gmail_draft_allowed_but_send_denied(policy):
    kernel = Kernel(policy)
    draft = kernel.check(Operation("fixture_writer", "gmail.draft", "draft-1"))
    send = kernel.check(Operation("fixture_writer", "gmail.send", "recipient@example.test"))
    assert (draft.decision, draft.reason) == ("allow", "capability-granted")
    assert (send.decision, send.reason) == ("deny", "unknown-capability")


def test_filesystem_directory_boundaries(policy):
    kernel = Kernel(policy)
    allowed = kernel.check(Operation("fixture_writer", "fs.write", "/tmp/item.txt"))
    outside = kernel.check(Operation("fixture_writer", "fs.write", "/tmp-other/item.txt"))
    traversal = kernel.check(Operation("fixture_writer", "fs.write", "/tmp/../data/item.txt"))
    assert allowed.decision == "allow"
    assert outside.reason == "scope-exceeded"
    assert traversal.reason == "scope-exceeded"


def test_spend_cap_allows_exact_cap_and_denies_overflow(policy):
    kernel = Kernel(policy)
    first = kernel.check(Operation("fixture_writer", "spend.charge", "invoice-1", Decimal("3")))
    second = kernel.check(Operation("fixture_writer", "spend.charge", "invoice-2", Decimal("2")))
    third = kernel.check(Operation("fixture_writer", "spend.charge", "invoice-3", Decimal("0.01")))
    assert [first.decision, second.decision, third.reason] == ["allow", "allow", "spend-cap-hit"]
    assert kernel.state["spend"]["fixture_writer"] == "5"


def test_same_check_has_byte_identical_decision_and_audit(policy):
    kernel = Kernel(policy)
    operation = Operation("fixture_writer", "gmail.draft", "deterministic-draft")
    first = kernel.check(operation)
    first_entry = kernel.audit[-1]
    second = kernel.check(operation)
    second_entry = kernel.audit[-1]
    assert json.dumps(first.as_dict(), sort_keys=True, separators=(",", ":")) == json.dumps(
        second.as_dict(), sort_keys=True, separators=(",", ":")
    )
    assert json.dumps(first_entry, sort_keys=True, separators=(",", ":")).encode() == json.dumps(
        second_entry, sort_keys=True, separators=(",", ":")
    ).encode()


def test_repeated_spend_transaction_is_idempotent(policy):
    kernel = Kernel(policy)
    operation = Operation("fixture_writer", "spend.charge", "invoice-retry", Decimal("3"))
    first = kernel.check(operation)
    second = kernel.check(operation)
    assert first.as_dict() == second.as_dict()
    assert kernel.state["spend"]["fixture_writer"] == "3"
    assert kernel.audit[-1] == kernel.audit[-2]


def test_production_deploy_waits_for_human(policy):
    kernel = Kernel(policy)
    result = kernel.check(Operation("fixture_writer", "prod.deploy", "prod/payments"))
    assert result.decision == "escalate"
    assert result.reason == "needs-escalation"
    assert len(kernel.escalations) == 1
    assert kernel.escalations[0]["status"] == "pending"


def test_approval_allows_retry_and_records_evidence(policy):
    kernel = Kernel(policy)
    operation = Operation("fixture_writer", "prod.deploy", "prod/payments")
    waiting = kernel.check(operation)
    record = kernel.decide_escalation(waiting.escalation_id, True, "reviewed synthetic release")
    retry = kernel.check(operation)
    assert record["status"] == "approved"
    assert record["evidence"] == "reviewed synthetic release"
    assert "approved" in record["agent_notification"]
    assert (retry.decision, retry.reason) == ("allow", "escalation-approved")


def test_denial_blocks_retry_and_records_decision(policy):
    kernel = Kernel(policy)
    operation = Operation("fixture_writer", "prod.deploy", "prod/payments")
    waiting = kernel.check(operation)
    record = kernel.decide_escalation(waiting.escalation_id, False, "fixture risk not accepted")
    retry = kernel.check(operation)
    assert record["status"] == "denied"
    assert record["evidence"] == "fixture risk not accepted"
    assert "denied" in record["agent_notification"]
    assert (retry.decision, retry.reason) == ("deny", "escalation-denied")


def test_escalation_can_only_be_decided_once(policy):
    kernel = Kernel(policy)
    waiting = kernel.check(Operation("fixture_writer", "prod.deploy", "prod/payments"))
    kernel.decide_escalation(waiting.escalation_id, True)
    import pytest

    with pytest.raises(ValueError, match="already approved"):
        kernel.decide_escalation(waiting.escalation_id, False)

