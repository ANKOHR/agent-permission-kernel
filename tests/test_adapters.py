from decimal import Decimal

from apk.adapters import SyntheticAdapters
from apk.kernel import Kernel
from apk.model import Operation


def test_allowed_fixture_operation_runs_only_in_memory(policy, tmp_path):
    kernel = Kernel(policy)
    adapters = SyntheticAdapters(policy, kernel.state)
    operation = Operation("fixture_writer", "fs.write", "/tmp/proof.txt")
    decision = kernel.check(operation)
    result = adapters.execute(operation, decision)
    assert decision.decision == "allow"
    assert result["adapter"] == "synthetic-filesystem"
    assert adapters.files["/tmp/proof.txt"].startswith("Synthetic fixture write")
    assert not (tmp_path / "tmp" / "proof.txt").exists()


def test_denied_operations_never_reach_adapter(policy):
    kernel = Kernel(policy)
    adapters = SyntheticAdapters(policy, kernel.state)
    operation = Operation("fixture_writer", "gmail.send", "recipient@example.test")
    decision = kernel.check(operation)
    assert adapters.execute(operation, decision) is None
    assert adapters.gmail_sent == []


def test_approved_deploy_is_recorded_in_synthetic_adapter(policy):
    kernel = Kernel(policy)
    adapters = SyntheticAdapters(policy, kernel.state)
    operation = Operation("fixture_writer", "prod.deploy", "prod/payments")
    waiting = kernel.check(operation)
    assert adapters.execute(operation, waiting) is None
    kernel.decide_escalation(waiting.escalation_id, True, "approved for fixture")
    retry = kernel.check(operation)
    result = adapters.execute(operation, retry)
    assert result["adapter"] == "synthetic-production-deploy"
    assert adapters.deployments == ["prod/payments"]

