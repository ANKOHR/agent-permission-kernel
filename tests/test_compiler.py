import pytest

from apk.compiler import PolicyError, compile_policy


def document(capabilities):
    return {"version": 1, "agents": {"agent-a": {"capabilities": capabilities}}}


def test_valid_policy_compiles_typed_scoped_and_spend_grants():
    policy = compile_policy(document(["gmail.draft", "fs.write:/tmp", "spend.cap:$5"]))
    agent = policy.agent("agent-a")
    assert agent is not None
    assert agent.has("gmail.draft")
    assert agent.scopes("fs.write") == ("/tmp",)
    assert str(agent.spend_cap) == "5"
    assert len(policy.digest) == 64


def test_unknown_capability_has_named_error():
    with pytest.raises(PolicyError) as exc:
        compile_policy(document(["gmail.admin"]))
    assert exc.value.code == "unknown-capability"
    assert "gmail.admin" in exc.value.message


@pytest.mark.parametrize(
    "scope",
    ["/", "relative/path", "/data/../etc", "/data/./private", "/data//private", "/data/", "//server/share"],
)
def test_over_broad_or_noncanonical_scope_has_named_error(scope):
    with pytest.raises(PolicyError) as exc:
        compile_policy(document([f"fs.read:{scope}"]))
    assert exc.value.code == "over-broad-scope"


@pytest.mark.parametrize(
    "capabilities",
    [
        ["gmail.draft", "gmail.draft"],
        ["spend.cap:$5", "spend.cap:$8"],
    ],
)
def test_conflicting_grants_have_named_error(capabilities):
    with pytest.raises(PolicyError) as exc:
        compile_policy(document(capabilities))
    assert exc.value.code == "conflicting-grants"


def test_same_spend_cap_written_with_equivalent_decimal_is_a_conflict():
    with pytest.raises(PolicyError) as exc:
        compile_policy(document(["spend.cap:$5", "spend.cap:$5.00"]))
    assert exc.value.code == "conflicting-grants"
