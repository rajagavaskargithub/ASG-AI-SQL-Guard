import copy

import pytest

from src.asg import seed
from src.asg.approvals import ApprovalError, ApprovalStore
from src.asg.executor import ExecutionFailed, ExecutionRefused, execute_approved
from src.asg.guard import check_sql, hash_sql, load_policy

POLICY = load_policy()
EMAIL_SQL = "SELECT email FROM customers LIMIT 5"
PHONE_SQL = "SELECT phone FROM customers LIMIT 5"


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


@pytest.fixture()
def sandbox(tmp_path):
    path = tmp_path / "sandbox.duckdb"
    seed.build(str(path))
    return path


@pytest.fixture()
def clock():
    return Clock()


@pytest.fixture()
def store(clock):
    s = ApprovalStore(":memory:", clock=clock)
    yield s
    s.close()


def submit(store, sql=EMAIL_SQL, session="s1", requester="agent"):
    d = check_sql(sql, POLICY)
    assert d.decision == "approve"
    return store.request(d, session, POLICY, requester)


def test_only_approve_decisions_can_be_submitted(store):
    for sql in ["SELECT order_id FROM orders LIMIT 3",      # allow
                "SELECT ssn FROM customers LIMIT 5"]:       # deny
        with pytest.raises(ApprovalError):
            store.request(check_sql(sql, POLICY), "s1", POLICY, "agent")


def test_pending_approval_cannot_execute(store, sandbox):
    aid = submit(store)
    with pytest.raises(ApprovalError, match="not approved"):
        store.execute(aid, "s1", POLICY, sandbox)


def test_approved_query_runs_once_and_returns_rows(store, sandbox):
    aid = submit(store)
    store.decide(aid, "alice", True)
    r = store.execute(aid, "s1", POLICY, sandbox)
    assert r.columns == ["email"] and len(r.rows) == 5
    with pytest.raises(ApprovalError, match="consumed"):     # single use
        store.execute(aid, "s1", POLICY, sandbox)


def test_rejected_approval_never_executes(store, sandbox):
    aid = submit(store)
    store.decide(aid, "alice", False)
    with pytest.raises(ApprovalError, match="rejected"):
        store.execute(aid, "s1", POLICY, sandbox)


def test_expired_before_decision(store, clock):
    aid = submit(store)
    clock.t += 901
    with pytest.raises(ApprovalError, match="expired"):
        store.decide(aid, "alice", True)
    assert store.pending() == []


def test_expired_after_approval(store, clock, sandbox):
    aid = submit(store)
    store.decide(aid, "alice", True)
    clock.t += 901
    with pytest.raises(ApprovalError, match="expired"):
        store.execute(aid, "s1", POLICY, sandbox)


def test_policy_change_invalidates_approval(store, sandbox):
    aid = submit(store)
    store.decide(aid, "alice", True)
    changed = copy.deepcopy(POLICY)
    changed["limits"]["max_limit"] = 500
    with pytest.raises(ApprovalError, match="policy changed"):
        store.execute(aid, "s1", changed, sandbox)


def test_approval_is_bound_to_its_session(store, sandbox):
    aid = submit(store, session="s1")
    store.decide(aid, "alice", True)
    with pytest.raises(ApprovalError, match="different session"):
        store.execute(aid, "other-session", POLICY, sandbox)


def test_requester_cannot_approve_own_request(store):
    aid = submit(store, requester="agent")
    with pytest.raises(ApprovalError, match="own request"):
        store.decide(aid, "agent", True)
    store.decide(aid, "agent", True, allow_self_approval=True)   # explicit demo override


def test_an_approval_cannot_run_different_sql(store, sandbox):
    a = submit(store, EMAIL_SQL)
    b = submit(store, PHONE_SQL)
    store.decide(a, "alice", True)
    store.decide(b, "alice", True)
    assert store.execute(a, "s1", POLICY, sandbox).columns == ["email"]
    assert store.execute(b, "s1", POLICY, sandbox).columns == ["phone"]


def test_tampered_stored_sql_is_refused(store, sandbox):
    aid = submit(store)
    store.decide(aid, "alice", True)
    store.con.execute("UPDATE approvals SET canonical_sql = ? WHERE approval_id = ?",
                      ["SELECT ssn FROM customers LIMIT 5", aid])
    with pytest.raises(ApprovalError, match="hash"):
        store.execute(aid, "s1", POLICY, sandbox)


def test_revalidation_refuses_hash_mismatch(sandbox):
    with pytest.raises(ExecutionRefused):
        execute_approved(EMAIL_SQL, "deadbeefdeadbeef", POLICY, sandbox)


def test_revalidation_refuses_query_the_policy_now_denies(sandbox):
    stricter = copy.deepcopy(POLICY)
    stricter["columns"]["customers.email"]["action"] = "deny"
    with pytest.raises(ExecutionRefused):
        execute_approved(EMAIL_SQL, hash_sql(EMAIL_SQL), stricter, sandbox)


def test_revalidation_refuses_unapproved_sql_classes(sandbox):
    sql = "SELECT order_id FROM orders LIMIT 3"      # an 'allow' query is not an approval case
    with pytest.raises(ExecutionRefused):
        execute_approved(sql, hash_sql(sql), POLICY, sandbox)


def test_every_step_is_recorded_in_order(store, sandbox):
    aid = submit(store)
    store.decide(aid, "alice", True)
    store.execute(aid, "s1", POLICY, sandbox)
    assert [e[0] for e in store.events(aid)] == ["requested", "approved", "consumed", "executed"]


def test_failed_execution_is_recorded_and_not_retryable(store, tmp_path):
    aid = submit(store)
    store.decide(aid, "alice", True)
    missing = tmp_path / "does_not_exist.duckdb"
    with pytest.raises(ExecutionFailed):
        store.execute(aid, "s1", POLICY, missing)
    names = [e[0] for e in store.events(aid)]
    assert names[-2:] == ["consumed", "execution_failed"]
    with pytest.raises(ApprovalError, match="consumed"):
        store.execute(aid, "s1", POLICY, missing)


def test_refusals_are_recorded(store, sandbox):
    aid = submit(store)
    with pytest.raises(ApprovalError):
        store.execute(aid, "s1", POLICY, sandbox)
    assert "execution_refused" in [e[0] for e in store.events(aid)]
