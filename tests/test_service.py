import pytest

from src.asg import seed
from src.asg.approvals import ApprovalError
from src.asg.executor import ExecutionFailed
from src.asg.guard import check_sql, load_policy
from src.asg.scenarios import SCENARIOS
from src.asg.service import AsgService, PolicyMismatch, triggered_policy

POLICY = load_policy()
ALLOWED = "SELECT order_id, amount FROM orders LIMIT 3"


@pytest.fixture()
def svc(tmp_path):
    db = tmp_path / "sandbox.duckdb"
    seed.build(str(db))
    s = AsgService(sandbox_path=db, audit_path=":memory:", approvals_path=":memory:")
    yield s
    s.close()


def test_every_scenario_behaves_as_expected(svc):
    rows = svc.run_scenarios("t")
    assert len(rows) == 8
    assert all(r["match"] for r in rows), rows


def test_only_the_allowed_scenario_executes(svc):
    rows = svc.run_scenarios("t")
    assert [r["executed"] for r in rows] == [True] + [False] * 7


def test_metrics_use_truthful_counting_rules(svc):
    svc.run_scenarios("t")
    m = svc.metrics()
    assert (m["reviewed"], m["allow"], m["deny"], m["approve"]) == (8, 1, 6, 1)
    assert (m["executed"], m["failed"]) == (1, 0)
    assert m["approvals_requested"] == 1 and m["approvals_approved"] == 0


def test_deny_and_approve_never_reach_the_executor(svc, monkeypatch):
    def spy(*a, **k):
        raise AssertionError("executor must not run")

    monkeypatch.setattr("src.asg.service.execute_decision", spy)
    for sc in SCENARIOS[1:]:
        o = svc.submit(sc.sql, "t")
        assert o.executed is False and o.rows is None


def test_allowed_query_returns_rows_and_logs_execution(svc):
    o = svc.submit(ALLOWED, "t")
    assert o.executed and len(o.rows) == 3 and o.audit_written and o.execution_logged
    assert svc.audit.execution_records()[0][3] == "succeeded"


def test_audit_failure_fails_closed(svc, monkeypatch):
    calls = []
    monkeypatch.setattr("src.asg.service.execute_decision", lambda *a, **k: calls.append(1))

    def boom(*a, **k):
        raise RuntimeError("disk full")

    monkeypatch.setattr(svc.audit, "record", boom)
    o = svc.submit(ALLOWED, "t")
    assert o.decision.decision == "deny" and not o.executed and not o.audit_written
    assert o.error and calls == []


def test_execution_failure_is_reported_and_counted(svc, monkeypatch):
    def boom(*a, **k):
        raise ExecutionFailed("query exceeded the time limit")

    monkeypatch.setattr("src.asg.service.execute_decision", boom)
    o = svc.submit(ALLOWED, "t")
    assert not o.executed and "time limit" in o.error
    assert svc.metrics()["failed"] == 1 and svc.metrics()["executed"] == 0


def test_full_approval_path_through_the_service(svc):
    o = svc.submit("SELECT email FROM customers LIMIT 5", "t")
    assert o.approval_id and not o.executed
    assert len(svc.approvals.list_by_status("pending", "t")) == 1
    svc.decide(o.approval_id, "reviewer", True)
    res = svc.run_approved(o.approval_id, "t")
    assert res.columns == ["email"] and len(res.rows) == 5
    with pytest.raises(ApprovalError):                      # single use
        svc.run_approved(o.approval_id, "t")
    m = svc.metrics()
    assert m["approvals_executed"] == 1 and m["executed"] == 1


def test_approvals_are_listed_per_session(svc):
    svc.submit("SELECT email FROM customers LIMIT 5", "alice")
    assert svc.approvals.list_by_status("pending", "bob") == []


def test_unapproved_request_cannot_run(svc):
    o = svc.submit("SELECT email FROM customers LIMIT 5", "t")
    with pytest.raises(ApprovalError):
        svc.run_approved(o.approval_id, "t")
    assert svc.metrics()["executed"] == 0


def test_startup_refuses_policy_schema_drift(tmp_path):
    import duckdb
    db = tmp_path / "drift.duckdb"
    seed.build(str(db))
    w = duckdb.connect(str(db))
    w.execute("ALTER TABLE customers ADD COLUMN dob VARCHAR")
    w.close()
    with pytest.raises(PolicyMismatch, match="dob"):
        AsgService(sandbox_path=db, audit_path=":memory:", approvals_path=":memory:")


@pytest.mark.parametrize("sql,expected", [
    ("SELECT ssn FROM customers LIMIT 5", "columns.customers.ssn"),
    ("SELECT email FROM customers LIMIT 5", "columns.customers.email"),
    ("DROP TABLE orders", "allowed_statements"),
    ("SELECT order_id FROM orders", "limits"),
    ("SELECT dob FROM customers LIMIT 5", "default deny"),
    ("SELECT * FROM secrets LIMIT 1", "tables"),
    ("SELECT 1; SELECT 2", "parser"),
    (ALLOWED, "none"),
])
def test_triggered_policy_names_the_rule(sql, expected):
    assert expected in triggered_policy(check_sql(sql, POLICY))
