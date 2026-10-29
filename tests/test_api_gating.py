import pytest
from fastapi.testclient import TestClient

from src.asg import seed
from src.asg.api import create_app
from src.asg.executor import ExecResult, ExecutionFailed


@pytest.fixture()
def env(tmp_path):
    db = tmp_path / "sandbox.duckdb"
    seed.build(str(db))
    app = create_app(audit_path=":memory:", sandbox_path=str(db))
    return app, TestClient(app)


def post(client, sql):
    return client.post("/query", json={"sql": sql, "session_id": "g"})


def test_deny_and_approve_never_reach_the_executor(env, monkeypatch):
    app, client = env
    calls = []

    def spy(*a, **k):
        calls.append(a)
        raise AssertionError("executor must not be called")

    monkeypatch.setattr("src.asg.api.execute_decision", spy)
    rs = [post(client, "SELECT ssn FROM customers LIMIT 5"),
          post(client, "SELECT email FROM customers LIMIT 5"),
          post(client, "DROP TABLE orders")]
    assert [r.status_code for r in rs] == [403, 202, 403]
    assert calls == []
    assert all(r.json()["executed"] is False for r in rs)


def test_allowed_query_runs_exactly_the_canonical_sql(env, monkeypatch):
    app, client = env
    seen = []

    def spy(decision, *a, **k):
        seen.append(decision.canonical_sql)
        return ExecResult(["order_id"], [(1,)])

    monkeypatch.setattr("src.asg.api.execute_decision", spy)
    r = post(client, "select   order_id from orders limit 3")
    assert r.status_code == 200 and r.json()["executed"] is True
    assert seen == ["SELECT order_id FROM orders LIMIT 3"]
    assert [x[0] for x in app.state.audit.execution_rows()] == ["succeeded"]


def test_execution_failure_is_reported_and_logged(env, monkeypatch):
    app, client = env

    def boom(*a, **k):
        raise ExecutionFailed("query exceeded the time limit")

    monkeypatch.setattr("src.asg.api.execute_decision", boom)
    r = post(client, "SELECT order_id FROM orders LIMIT 3")
    assert r.status_code == 500 and r.json()["executed"] is False
    assert [x[0] for x in app.state.audit.execution_rows()] == ["failed"]


def test_audit_failure_blocks_execution(env, monkeypatch):
    app, client = env
    calls = []
    monkeypatch.setattr("src.asg.api.execute_decision", lambda *a, **k: calls.append(1))

    def broken(*a, **k):
        raise RuntimeError("disk full")

    monkeypatch.setattr("src.asg.api.review", broken)
    r = post(client, "SELECT order_id FROM orders LIMIT 3")
    assert r.status_code == 500 and calls == []
