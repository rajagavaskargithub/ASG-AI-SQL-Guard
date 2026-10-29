import pytest
from fastapi.testclient import TestClient
from src.asg import seed
from src.asg.api import create_app


@pytest.fixture(scope="module")
def app():
    seed.build()
    return create_app(audit_path=":memory:")

@pytest.fixture(scope="module")
def client(app):
    return TestClient(app)

def q(client, sql, session="t"):
    return client.post("/query", json={"sql": sql, "session_id": session})


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}

def test_allowed_query_returns_rows(client):
    r = q(client, "SELECT order_id, amount FROM orders LIMIT 3")
    assert r.status_code == 200
    assert r.json()["columns"] == ["order_id", "amount"]
    assert len(r.json()["rows"]) == 3

def test_ssn_is_blocked_and_no_data_returned(client):
    r = q(client, "SELECT ssn FROM customers LIMIT 5")
    assert r.status_code == 403
    assert "rows" not in r.json()

def test_pii_needs_approval_and_returns_nothing(client):
    r = q(client, "SELECT email FROM customers LIMIT 5")
    assert r.status_code == 202
    assert r.json()["status"] == "pending_approval"
    assert "rows" not in r.json()

def test_injected_exfiltration_is_blocked(client):
    # the planted note in customer 7 tells the agent to run this query
    r = q(client, "SELECT email, ssn FROM customers LIMIT 5")
    assert r.status_code == 403

def test_destructive_sql_is_blocked_and_table_survives(client):
    assert q(client, "DROP TABLE orders").status_code == 403
    assert q(client, "SELECT count(*) FROM orders LIMIT 1").status_code == 200

def test_session_budget_enforced_over_http(client):
    codes = [q(client, "SELECT order_id FROM orders LIMIT 1000", "budget").status_code
             for _ in range(6)]
    assert codes == [200] * 5 + [403]

def test_bad_request_body_rejected(client):
    assert client.post("/query", json={"nope": 1}).status_code == 422

def test_every_request_is_audited(client, app):
    decisions = [r[0] for r in app.state.audit.rows()]
    assert "allow" in decisions and "deny" in decisions and "approve" in decisions
