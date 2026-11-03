import pytest
from fastapi.testclient import TestClient

from src.asg import seed
from src.asg.api import create_app
from src.asg.executor import ExecutionFailed
from src.asg.guard import AuditLog, Session, check_sql, load_policy, public_reason, review

POLICY = load_policy()
GENERIC = "query not permitted by policy"
LIMIT_MSG = f"a LIMIT of at most {POLICY['limits']['max_limit']} rows is required"

# Denied for many different internal reasons; the agent must not be able to tell them apart.
DENIED = [
    "SELECT ssn FROM customers LIMIT 5",                                       # blocked column
    "SELECT dob FROM customers LIMIT 5",                                       # unknown column
    "SELECT secret FROM hidden_table LIMIT 5",                                 # unknown table
    "SELECT version() LIMIT 1",                                                # not on allowlist
    "SELECT * FROM read_csv('/etc/passwd') LIMIT 1",                           # blocked function
    "SELECT plan FROM customers AS t(a, b, c, d, e, plan, g, h) LIMIT 5",      # alias list
    "SELECT #6 FROM customers LIMIT 5",                                        # positional
    "DROP TABLE orders",                                                       # statement type
    "SELECT * FROM customers LIMIT 5",                                         # star on tagged table
]


def pub(sql):
    return public_reason(check_sql(sql, POLICY), POLICY)


@pytest.mark.parametrize("sql", DENIED)
def test_denials_look_identical_to_the_agent(sql):
    assert pub(sql) == GENERIC


@pytest.mark.parametrize("sql", ["SELEC FROM", "SELECT 1; SELECT 2"])
def test_parse_failures_are_labelled_as_such(sql):
    assert pub(sql) == "query could not be parsed as a single statement"


def test_missing_limit_message_does_not_depend_on_the_query():
    msgs = {pub(q) for q in [
        "SELECT order_id FROM orders",
        "SELECT ssn FROM customers",
        "SELECT dob FROM customers",
        "SELECT * FROM nope",
        "SELECT version()",
    ]}
    assert msgs == {LIMIT_MSG}


def test_oversized_limit_message_does_not_depend_on_the_query():
    assert pub("SELECT ssn FROM customers LIMIT 99999") == LIMIT_MSG
    assert pub("SELECT order_id FROM orders LIMIT 99999") == LIMIT_MSG


def test_approval_message_names_no_columns():
    msg = pub("SELECT email FROM customers LIMIT 5")
    assert msg == "human approval required" and "email" not in msg


def test_allowed_message():
    assert pub("SELECT order_id FROM orders LIMIT 5") == "within policy"


def test_audit_keeps_the_specific_reason():
    audit, s = AuditLog(":memory:"), Session()
    d = review("SELECT ssn FROM customers LIMIT 5", POLICY, s, audit)
    assert "customers.ssn" in d.reason
    assert "customers.ssn" in audit.rows()[0][2]
    audit.close()


@pytest.fixture()
def env(tmp_path):
    db = tmp_path / "sandbox.duckdb"
    seed.build(str(db))
    app = create_app(audit_path=":memory:", sandbox_path=str(db))
    return app, TestClient(app)


def test_api_responses_leak_no_rule_details(env):
    app, c = env
    sqls = DENIED + ["SELECT email FROM customers LIMIT 5",
                     "SELECT order_id FROM orders LIMIT 3", "SELECT 1; SELECT 2"]
    text = " ".join(c.post("/query", json={"sql": q, "session_id": "p"}).text.lower()
                    for q in sqls)
    for word in ["ssn", "customers.", "allowlist", "default deny", "blocked",
                 "positional", "alias", "risk", "sensitive"]:
        assert word not in text, word


def test_api_execution_errors_are_coarse_but_audited_in_detail(env, monkeypatch):
    app, c = env

    def boom(*a, **k):
        raise ExecutionFailed("database error (BinderException)")

    monkeypatch.setattr("src.asg.api.execute_decision", boom)
    r = c.post("/query", json={"sql": "SELECT order_id FROM orders LIMIT 3", "session_id": "p"})
    assert r.status_code == 500
    assert r.json()["reason"] == "query could not be executed"
    assert "Binder" not in r.text
    assert "BinderException" in app.state.audit.execution_rows()[0][2]
