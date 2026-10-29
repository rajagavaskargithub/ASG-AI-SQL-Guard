from dataclasses import replace

import duckdb
import pytest

from src.asg import seed
from src.asg.executor import (ExecutionFailed, ExecutionRefused, _run,
                              execute_decision, open_sandbox)
from src.asg.guard import (Decision, check_sql, hash_sql, load_policy,
                           validate_policy_against_schema)

POLICY = load_policy()


@pytest.fixture(scope="module")
def sandbox(tmp_path_factory):
    path = tmp_path_factory.mktemp("db") / "sandbox.duckdb"   # isolated temp DB
    seed.build(str(path))
    return path


def test_allow_executes_the_evaluated_sql(sandbox):
    d = check_sql("SELECT order_id, amount FROM orders LIMIT 3", POLICY)
    r = execute_decision(d, POLICY, sandbox)
    assert r.columns == ["order_id", "amount"] and len(r.rows) == 3


@pytest.mark.parametrize("sql", [
    "SELECT ssn FROM customers LIMIT 5",         # deny
    "DROP TABLE orders",                          # deny
    "SELECT email FROM customers LIMIT 5",       # approve
])
def test_deny_and_approve_never_execute(sandbox, sql):
    d = check_sql(sql, POLICY)
    assert d.decision in ("deny", "approve")
    with pytest.raises(ExecutionRefused):
        execute_decision(d, POLICY, sandbox)


def test_tampered_sql_is_refused(sandbox):
    d = check_sql("SELECT order_id FROM orders LIMIT 3", POLICY)
    evil = replace(d, canonical_sql="SELECT ssn FROM customers LIMIT 5")
    with pytest.raises(ExecutionRefused):
        execute_decision(evil, POLICY, sandbox)


def test_forged_allow_decision_is_refused_by_revalidation(sandbox):
    sql = "SELECT ssn FROM customers LIMIT 5"
    forged = Decision("allow", "forged", 0, hash_sql(sql), canonical_sql=sql)
    with pytest.raises(ExecutionRefused):
        execute_decision(forged, POLICY, sandbox)


@pytest.mark.parametrize("sql", [
    "SELECT order_id, amount FROM orders LIMIT 3",
    "select   order_id  from orders limit 5 -- ; DROP TABLE orders",
    "SELECT o.order_id, c.plan FROM orders o JOIN customers c "
    "ON o.customer_id = c.customer_id LIMIT 10",
])
def test_canonical_sql_is_stable_and_reallowed(sql):
    d = check_sql(sql, POLICY)
    assert d.decision == "allow"
    assert "--" not in d.canonical_sql and "/*" not in d.canonical_sql
    again = check_sql(d.canonical_sql, POLICY)
    assert again.decision == "allow" and again.canonical_sql == d.canonical_sql


@pytest.mark.parametrize("stmt", [
    "SELECT * FROM read_csv('/etc/passwd')",
    "COPY orders TO '/tmp/asg_leak.csv'",
    "DROP TABLE orders",
    "DELETE FROM orders",
    "INSERT INTO orders VALUES (1, 1, 1.0, DATE '2026-01-01')",
])
def test_database_layer_blocks_even_without_the_guard(sandbox, stmt):
    con = open_sandbox(sandbox)
    try:
        with pytest.raises(duckdb.Error):
            con.execute(stmt)
    finally:
        con.close()


def test_database_layer_cannot_attach_other_databases(sandbox, tmp_path):
    other = tmp_path / "other.duckdb"
    duckdb.connect(str(other)).close()
    con = open_sandbox(sandbox)
    try:
        with pytest.raises(duckdb.Error):
            con.execute(f"ATTACH '{other}' AS other")
    finally:
        con.close()


def test_row_cap(sandbox):
    r = _run(open_sandbox(sandbox), "SELECT * FROM range(5000)", 100, 5.0)
    assert len(r.rows) == 100


def test_timeout_interrupts_runaway_query(sandbox):
    slow = "SELECT sum(a.range * b.range) FROM range(1000000) a, range(1000000) b"
    with pytest.raises(ExecutionFailed, match="time limit"):
        _run(open_sandbox(sandbox), slow, 10, 1.0)


def test_errors_are_safe_to_show(sandbox):
    with pytest.raises(ExecutionFailed) as e:
        _run(open_sandbox(sandbox), "SELECT nope FROM orders", 10, 5.0)
    assert "nope" not in str(e.value) and "Traceback" not in str(e.value)


def test_policy_matches_schema(sandbox):
    con = open_sandbox(sandbox)
    try:
        assert validate_policy_against_schema(POLICY, con) == []
    finally:
        con.close()


def test_schema_drift_is_detected(tmp_path):
    path = tmp_path / "drift.duckdb"
    seed.build(str(path))
    w = duckdb.connect(str(path))
    w.execute("ALTER TABLE customers ADD COLUMN dob VARCHAR")
    w.close()
    con = open_sandbox(path)
    try:
        problems = validate_policy_against_schema(POLICY, con)
    finally:
        con.close()
    assert any("customers.dob" in p for p in problems)
