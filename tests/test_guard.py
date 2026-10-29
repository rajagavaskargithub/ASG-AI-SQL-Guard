import pytest
from src.asg.guard import AuditLog, Session, check_sql, load_policy, review

POLICY = load_policy()

def decide(sql, session=None):
    return check_sql(sql, POLICY, session).decision

ALLOW = [
    "SELECT order_id, amount FROM orders LIMIT 10",
    "SELECT count(*) FROM orders LIMIT 1",
    "SELECT o.order_id, c.plan FROM orders o JOIN customers c "
    "ON o.customer_id = c.customer_id LIMIT 10",
    "SELECT order_id FROM orders LIMIT 5 -- ; DROP TABLE orders",
]

APPROVE = [
    "SELECT email FROM customers LIMIT 5",
    "SELECT c.phone FROM customers c LIMIT 5",
]

DENY = [
    # sensitive column, direct and disguised
    "SELECT ssn FROM customers LIMIT 5",
    "SELECT c.ssn FROM customers AS c LIMIT 5",
    "SELECT SSN FROM customers LIMIT 5",
    "SELECT * FROM customers LIMIT 5",
    "SELECT c.* FROM customers c LIMIT 5",
    "SELECT c FROM customers c LIMIT 5",
    "SELECT customers FROM customers LIMIT 5",
    "WITH x AS (SELECT ssn FROM customers) SELECT * FROM x LIMIT 5",
    "SELECT v FROM (SELECT ssn AS v FROM customers) LIMIT 5",
    # inference through filtering
    "SELECT o.order_id FROM orders o JOIN customers c "
    "ON o.customer_id = c.customer_id WHERE c.ssn LIKE '9%' LIMIT 5",
    # wrong statement types
    "DROP TABLE orders",
    "DELETE FROM orders",
    "UPDATE orders SET amount = 0",
    "INSERT INTO orders VALUES (1, 1, 1.0, DATE '2026-01-01')",
    "COPY customers TO '/tmp/out.csv'",
    "SELECT 1; DROP TABLE orders",
    # files, catalog, unknown tables
    "SELECT * FROM read_csv('/etc/passwd') LIMIT 1",
    "SELECT * FROM information_schema.tables LIMIT 1",
    "SELECT * FROM secrets LIMIT 1",
    # limits
    "SELECT order_id FROM orders",
    "SELECT order_id FROM orders LIMIT 100000",
    # junk
    "", "SELEC FROM", "not sql at all",
]

@pytest.mark.parametrize("sql", ALLOW)
def test_allow(sql):
    assert decide(sql) == "allow", check_sql(sql, POLICY)

@pytest.mark.parametrize("sql", APPROVE)
def test_approve(sql):
    assert decide(sql) == "approve", check_sql(sql, POLICY)

@pytest.mark.parametrize("sql", DENY)
def test_deny(sql):
    assert decide(sql) == "deny", check_sql(sql, POLICY)

def test_session_row_budget():
    s = Session()
    q = "SELECT order_id FROM orders LIMIT 1000"
    results = [check_sql(q, POLICY, s).decision for _ in range(6)]
    assert results == ["allow"] * 5 + ["deny"]

def test_fails_closed_on_broken_policy():
    d = check_sql("SELECT 1 LIMIT 1", {"allowed_statements": ["select"]})
    assert d.decision == "deny" and "fail closed" in d.reason

def test_same_query_same_hash():
    a = check_sql("SELECT order_id FROM orders LIMIT 5", POLICY)
    b = check_sql("select   order_id  from orders limit 5", POLICY)
    assert a.sql_hash == b.sql_hash

def test_audit_log_records_every_decision():
    audit, s = AuditLog(":memory:"), Session()
    review("SELECT order_id FROM orders LIMIT 5", POLICY, s, audit)
    review("SELECT ssn FROM customers LIMIT 5", POLICY, s, audit)
    rows = audit.rows()
    assert [r[0] for r in rows] == ["allow", "deny"]
    audit.close()
