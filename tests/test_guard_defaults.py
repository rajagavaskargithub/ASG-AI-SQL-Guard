import pytest
from src.asg.guard import check_sql, load_policy

POLICY = load_policy()

@pytest.mark.parametrize("sql", [
    "SELECT first_name, plan FROM customers LIMIT 5",
    "SELECT c.first_name FROM customers c LIMIT 5",
    "SELECT amount AS total FROM orders ORDER BY total LIMIT 5",
    "SELECT order_id AS x FROM orders ORDER BY x LIMIT 5",
    "SELECT * FROM orders LIMIT 3",
])
def test_listed_columns_are_allowed(sql):
    assert check_sql(sql, POLICY).decision == "allow", check_sql(sql, POLICY)

@pytest.mark.parametrize("sql", [
    "SELECT dob FROM customers LIMIT 5",          # unclassified column
    "SELECT hidden FROM orders LIMIT 5",
    "SELECT c.nope FROM customers c LIMIT 5",
    "SELECT foo AS foo FROM orders LIMIT 5",      # alias must not hide an unknown column
    "SELECT ssn AS ssn FROM customers LIMIT 5",   # alias must not hide a blocked column
    "SELECT x LIMIT 1",                           # column with no table
])
def test_unlisted_columns_are_denied(sql):
    assert check_sql(sql, POLICY).decision == "deny", check_sql(sql, POLICY)

def test_unknown_column_reason_mentions_default_deny():
    assert "default deny" in check_sql("SELECT dob FROM customers LIMIT 5", POLICY).reason
