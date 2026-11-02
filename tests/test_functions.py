import pytest
from src.asg.guard import check_sql, load_policy

POLICY = load_policy()

# Found by the batch-2 red team (information disclosure), plus close relatives.
UNLISTED_FUNCTIONS = [
    "SELECT version() LIMIT 1",
    "SELECT current_setting('home_directory') LIMIT 1",
    "SELECT current_database() LIMIT 1",
    "SELECT pg_typeof(1) LIMIT 1",
]

ORDINARY_ANALYTICS = [
    "SELECT round(amount, 2) AS a FROM orders LIMIT 5",
    "SELECT coalesce(plan, 'none') FROM customers LIMIT 5",
    "SELECT upper(plan), lower(first_name) FROM customers LIMIT 5",
    "SELECT length(first_name) FROM customers LIMIT 5",
    "SELECT CAST(amount AS INTEGER) FROM orders LIMIT 5",
    "SELECT EXTRACT(year FROM order_date) AS y, count(*) FROM orders GROUP BY y LIMIT 5",
    "SELECT plan, avg(amount) FROM customers c JOIN orders o ON o.customer_id = c.customer_id GROUP BY plan LIMIT 5",
    "SELECT customer_id, rank() OVER (ORDER BY amount DESC) FROM orders LIMIT 5",
    "SELECT median(amount), max(amount) FROM orders LIMIT 1",
]

# UNION is denied by statement type. The first query is type-compatible, so it
# would really leak if unions were ever allowed without per-branch checks.
UNIONS = [
    "SELECT first_name FROM customers UNION ALL SELECT ssn FROM customers LIMIT 5",
    "SELECT first_name FROM customers UNION ALL SELECT first_name FROM customers LIMIT 5",
]


@pytest.mark.parametrize("sql", UNLISTED_FUNCTIONS)
def test_unlisted_functions_are_denied(sql):
    assert check_sql(sql, POLICY).decision == "deny", check_sql(sql, POLICY)


@pytest.mark.parametrize("sql", ORDINARY_ANALYTICS)
def test_ordinary_analytics_still_allowed(sql):
    d = check_sql(sql, POLICY)
    assert d.decision == "allow", d


@pytest.mark.parametrize("sql", UNIONS)
def test_unions_are_denied(sql):
    assert check_sql(sql, POLICY).decision == "deny"
