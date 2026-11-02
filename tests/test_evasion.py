import pytest
from src.asg.guard import check_sql, load_policy

POLICY = load_policy()

BYPASSES_FOUND_BY_RED_TEAM = [
    "SELECT plan FROM customers AS t(a1, a2, a3, a4, a5, plan, a7, a8) LIMIT 5",
    "SELECT first_name FROM customers AS t(a1, a2, a3, first_name, a5, a6, a7, a8) LIMIT 5",
    "SELECT #6 FROM customers LIMIT 5",
    "SELECT email FROM customers AS t(a, b, c, d, e, email, g, h) LIMIT 5",
    "SELECT t.plan FROM customers AS t(a, b, c, d, e, plan, g, h) LIMIT 5",
    "SELECT #1, #6 FROM customers LIMIT 5",
]

# Accepted false blocks: harmless, but the same construct enables the bypass.
KNOWN_FALSE_BLOCKS = [
    "SELECT order_id FROM orders AS o(x, y, z, w) LIMIT 5",
    "WITH x(a, b) AS (SELECT order_id, amount FROM orders) SELECT a FROM x LIMIT 5",
]

STILL_ALLOWED = [
    "SELECT order_id AS x FROM orders ORDER BY x LIMIT 5",
    "SELECT c.plan, sum(o.amount) AS revenue FROM customers c JOIN orders o "
    "ON o.customer_id = c.customer_id GROUP BY c.plan LIMIT 10",
    "SELECT order_id FROM orders WHERE 'a#1' = 'a#1' LIMIT 5",
    "SELECT plan AS segment, count(*) FROM customers GROUP BY segment LIMIT 5",
]


@pytest.mark.parametrize("sql", BYPASSES_FOUND_BY_RED_TEAM)
def test_red_team_bypasses_are_denied(sql):
    assert check_sql(sql, POLICY).decision == "deny", check_sql(sql, POLICY)


@pytest.mark.parametrize("sql", KNOWN_FALSE_BLOCKS)
def test_documented_false_blocks(sql):
    assert check_sql(sql, POLICY).decision == "deny"


@pytest.mark.parametrize("sql", STILL_ALLOWED)
def test_normal_queries_still_allowed(sql):
    assert check_sql(sql, POLICY).decision == "allow", check_sql(sql, POLICY)
