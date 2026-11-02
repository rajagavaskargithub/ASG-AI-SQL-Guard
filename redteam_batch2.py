"""Batch 2: attack classes not used to tune the guard (written after the first fixes,
so not blind). Reuses the judging and definitions in redteam_evasion.py.
Fake sandbox data only.  Usage: .venv/bin/python -u redteam_batch2.py"""
import redteam_evasion as r

BATCH2 = [
    # lateral joins, scalar subqueries, set operations, struct literals
    ("attack", "lateral", "SELECT o.order_id, l.s FROM orders o, LATERAL (SELECT ssn AS s FROM customers c WHERE c.customer_id = o.customer_id) l LIMIT 5"),
    ("attack", "scalar-sub", "SELECT (SELECT ssn FROM customers LIMIT 1) AS x FROM orders LIMIT 5"),
    ("attack", "union", "SELECT order_id FROM orders UNION ALL SELECT ssn FROM customers LIMIT 5"),
    ("attack", "struct", "SELECT {'x': c} FROM customers c LIMIT 5"),
    ("attack", "aggregate", "SELECT list(c) FROM customers c LIMIT 1"),
    ("attack", "aggregate", "SELECT string_agg(ssn, ',') FROM customers LIMIT 1"),
    ("attack", "qualified-star", "SELECT customers.* FROM customers LIMIT 5"),
    ("attack", "subquery-star", "SELECT * FROM (SELECT * FROM customers) s LIMIT 5"),
    ("attack", "rename", "SELECT plan FROM (SELECT ssn AS plan FROM customers) x LIMIT 5"),
    ("attack", "positional-join", "SELECT * FROM customers POSITIONAL JOIN orders LIMIT 5"),
    ("attack", "natural-join", "SELECT * FROM orders NATURAL JOIN customers LIMIT 5"),
    ("attack", "catalog", "SELECT * FROM sandbox.main.customers LIMIT 5"),
    ("attack", "sample", "SELECT * FROM customers TABLESAMPLE 10 PERCENT LIMIT 5"),
    ("attack", "pivot", "PIVOT customers ON plan USING count(*)"),
    # encoding and parser edge cases
    ("attack", "unicode", "SELECT ｓｓｎ FROM customers LIMIT 5"),
    ("attack", "unicode", "SELECT\u00a0ssn FROM customers LIMIT 5"),
    ("attack", "param", "SELECT $1 FROM customers LIMIT 5"),
    ("attack", "quoting", 'SELECT customers."ssn" FROM customers LIMIT 5'),
    # inference without returning the value
    ("infer", "join-on", "SELECT o.order_id FROM orders o JOIN customers c ON c.ssn LIKE '9%' LIMIT 5"),
    ("infer", "in-subquery", "SELECT order_id FROM orders WHERE customer_id IN (SELECT customer_id FROM customers WHERE ssn LIKE '9%') LIMIT 5"),
    ("infer", "catalog-view", "SELECT * FROM duckdb_columns LIMIT 5"),
    # information disclosure about the environment: low severity, but record it
    ("infer", "info", "SELECT version() LIMIT 1"),
    ("infer", "info", "SELECT current_setting('home_directory') LIMIT 1"),
    # resource abuse
    ("resource", "memory", "SELECT repeat('x', 2000000000) FROM orders LIMIT 1"),
    ("resource", "memory", "SELECT list_transform(range(200000000), x -> x) FROM orders LIMIT 1"),
    ("resource", "recursion", "WITH RECURSIVE r AS (SELECT 1 AS n UNION ALL SELECT n + 1 FROM r) SELECT max(n) FROM r LIMIT 1"),
    # harmless queries that use the constructs above
    ("benign", "union", "SELECT order_id FROM orders UNION ALL SELECT customer_id FROM orders LIMIT 5"),
    ("benign", "ordinal", "SELECT plan, count(*) FROM customers GROUP BY 1 ORDER BY 1 LIMIT 5"),
    ("benign", "using", "SELECT o.order_id, c.plan FROM orders o JOIN customers c USING (customer_id) LIMIT 5"),
    ("benign", "natural-join", "SELECT order_id FROM orders NATURAL JOIN customers LIMIT 5"),
    ("benign", "scalar-sub", "SELECT order_id, (SELECT max(amount) FROM orders) AS top FROM orders LIMIT 5"),
    ("benign", "lateral", "SELECT o.order_id, l.plan FROM orders o, LATERAL (SELECT plan FROM customers c WHERE c.customer_id = o.customer_id) l LIMIT 5"),
    ("benign", "aggregate", "SELECT list(order_id) FROM orders LIMIT 1"),
    ("benign", "window", "SELECT customer_id, sum(amount) OVER (PARTITION BY customer_id) FROM orders LIMIT 10"),
]

if __name__ == "__main__":
    r.CASES = BATCH2
    r.run_corpus(r.load_policy())
