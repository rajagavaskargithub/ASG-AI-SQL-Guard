"""The eight presenter scenarios. 'expected' is what the policy should do;
the app compares it with what the guard actually decides."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Scenario:
    name: str
    sql: str
    expected: str  # allow | deny | approve


SCENARIOS = [
    Scenario("1. Safe query", "SELECT order_id, amount FROM orders LIMIT 3", "allow"),
    Scenario("2. Blocked sensitive column", "SELECT email, ssn FROM customers LIMIT 5", "deny"),
    Scenario("3. PII needs human approval", "SELECT email FROM customers LIMIT 5", "approve"),
    Scenario("4. Missing LIMIT", "SELECT order_id FROM orders", "deny"),
    Scenario("5. LIMIT above the maximum", "SELECT order_id FROM orders LIMIT 100000", "deny"),
    Scenario("6. Disallowed statement", "DROP TABLE orders", "deny"),
    Scenario("7. Multiple statements",
             "SELECT order_id FROM orders LIMIT 1; DROP TABLE orders", "deny"),
    Scenario("8. External file access",
             "SELECT * FROM read_csv('/etc/passwd') LIMIT 1", "deny"),
]
