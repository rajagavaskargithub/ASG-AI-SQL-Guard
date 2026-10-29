"""Deterministic mock SQL generation for the ASG customer demo."""

SCENARIOS = {
    "Top orders": "SELECT order_id, amount FROM orders LIMIT 3",
    "Sensitive customer data": "SELECT email, ssn FROM customers LIMIT 5",
    "Customer emails": "SELECT email FROM customers LIMIT 5",
    "All order columns": "SELECT * FROM orders LIMIT 3",
}


def generate_sql(scenario: str) -> str:
    """Return predefined SQL for a supported demo scenario."""
    if scenario not in SCENARIOS:
        raise ValueError(f"Unknown demo scenario: {scenario}")
    return SCENARIOS[scenario]
