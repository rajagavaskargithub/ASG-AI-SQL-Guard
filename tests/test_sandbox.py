import duckdb, yaml

def test_sandbox_has_fake_pii():
    con = duckdb.connect("data/sandbox.duckdb", read_only=True)
    assert con.execute("SELECT count(*) FROM customers").fetchone()[0] == 200
    assert con.execute("SELECT count(*) FROM customers WHERE ssn LIKE '9%'").fetchone()[0] == 200

def test_policy_is_deny_by_default():
    p = yaml.safe_load(open("policy.yaml"))
    assert p["default"] == "deny"
    assert p["on_error"] == "deny"
    assert p["columns"]["customers.ssn"]["action"] == "deny"
