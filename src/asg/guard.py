"""AI-ASG guard core: parse SQL, apply policy, decide allow / approve / deny.
Deterministic code only. No LLM is involved in the decision."""
from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from pathlib import Path

import duckdb
import sqlglot
import yaml
from sqlglot import exp

ROOT = Path(__file__).resolve().parents[2]

# Compared after removing underscores and lowercasing
BLOCKED_FUNCS = {
    "readcsv", "readcsvauto", "readjson", "readjsonauto", "readparquet",
    "readtext", "readblob", "glob", "getenv", "query", "querytable",
    "duckdbsecrets", "columns",
}


def load_policy(path: Path = ROOT / "policy.yaml") -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


@dataclass
class Session:
    session_id: str = "s-1"
    rows_used: int = 0
    pii_columns: set = field(default_factory=set)


@dataclass
class Decision:
    decision: str            # "allow" | "approve" | "deny"
    reason: str
    risk: int = 0
    sql_hash: str = ""
    tables: list = field(default_factory=list)
    columns: list = field(default_factory=list)
    canonical_sql: str = ""  # the exact string that was evaluated; only this may execute


def hash_sql(sql: str) -> str:
    return hashlib.sha256(sql.encode()).hexdigest()[:16]


_hash = hash_sql


def _deny(reason, h, tables=(), columns=()) -> Decision:
    return Decision("deny", reason, 100, h, sorted(tables), sorted(columns))


def check_sql(sql: str, policy: dict, session: Session | None = None) -> Decision:
    session = session or Session()
    try:
        return _check(sql, policy, session)
    except Exception as e:  # fail closed on ANY error
        return Decision("deny", f"guard error (fail closed): {type(e).__name__}",
                        100, _hash(str(sql)))


def _check(sql: str, policy: dict, session: Session) -> Decision:
    h = _hash(sql)

    # 1. Parse: exactly one statement
    try:
        parsed = sqlglot.parse(sql, read="duckdb")
    except sqlglot.errors.SqlglotError:
        return _deny("unparseable SQL", h)
    statements = [s for s in parsed if s is not None]
    if len(statements) != 1:
        return _deny("exactly one statement is allowed", h)
    stmt = statements[0]
    canonical = stmt.sql(dialect="duckdb", comments=False)
    h = _hash(canonical)

    # 2. Statement type
    allowed = {s.lower() for s in policy.get("allowed_statements", [])}
    kind = type(stmt).__name__.lower()
    if kind not in allowed:
        return _deny(f"statement type '{kind}' is not allowed", h)

    # 3. Blocked functions and parameters
    for f in stmt.find_all(exp.Func):
        names = {f.key}
        if isinstance(f, exp.Anonymous):
            names.add(str(f.this))
        if any(n.lower().replace("_", "") in BLOCKED_FUNCS for n in names):
            return _deny(f"function {sorted(names)} is blocked", h)
    if stmt.find(exp.Placeholder) or stmt.find(exp.Parameter):
        return _deny("query parameters are not allowed", h)

    # 4. Tables
    cte_names = {c.alias.lower() for c in stmt.find_all(exp.CTE)}
    alias_to_table: dict[str, str] = {}
    for t in stmt.find_all(exp.Table):
        name = t.name.lower()
        if not name:
            return _deny("table functions / unnamed sources are not allowed", h)
        if name in cte_names and not t.args.get("db"):
            continue
        if t.args.get("db") or t.args.get("catalog"):
            return _deny("schema-qualified tables are not allowed", h)
        rule = policy.get("tables", {}).get(name)
        if not rule or not rule.get("allowed"):
            return _deny(f"table '{name}' is not allowed", h, tables=[name])
        alias_to_table[(t.alias or t.name).lower()] = name
    real = sorted(set(alias_to_table.values()))

    # 5. Columns: default deny. A column must be tagged or explicitly listed.
    col_rules = {k.lower(): v for k, v in policy.get("columns", {}).items()}
    tagged: dict[str, list[str]] = {}
    for key in col_rules:
        t, c = key.split(".")
        tagged.setdefault(t, []).append(c)
    known: dict[str, set[str]] = {}
    for tname, trule in policy.get("tables", {}).items():
        tn = tname.lower()
        known[tn] = {c.lower() for c in (trule.get("columns") or [])} | set(tagged.get(tn, []))
    aliases = {a.alias.lower() for a in stmt.find_all(exp.Alias)}

    def whole_table(t: str) -> set:
        return {f"{t}.{c}" for c in tagged.get(t, [])}

    def inside_alias(node, name: str) -> bool:
        p = node.parent
        while p is not None:
            if isinstance(p, exp.Alias) and p.alias.lower() == name:
                return True
            p = p.parent
        return False

    touched: set[str] = set()
    for node in stmt.find_all(exp.Column):
        qual = node.table.lower()
        targets = [alias_to_table[qual]] if qual in alias_to_table else real
        if isinstance(node.this, exp.Star):                    # c.*
            for t in targets:
                touched |= whole_table(t)
            continue
        col = node.name.lower()
        if not qual and col in alias_to_table:                 # SELECT c FROM customers c
            touched |= whole_table(alias_to_table[col])
            continue
        hit = False
        for t in targets:
            key = f"{t}.{col}"
            if key in col_rules:
                touched.add(key)
                hit = True
        if hit or any(col in known.get(t, set()) for t in targets):
            continue
        # Output aliases (ORDER BY total) are fine, but "SELECT foo AS foo" is not
        if col in aliases and not inside_alias(node, col):
            continue
        return _deny(f"column '{col}' is not in the policy (default deny)",
                     h, real, touched)
    for star in stmt.find_all(exp.Star):                       # bare SELECT *
        if isinstance(star.parent, (exp.Count, exp.Column)):
            continue
        for t in real:
            touched |= whole_table(t)

    approvals, pii = [], set()
    risk = 10
    for key in sorted(touched):
        rule = col_rules[key]
        action = rule.get("action", "deny")
        if action == "deny" or action not in ("allow", "require_approval"):
            return _deny(f"column {key} is blocked ({rule.get('tag')})", h, real, touched)
        if action == "require_approval":
            approvals.append(key)
        if rule.get("tag") == "pii":
            pii.add(key)
        if rule.get("tag") == "untrusted":
            risk += 10

    # 6. Limits
    lim = policy["limits"]
    limit_val = None
    limit_node = stmt.args.get("limit")
    if limit_node is not None:
        lit = limit_node.expression
        if isinstance(lit, exp.Literal) and lit.is_int:
            limit_val = int(lit.name)
        else:
            return _deny("LIMIT must be a plain integer", h, real, touched)
    if lim.get("require_limit") and limit_val is None:
        return _deny("a LIMIT is required", h, real, touched)
    if limit_val is not None and limit_val > lim["max_limit"]:
        return _deny(f"LIMIT {limit_val} exceeds max {lim['max_limit']}", h, real, touched)

    # 7. Session budgets
    if session.rows_used + (limit_val or 0) > lim["max_rows_per_session"]:
        return _deny("session row budget exceeded", h, real, touched)
    if len(session.pii_columns | pii) > lim["max_pii_columns_per_session"]:
        return _deny("session PII column budget exceeded", h, real, touched)

    # 8. Risk score and decision
    if pii:
        risk += 40
    if stmt.find(exp.Join):
        risk += 10
    if limit_val and limit_val > 500:
        risk += 10
    if stmt.find(exp.Subquery):
        risk += 5

    if approvals:
        return Decision("approve", f"human approval required for {approvals}",
                        risk, h, real, sorted(touched), canonical)

    session.rows_used += limit_val or 0   # budgets only count allowed queries
    session.pii_columns |= pii
    return Decision("allow", "within policy", risk, h, real, sorted(touched), canonical)


def validate_policy_against_schema(policy: dict, con) -> list[str]:
    """Return problems where the policy and the real database disagree. Empty = OK."""
    rows = con.execute(
        "SELECT table_name, column_name FROM information_schema.columns "
        "WHERE table_schema = 'main'").fetchall()
    actual: dict[str, set[str]] = {}
    for t, c in rows:
        actual.setdefault(t.lower(), set()).add(c.lower())
    tagged: dict[str, set[str]] = {}
    for key in policy.get("columns", {}):
        t, c = key.lower().split(".")
        tagged.setdefault(t, set()).add(c)
    problems = []
    for tname, trule in policy.get("tables", {}).items():
        t = tname.lower()
        declared = {c.lower() for c in (trule.get("columns") or [])} | tagged.get(t, set())
        if t not in actual:
            problems.append(f"table {t} is in the policy but not in the database")
            continue
        for c in sorted(actual[t] - declared):
            problems.append(f"{t}.{c} exists in the database but is unclassified")
        for c in sorted(declared - actual[t]):
            problems.append(f"{t}.{c} is in the policy but missing from the database")
    return problems


class AuditLog:
    """Every decision and every execution outcome is recorded."""

    def __init__(self, path: str = str(ROOT / "data" / "audit.duckdb")):
        self._lock = threading.Lock()
        self.con = duckdb.connect(path)
        with self._lock:
            self.con.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    ts TIMESTAMP DEFAULT current_timestamp,
                    session_id VARCHAR, sql VARCHAR, sql_hash VARCHAR,
                    decision VARCHAR, risk INTEGER, reason VARCHAR)""")
            self.con.execute("""
                CREATE TABLE IF NOT EXISTS execution_log (
                    ts TIMESTAMP DEFAULT current_timestamp,
                    session_id VARCHAR, sql_hash VARCHAR,
                    outcome VARCHAR, row_count INTEGER, error VARCHAR)""")

    def record(self, session_id: str, sql: str, d: Decision) -> None:
        with self._lock:
            self.con.execute(
                "INSERT INTO audit_log (session_id, sql, sql_hash, decision, risk, reason) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                [session_id, sql, d.sql_hash, d.decision, d.risk, d.reason])

    def record_execution(self, session_id: str, sql_hash: str, outcome: str,
                         row_count: int = 0, error: str = "") -> None:
        with self._lock:
            self.con.execute(
                "INSERT INTO execution_log (session_id, sql_hash, outcome, row_count, error) "
                "VALUES (?, ?, ?, ?, ?)",
                [session_id, sql_hash, outcome, row_count, error])

    def rows(self) -> list:
        with self._lock:
            return self.con.execute(
                "SELECT decision, risk, reason, sql FROM audit_log ORDER BY ts").fetchall()

    def execution_rows(self) -> list:
        with self._lock:
            return self.con.execute(
                "SELECT outcome, row_count, error, sql_hash FROM execution_log ORDER BY ts").fetchall()

    def close(self) -> None:
        with self._lock:
            self.con.close()


def review(sql: str, policy: dict, session: Session, audit: AuditLog) -> Decision:
    d = check_sql(sql, policy, session)
    audit.record(session.session_id, sql, d)
    return d
