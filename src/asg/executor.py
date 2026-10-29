"""The only path from an ASG decision to the database.
Defence in depth: refuse anything but a verified 'allow', re-run the guard on
the exact string, then execute read-only with external access disabled."""
from __future__ import annotations

import threading
from dataclasses import dataclass

import duckdb
import sqlglot

from .guard import ROOT, Decision, Session, check_sql, hash_sql

SANDBOX = ROOT / "data" / "sandbox.duckdb"


class ExecutionRefused(Exception):
    """The gate refused to run the SQL (decision not 'allow', or verification failed)."""


class ExecutionFailed(Exception):
    """The database run failed. The message is safe to show: no stack trace, no data."""


@dataclass
class ExecResult:
    columns: list
    rows: list


def open_sandbox(path=SANDBOX, memory_limit: str = "256MB", threads: int = 2):
    """Read-only connection with file, network, and ATTACH access disabled."""
    return duckdb.connect(str(path), read_only=True, config={
        "enable_external_access": False,
        "memory_limit": memory_limit,
        "threads": str(threads),
    })


def _run(con, sql: str, max_rows: int, timeout_s: float) -> ExecResult:
    timer = threading.Timer(timeout_s, con.interrupt)   # best-effort time limit
    timer.start()
    try:
        cur = con.execute(sql)
        cols = [c[0] for c in cur.description]
        return ExecResult(cols, cur.fetchmany(max_rows))
    except duckdb.InterruptException:
        raise ExecutionFailed("query exceeded the time limit") from None
    except duckdb.Error as e:
        raise ExecutionFailed(f"database error ({type(e).__name__})") from None
    finally:
        timer.cancel()
        con.close()


def execute_decision(decision: Decision, policy: dict, path=SANDBOX,
                     max_rows: int = 1000, timeout_s: float = 5.0) -> ExecResult:
    if decision.decision != "allow":
        raise ExecutionRefused(f"decision is '{decision.decision}', not 'allow'")
    sql = decision.canonical_sql
    if not sql or hash_sql(sql) != decision.sql_hash:
        raise ExecutionRefused("SQL does not match the evaluated hash")
    try:
        again = sqlglot.parse_one(sql, read="duckdb").sql(dialect="duckdb", comments=False)
    except sqlglot.errors.SqlglotError:
        raise ExecutionRefused("SQL no longer parses") from None
    if again != sql:
        raise ExecutionRefused("SQL is not in canonical form")
    recheck = check_sql(sql, policy, Session())          # revalidate the exact string
    if recheck.decision != "allow" or recheck.sql_hash != decision.sql_hash:
        raise ExecutionRefused("revalidation of the exact SQL failed")
    return _run(open_sandbox(path), sql, max_rows, timeout_s)


def execute_approved(sql: str, sql_hash: str, policy: dict, path=SANDBOX,
                     max_rows: int = 1000, timeout_s: float = 5.0) -> ExecResult:
    """Run SQL that a human approved. Re-verifies the exact string first, and
    requires that the guard still classifies it as 'approve' under the policy."""
    if hash_sql(sql) != sql_hash:
        raise ExecutionRefused("SQL does not match the approved hash")
    try:
        again = sqlglot.parse_one(sql, read="duckdb").sql(dialect="duckdb", comments=False)
    except sqlglot.errors.SqlglotError:
        raise ExecutionRefused("SQL no longer parses") from None
    if again != sql:
        raise ExecutionRefused("SQL is not in canonical form")
    recheck = check_sql(sql, policy, Session())
    if recheck.decision != "approve" or recheck.sql_hash != sql_hash:
        raise ExecutionRefused("revalidation failed: the query is no longer an approvable query")
    try:
        con = open_sandbox(path)
    except duckdb.Error:
        raise ExecutionFailed("could not open the database") from None
    return _run(con, sql, max_rows, timeout_s)
