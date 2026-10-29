"""Human approval workflow for queries the guard classifies as 'approve'.
An approval is bound to the exact SQL hash, the policy version, and the session.
It is single-use and expires. Identity is a plain string: there is no
authentication yet, so 'decided_by' is NOT a verified identity."""
from __future__ import annotations

import hashlib
import json
import threading
import time
import uuid

import duckdb

from .executor import (SANDBOX, ExecResult, ExecutionFailed, ExecutionRefused,
                       execute_approved)
from .guard import ROOT, Decision, hash_sql


class ApprovalError(Exception):
    """An approval action was refused. The message is safe to show."""


def policy_version(policy: dict) -> str:
    blob = json.dumps(policy, sort_keys=True, default=str).encode()
    return hashlib.sha256(blob).hexdigest()[:16]


COLS = ["approval_id", "session_id", "requester", "sql_hash", "canonical_sql",
        "policy_version", "context", "created_at", "expires_at", "status",
        "decided_by", "decided_at"]


class ApprovalStore:
    def __init__(self, path: str = str(ROOT / "data" / "approvals.duckdb"),
                 clock=time.time):
        self.clock = clock
        self._lock = threading.Lock()
        self._seq = 0
        self.con = duckdb.connect(path)
        with self._lock:
            self.con.execute("""
                CREATE TABLE IF NOT EXISTS approvals (
                    approval_id VARCHAR, session_id VARCHAR, requester VARCHAR,
                    sql_hash VARCHAR, canonical_sql VARCHAR, policy_version VARCHAR,
                    context VARCHAR, created_at DOUBLE, expires_at DOUBLE,
                    status VARCHAR, decided_by VARCHAR, decided_at DOUBLE)""")
            self.con.execute("""
                CREATE TABLE IF NOT EXISTS approval_events (
                    seq INTEGER, ts DOUBLE, approval_id VARCHAR,
                    event VARCHAR, actor VARCHAR, detail VARCHAR)""")

    # internal helpers: callers hold self._lock
    def _row(self, approval_id: str):
        r = self.con.execute("SELECT * FROM approvals WHERE approval_id = ?",
                             [approval_id]).fetchone()
        return dict(zip(COLS, r)) if r else None

    def _event(self, approval_id: str, event: str, actor: str = "", detail: str = ""):
        self._seq += 1
        self.con.execute("INSERT INTO approval_events VALUES (?, ?, ?, ?, ?, ?)",
                         [self._seq, self.clock(), approval_id, event, actor, detail])

    def _set_status(self, approval_id: str, status: str):
        self.con.execute("UPDATE approvals SET status = ? WHERE approval_id = ?",
                         [status, approval_id])

    # public API
    def request(self, decision: Decision, session_id: str, policy: dict,
                requester: str, ttl_s: float = 900) -> str:
        if decision.decision != "approve" or not decision.canonical_sql:
            raise ApprovalError("only queries classified 'approve' can be submitted")
        if hash_sql(decision.canonical_sql) != decision.sql_hash:
            raise ApprovalError("SQL does not match its hash")
        aid = uuid.uuid4().hex
        now = self.clock()
        ctx = json.dumps({"tables": decision.tables, "columns": decision.columns,
                          "reason": decision.reason, "risk": decision.risk})
        with self._lock:
            self.con.execute(
                "INSERT INTO approvals VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', NULL, NULL)",
                [aid, session_id, requester, decision.sql_hash, decision.canonical_sql,
                 policy_version(policy), ctx, now, now + ttl_s])
            self._event(aid, "requested", requester, decision.sql_hash)
        return aid

    def decide(self, approval_id: str, approver: str, approve: bool,
               allow_self_approval: bool = False) -> None:
        with self._lock:
            row = self._row(approval_id)
            if not row:
                raise ApprovalError("unknown approval")
            if row["status"] != "pending":
                raise ApprovalError(f"approval is {row['status']}, not pending")
            if self.clock() > row["expires_at"]:
                self._set_status(approval_id, "expired")
                self._event(approval_id, "expired", approver)
                raise ApprovalError("approval expired")
            if approver == row["requester"] and not allow_self_approval:
                self._event(approval_id, "refused", approver, "self-approval")
                raise ApprovalError("requester cannot approve their own request")
            status = "approved" if approve else "rejected"
            self.con.execute(
                "UPDATE approvals SET status = ?, decided_by = ?, decided_at = ? "
                "WHERE approval_id = ?", [status, approver, self.clock(), approval_id])
            self._event(approval_id, status, approver)

    def execute(self, approval_id: str, session_id: str, policy: dict,
                sandbox_path=SANDBOX, max_rows: int | None = None,
                timeout_s: float = 5.0) -> ExecResult:
        """Run an approved query. The caller supplies an ID, never SQL."""
        with self._lock:
            row = self._row(approval_id)
            if not row:
                raise ApprovalError("unknown approval")
            problem = None
            if row["status"] != "approved":
                problem = f"approval is {row['status']}, not approved"
            elif self.clock() > row["expires_at"]:
                self._set_status(approval_id, "expired")
                problem = "approval expired"
            elif row["session_id"] != session_id:
                problem = "approval belongs to a different session"
            elif row["policy_version"] != policy_version(policy):
                problem = "policy changed since the request"
            elif hash_sql(row["canonical_sql"]) != row["sql_hash"]:
                problem = "stored SQL does not match its hash"
            if problem:
                self._event(approval_id, "execution_refused", "", problem)
                raise ApprovalError(problem)
            # Single use: claim it BEFORE running, so a failed run cannot be retried.
            self._set_status(approval_id, "consumed")
            self._event(approval_id, "consumed", row["decided_by"] or "")
            sql, h = row["canonical_sql"], row["sql_hash"]
        try:
            result = execute_approved(sql, h, policy, sandbox_path,
                                      max_rows or policy["limits"]["max_limit"], timeout_s)
        except (ExecutionRefused, ExecutionFailed) as e:
            with self._lock:
                self._event(approval_id, "execution_failed", "", str(e))
            raise
        with self._lock:
            self._event(approval_id, "executed", "", f"{len(result.rows)} rows")
        return result

    def get(self, approval_id: str):
        with self._lock:
            return self._row(approval_id)

    def pending(self) -> list[dict]:
        with self._lock:
            now = self.clock()
            rows = self.con.execute(
                "SELECT * FROM approvals WHERE status = 'pending' AND expires_at >= ? "
                "ORDER BY created_at", [now]).fetchall()
        return [dict(zip(COLS, r)) for r in rows]

    def events(self, approval_id: str | None = None) -> list[tuple]:
        with self._lock:
            if approval_id:
                q = ("SELECT event, actor, detail FROM approval_events "
                     "WHERE approval_id = ? ORDER BY seq")
                return self.con.execute(q, [approval_id]).fetchall()
            return self.con.execute(
                "SELECT event, actor, detail FROM approval_events ORDER BY seq").fetchall()

    def close(self) -> None:
        with self._lock:
            self.con.close()
