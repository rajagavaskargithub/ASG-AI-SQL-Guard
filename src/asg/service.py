"""Everything the demo UI does goes through here: guard -> audit -> approval/execution.
The UI only displays what this layer reports."""
from __future__ import annotations

import re
import threading
from collections import Counter
from dataclasses import dataclass, field

from .approvals import COLS, ApprovalError, ApprovalStore, policy_version
from .executor import (SANDBOX, ExecutionFailed, ExecutionRefused, execute_decision,
                       open_sandbox)
from .guard import (ROOT, AuditLog, Decision, Session, hash_sql, load_policy, review,
                    validate_policy_against_schema)
from .scenarios import SCENARIOS

DEFAULT_AUDIT = ROOT / "data" / "audit.duckdb"
DEFAULT_APPROVALS = ROOT / "data" / "approvals.duckdb"


class PolicyMismatch(RuntimeError):
    pass


class ReportingAuditLog(AuditLog):
    def counts(self) -> dict:
        with self._lock:
            dec = dict(self.con.execute(
                "SELECT decision, count(*) FROM audit_log GROUP BY 1").fetchall())
            ex = dict(self.con.execute(
                "SELECT outcome, count(*) FROM execution_log GROUP BY 1").fetchall())
        return {"reviewed": sum(dec.values()), "allow": dec.get("allow", 0),
                "deny": dec.get("deny", 0), "approve": dec.get("approve", 0),
                "executed": ex.get("succeeded", 0), "failed": ex.get("failed", 0)}

    def records(self, decision: str | None = None, limit: int = 200) -> list:
        q = ("SELECT ts, session_id, sql_hash, decision, risk, reason, sql FROM audit_log")
        params: list = []
        if decision:
            q += " WHERE decision = ?"
            params.append(decision)
        q += " ORDER BY ts DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            return self.con.execute(q, params).fetchall()

    def execution_records(self, limit: int = 200) -> list:
        with self._lock:
            return self.con.execute(
                "SELECT ts, session_id, sql_hash, outcome, row_count, error "
                "FROM execution_log ORDER BY ts DESC LIMIT ?", [limit]).fetchall()


class ReportingApprovalStore(ApprovalStore):
    def list_by_status(self, status: str, session_id: str) -> list[dict]:
        with self._lock:
            rows = self.con.execute(
                "SELECT * FROM approvals WHERE status = ? AND session_id = ? "
                "AND expires_at >= ? ORDER BY created_at",
                [status, session_id, self.clock()]).fetchall()
        return [dict(zip(COLS, r)) for r in rows]


def triggered_policy(d: Decision) -> str:
    """Name the policy rule behind a decision, derived from the guard's reason text."""
    r = d.reason.lower()
    if d.decision == "allow":
        return "none (all rules satisfied)"
    if "audit unavailable" in r:
        return "audit log write (fail closed)"
    if r.startswith("guard error"):
        return "fail-closed handler"
    if "unparseable" in r or "exactly one statement" in r:
        return "parser: one valid statement"
    if "statement type" in r:
        return "allowed_statements"
    if r.startswith("function"):
        return "blocked functions (guard code)"
    if "parameters" in r:
        return "query parameters blocked (guard code)"
    if "table functions" in r or "schema-qualified" in r:
        return "table sources (guard code)"
    if "default deny" in r:
        return "tables.<table>.columns (default deny)"
    if r.startswith("table"):
        return "tables"
    if d.decision == "approve":
        cols = re.findall(r"\w+\.\w+", d.reason)
        return "columns." + ", ".join(cols) if cols else "columns (require_approval)"
    m = re.search(r"column (\S+) is blocked", d.reason)
    if m:
        return f"columns.{m.group(1)}"
    if "limit" in r:
        return "limits.require_limit / limits.max_limit"
    if "budget" in r:
        return "limits.max_rows_per_session / max_pii_columns_per_session"
    return f"guard rule: {d.reason}"


@dataclass
class Outcome:
    sql: str
    decision: Decision
    policy_rule: str = ""
    executed: bool = False
    columns: list | None = None
    rows: list | None = None
    approval_id: str | None = None
    audit_written: bool = False
    execution_logged: bool = False
    error: str | None = None


class AsgService:
    def __init__(self, sandbox_path=None, audit_path=None, approvals_path=None,
                 policy_path=ROOT / "policy.yaml"):
        self.sandbox_path = sandbox_path or SANDBOX
        self.policy = load_policy(policy_path)
        self.policy_version = policy_version(self.policy)
        con = open_sandbox(self.sandbox_path)
        try:
            problems = validate_policy_against_schema(self.policy, con)
        finally:
            con.close()
        if problems:
            raise PolicyMismatch("; ".join(problems))
        self.audit = ReportingAuditLog(str(audit_path or DEFAULT_AUDIT))
        self.approvals = ReportingApprovalStore(str(approvals_path or DEFAULT_APPROVALS))
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()

    def _session(self, session_id: str) -> Session:
        with self._lock:
            return self._sessions.setdefault(session_id, Session(session_id=session_id))

    def _log_exec(self, session_id, sql_hash, outcome, rows=0, error="") -> bool:
        try:
            self.audit.record_execution(session_id, sql_hash, outcome, rows, error)
            return True
        except Exception:
            return False

    def submit(self, sql: str, session_id: str) -> Outcome:
        session = self._session(session_id)
        try:
            d = review(sql, self.policy, session, self.audit)      # decide AND log
        except Exception:                                          # no audit record -> no execution
            d = Decision("deny", "audit unavailable (fail closed)", 100, hash_sql(str(sql)))
            return Outcome(sql, d, triggered_policy(d), audit_written=False,
                           error="the audit log write failed, so nothing was executed")
        out = Outcome(sql, d, triggered_policy(d), audit_written=True)
        if d.decision == "deny":
            return out
        if d.decision == "approve":
            try:
                out.approval_id = self.approvals.request(d, session_id, self.policy,
                                                         requester="agent")
            except ApprovalError as e:
                out.error = str(e)
            return out
        try:
            res = execute_decision(d, self.policy, self.sandbox_path,
                                   self.policy["limits"]["max_limit"])
        except (ExecutionRefused, ExecutionFailed) as e:
            out.error = str(e)
            out.execution_logged = self._log_exec(session_id, d.sql_hash, "failed", 0, str(e))
            return out
        except Exception:
            out.error = "unexpected execution error"
            out.execution_logged = self._log_exec(session_id, d.sql_hash, "failed", 0,
                                                  "unexpected error")
            return out
        out.executed, out.columns, out.rows = True, res.columns, res.rows
        out.execution_logged = self._log_exec(session_id, d.sql_hash, "succeeded",
                                              len(res.rows))
        return out

    def decide(self, approval_id: str, approver: str, approve: bool) -> None:
        self.approvals.decide(approval_id, approver, approve)

    def run_approved(self, approval_id: str, session_id: str):
        row = self.approvals.get(approval_id)
        h = row["sql_hash"] if row else ""
        try:
            res = self.approvals.execute(approval_id, session_id, self.policy,
                                         self.sandbox_path,
                                         self.policy["limits"]["max_limit"])
        except ApprovalError:
            raise                                   # refused before anything ran
        except (ExecutionRefused, ExecutionFailed) as e:
            self._log_exec(session_id, h, "failed", 0, str(e))
            raise
        self._log_exec(session_id, h, "succeeded", len(res.rows))
        return res

    def run_scenarios(self, session_id: str) -> list[dict]:
        rows = []
        for sc in SCENARIOS:
            o = self.submit(sc.sql, session_id)
            rows.append({"scenario": sc.name, "sql": sc.sql, "expected": sc.expected,
                         "actual": o.decision.decision,
                         "match": sc.expected == o.decision.decision,
                         "executed": o.executed, "rule": o.policy_rule})
        return rows

    def metrics(self) -> dict:
        m = self.audit.counts()
        ev = Counter(e[0] for e in self.approvals.events())
        m.update(approvals_requested=ev["requested"], approvals_approved=ev["approved"],
                 approvals_rejected=ev["rejected"], approvals_executed=ev["executed"])
        return m

    def schema_text(self) -> str:
        from .nl2sql import schema_text
        return schema_text(self.sandbox_path)

    def close(self) -> None:
        self.audit.close()
        self.approvals.close()
