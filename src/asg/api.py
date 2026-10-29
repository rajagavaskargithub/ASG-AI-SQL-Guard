"""AI-ASG gateway. The agent sends SQL here and never holds a DB connection."""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .executor import ExecutionFailed, ExecutionRefused, execute_decision, open_sandbox
from .guard import (ROOT, AuditLog, Session, load_policy, review,
                    validate_policy_against_schema)


class QueryRequest(BaseModel):
    sql: str
    session_id: str = "default"


def _log_execution(audit, session_id, sql_hash, outcome, rows=0, error="") -> bool:
    try:
        audit.record_execution(session_id, sql_hash, outcome, rows, error)
        return True
    except Exception:
        return False


def create_app(audit_path: str = str(ROOT / "data" / "audit.duckdb"),
               sandbox_path: str = str(ROOT / "data" / "sandbox.duckdb")) -> FastAPI:
    app = FastAPI(title="AI-ASG")
    policy = load_policy()

    con = open_sandbox(sandbox_path)
    try:
        problems = validate_policy_against_schema(policy, con)
    finally:
        con.close()
    if problems:
        raise RuntimeError("policy does not match the database schema: " + "; ".join(problems))

    audit = AuditLog(audit_path)
    app.state.audit = audit
    sessions: dict[str, Session] = {}
    max_rows = policy["limits"]["max_limit"]

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.post("/query")
    async def query(req: QueryRequest):
        session = sessions.setdefault(req.session_id, Session(session_id=req.session_id))
        try:
            d = review(req.sql, policy, session, audit)       # decide AND log
        except Exception:                                     # no audit record, no execution
            return JSONResponse({"decision": "deny", "executed": False,
                                 "reason": "audit unavailable (fail closed)"},
                                status_code=500)
        info = {"decision": d.decision, "reason": d.reason, "risk": d.risk,
                "sql_hash": d.sql_hash, "executed": False}

        if d.decision == "deny":
            return JSONResponse(info, status_code=403)
        if d.decision == "approve":                           # approvals are not built yet
            return JSONResponse({**info, "status": "pending_approval"}, status_code=202)

        try:
            result = execute_decision(d, policy, sandbox_path, max_rows)
        except (ExecutionRefused, ExecutionFailed) as e:
            logged = _log_execution(audit, session.session_id, d.sql_hash, "failed", 0, str(e))
            return JSONResponse({**info, "reason": str(e), "execution_logged": logged},
                                status_code=500)
        except Exception:
            logged = _log_execution(audit, session.session_id, d.sql_hash, "failed", 0,
                                    "unexpected error")
            return JSONResponse({**info, "reason": "execution error (fail closed)",
                                 "execution_logged": logged}, status_code=500)

        logged = _log_execution(audit, session.session_id, d.sql_hash, "succeeded",
                                len(result.rows))
        return {**info, "executed": True, "execution_logged": logged,
                "columns": result.columns, "rows": result.rows}

    return app
