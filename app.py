"""ASG demo UI. Run: .venv/bin/python -m streamlit run app.py
Everything shown here comes from src/asg/service.py; this file only displays it."""
import json
import os
import uuid

import duckdb
import pandas as pd
import streamlit as st

from src.asg import nl2sql
from src.asg.approvals import ApprovalError
from src.asg.executor import ExecutionFailed, ExecutionRefused
from src.asg.service import AsgService, PolicyMismatch

st.set_page_config(page_title="ASG: AI SQL Guard", layout="wide")


@st.cache_resource
def get_service() -> AsgService:
    return AsgService(sandbox_path=os.environ.get("ASG_SANDBOX") or None,
                      audit_path=os.environ.get("ASG_AUDIT") or None,
                      approvals_path=os.environ.get("ASG_APPROVALS") or None)


try:
    svc = get_service()
except PolicyMismatch as e:
    st.error(f"The policy and the database schema disagree, so ASG will not start: {e}")
    st.stop()
except duckdb.IOException:
    st.error("Could not open an ASG database file. Another process (for example uvicorn) "
             "may hold the lock: stop it and reload. If data/sandbox.duckdb is missing, "
             "run `python -m src.asg.seed`.")
    st.stop()
except Exception as e:
    st.error(f"ASG failed to start ({type(e).__name__}).")
    st.stop()

sid = st.session_state.setdefault("sid", f"ui-{uuid.uuid4().hex[:8]}")


def show_outcome(o):
    d = o.decision
    label = {"allow": "ALLOW", "deny": "DENY", "approve": "APPROVAL REQUIRED"}[d.decision]
    {"allow": st.success, "deny": st.error, "approve": st.warning}[d.decision](
        f"**{label}**: {d.reason}")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Risk score", d.risk)
    c2.metric("Executed", "Yes" if o.executed else "No")
    c3.metric("Audit record written", "Yes" if o.audit_written else "NO")
    c4.metric("Execution logged", "Yes" if o.execution_logged else "n/a")
    st.markdown(f"**Triggering rule:** `{o.policy_rule}` *(derived from the guard's reason)*")
    st.markdown(f"**Tables:** {d.tables or 'none'}  \n**Columns touched:** {d.columns or 'none'}  \n"
                f"**SQL hash:** `{d.sql_hash}`")
    if d.canonical_sql:
        st.markdown("**Exact SQL that was evaluated:**")
        st.code(d.canonical_sql, language="sql")
    if o.error:
        st.error(o.error)
    if o.approval_id:
        st.info(f"Held for approval (id `{o.approval_id[:8]}`). Nothing has executed. "
                "Use the **Approvals** tab.")
    if o.executed:
        st.dataframe(pd.DataFrame(o.rows, columns=o.columns))


st.title("ASG: AI SQL Guard")
st.caption("The security layer between AI-generated SQL and your data.")

with st.sidebar:
    st.header("SQL source")
    mode = st.radio("Mode", ["Mock (no API key)", "Muse (live model)"], key="mode")
    mock = mode.startswith("Mock")
    st.caption("Mock mode uses fixed questions and needs no key." if mock else
               "Live mode calls the model configured in .env. Its output is untrusted.")
    st.caption(f"Session `{sid}`  \nPolicy version `{svc.policy_version}`")

t_over, t_play, t_appr, t_scen, t_pol, t_audit = st.tabs(
    ["Overview", "Playground", "Approvals", "Scenarios", "Policy", "Audit trail"])

with t_over:
    st.subheader("What ASG does")
    st.write("AI agents write SQL. ASG decides, with deterministic code, whether that SQL "
             "may run. The model never judges its own output.")
    st.code("Question -> LLM (untrusted) -> SQL -> ASG guard -> audit log\n"
            "                                     |-- allow   -> read-only execution\n"
            "                                     |-- approve -> human decision -> revalidate -> execute once\n"
            "                                     `-- deny    -> stop", language="text")
    m = svc.metrics()
    cols = st.columns(6)
    for col, (k, label) in zip(cols, [("reviewed", "Reviewed"), ("allow", "Allowed"),
                                      ("deny", "Denied"), ("approve", "Approval required"),
                                      ("executed", "Executed"), ("failed", "Failed runs")]):
        col.metric(label, m[k])
    st.caption("Live counts from the audit database (data/audit.duckdb), all sessions since "
               "the file was created. Not demo data. Reviewed = every query evaluated. "
               "Approval required = held, not approved. Executed = a run that succeeded "
               "(including approved runs). Failed = a run that started and errored.")
    a = st.columns(4)
    a[0].metric("Approvals requested", m["approvals_requested"])
    a[1].metric("Approved", m["approvals_approved"])
    a[2].metric("Rejected", m["approvals_rejected"])
    a[3].metric("Approved and run", m["approvals_executed"])
    st.subheader("Controls")
    st.dataframe(pd.DataFrame([
        ("One statement, SELECT only", "Implemented", "Tested"),
        ("Table allowlist, column default-deny", "Implemented", "Tested"),
        ("Blocked columns, PII approval, whole-row and star expansion", "Implemented", "Tested"),
        ("Required and maximum LIMIT", "Implemented", "Tested"),
        ("Blocked file and system functions", "Implemented", "Tested"),
        ("Read-only DB, external access and ATTACH disabled", "Implemented", "Tested"),
        ("Only the evaluated SQL executes; revalidated first", "Implemented", "Tested"),
        ("Fail closed on errors, including audit write failure", "Implemented", "Tested"),
        ("Audit of decisions and execution outcomes", "Implemented", "Tested"),
        ("Hash-bound, expiring, single-use approvals", "Implemented", "Tested"),
        ("Query timeout and memory limit", "Implemented (best effort)", "Tested"),
        ("Verified approver identity / authentication", "NOT implemented", "n/a"),
        ("Tamper-evident audit log", "NOT implemented", "n/a"),
        ("Real warehouse connectors (Snowflake, BigQuery)", "NOT implemented", "n/a"),
    ], columns=["Control", "Status", "Tests"]))

with t_play:
    if mock:
        q = st.selectbox("Business question", list(nl2sql.MOCK_QUESTIONS), key="mock_q")
        inject = False
    else:
        q = st.text_area("Business question", "Show the top three orders by amount.",
                         key="live_q")
        inject = st.checkbox("Add customer 7's note as untrusted context "
                             "(prompt-injection demo)", key="inject")
    if st.button("Generate SQL and evaluate", key="go_playground"):
        try:
            sql = (nl2sql.mock_sql(q) if mock else
                   nl2sql.live_sql(q, svc.schema_text(),
                                   nl2sql.INJECTED_NOTE if inject else None))
        except nl2sql.NL2SQLError as e:
            st.session_state["last"] = {"error": str(e)}
        else:
            st.session_state["last"] = {"question": q, "sql": sql,
                                        "outcome": svc.submit(sql, sid)}
    with st.expander("Send SQL straight to the guard (skips the LLM)"):
        raw = st.text_area("SQL", "SELECT order_id FROM orders LIMIT 5", key="raw_sql")
        if st.button("Evaluate SQL", key="go_raw"):
            st.session_state["last"] = {"question": None, "sql": raw,
                                        "outcome": svc.submit(raw, sid)}
    last = st.session_state.get("last")
    if last:
        if "error" in last:
            st.error(last["error"])
        else:
            if last["question"]:
                st.markdown(f"**Question:** {last['question']}")
            st.markdown("**Generated SQL (untrusted until ASG evaluates it):**")
            st.code(last["sql"], language="sql")
            show_outcome(last["outcome"])

with t_appr:
    st.caption("The approver name is typed text, not an authenticated identity. In this demo "
               "one person plays both roles, so separation of duties is not demonstrated.")
    pending = svc.approvals.list_by_status("pending", sid)
    approved = svc.approvals.list_by_status("approved", sid)
    st.subheader(f"Pending ({len(pending)})")
    for row in pending:
        aid, ctx = row["approval_id"], json.loads(row["context"])
        with st.container(border=True):
            st.code(row["canonical_sql"], language="sql")
            st.write(f"Columns: {ctx['columns']} | Reason: {ctx['reason']} | "
                     f"Hash `{row['sql_hash']}` | Not executed")
            who = st.text_input("Approver name", "reviewer", key=f"who_{aid}")
            b1, b2 = st.columns(2)
            for btn, ok in ((b1.button("Approve", key=f"ap_{aid}"), True),
                            (b2.button("Reject", key=f"rj_{aid}"), False)):
                if btn:
                    try:
                        svc.decide(aid, who, ok)
                    except ApprovalError as e:
                        st.error(str(e))
                    else:
                        st.rerun()
    st.subheader(f"Approved, waiting to run ({len(approved)})")
    for row in approved:
        aid = row["approval_id"]
        with st.container(border=True):
            st.code(row["canonical_sql"], language="sql")
            st.write(f"Approved by `{row['decided_by']}`. Single use. "
                     "The guard revalidates the exact SQL first.")
            if st.button("Run approved query", key=f"run_{aid}"):
                try:
                    res = svc.run_approved(aid, sid)
                except (ApprovalError, ExecutionRefused, ExecutionFailed) as e:
                    st.error(str(e))
                else:
                    st.session_state.setdefault("approved_results", {})[aid] = (
                        res.columns, res.rows)
                    st.rerun()
    for aid, (cols_, rows_) in st.session_state.get("approved_results", {}).items():
        st.markdown(f"**Result of approval `{aid[:8]}`**")
        st.dataframe(pd.DataFrame(rows_, columns=cols_))
    with st.expander("Approval event log"):
        st.dataframe(pd.DataFrame(svc.approvals.events(),
                                  columns=["event", "actor", "detail"]))

with t_scen:
    st.write("Each scenario runs through the real pipeline (guard, audit, execution gate) "
             "in this session. Scenario 3 creates a real pending approval.")
    if st.button("Run all scenarios", key="run_scenarios"):
        st.session_state["scenario_results"] = svc.run_scenarios(sid)
    res = st.session_state.get("scenario_results")
    if res:
        df = pd.DataFrame(res)
        df["result"] = df["match"].map({True: "MATCH", False: "MISMATCH"})
        st.dataframe(df[["scenario", "sql", "expected", "actual", "result", "executed", "rule"]])
        bad = [r["scenario"] for r in res if not r["match"]]
        if bad:
            st.error(f"Unexpected behaviour in: {bad}")
        else:
            st.success(f"All {len(res)} scenarios behaved as expected.")

with t_pol:
    pol = svc.policy
    st.caption(f"Loaded from policy.yaml. Version hash `{svc.policy_version}`.")
    st.markdown(f"**Allowed statements:** {pol['allowed_statements']}")
    st.dataframe(pd.DataFrame(
        [(t, r.get("allowed"), ", ".join(r.get("columns") or []))
         for t, r in pol["tables"].items()],
        columns=["Table", "Allowed", "Unclassified columns allowed"]))
    st.dataframe(pd.DataFrame(
        [(k, v["tag"], v["action"]) for k, v in pol["columns"].items()],
        columns=["Column", "Tag", "Action"]))
    st.json(pol["limits"])
    st.subheader("What is actually enforced")
    st.dataframe(pd.DataFrame([
        ("allowed_statements", "Enforced and tested"),
        ("tables (and per-table column lists)", "Enforced and tested; unlisted columns are denied"),
        ("columns: tag and action", "Enforced and tested"),
        ("limits.require_limit, limits.max_limit", "Enforced and tested"),
        ("limits.max_rows_per_session", "Enforced for allowed queries; tested"),
        ("limits.max_pii_columns_per_session",
         "Coded, but cannot trigger today: PII columns need approval and approved queries "
         "are not counted"),
        ("default, on_error",
         "Informational: the guard always denies by default and fails closed; these values "
         "are not read"),
        ("version", "Informational label"),
    ], columns=["Policy key", "Status"]))

with t_audit:
    flt = st.selectbox("Decision filter", ["all", "allow", "deny", "approve"], key="flt")
    recs = svc.audit.records(None if flt == "all" else flt)
    st.write(f"{len(recs)} records (newest first, max 200)")
    st.dataframe(pd.DataFrame(
        [(str(r[0]), r[1], r[2], r[3], r[4], r[5]) for r in recs],
        columns=["time", "session", "sql_hash", "decision", "risk", "reason"]))
    if recs:
        i = st.selectbox("Inspect a record", list(range(len(recs))), key="inspect",
                         format_func=lambda i: f"{recs[i][0]} | {recs[i][3]} | {recs[i][2]}")
        r = recs[i]
        st.json({"time": str(r[0]), "session": r[1], "sql_hash": r[2], "decision": r[3],
                 "risk": r[4], "reason": r[5], "sql": r[6]})
    st.subheader("Execution outcomes")
    st.dataframe(pd.DataFrame(
        [(str(r[0]), r[1], r[2], r[3], r[4], r[5]) for r in svc.audit.execution_records()],
        columns=["time", "session", "sql_hash", "outcome", "rows", "error"]))
