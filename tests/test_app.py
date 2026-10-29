import pytest
import streamlit as st
from streamlit.testing.v1 import AppTest

from src.asg import seed
from src.asg.guard import ROOT


@pytest.fixture()
def app(tmp_path, monkeypatch):
    db = tmp_path / "sandbox.duckdb"
    seed.build(str(db))
    monkeypatch.setenv("ASG_SANDBOX", str(db))
    monkeypatch.setenv("ASG_AUDIT", ":memory:")
    monkeypatch.setenv("ASG_APPROVALS", ":memory:")
    st.cache_resource.clear()
    yield AppTest.from_file(str(ROOT / "app.py"), default_timeout=60)
    st.cache_resource.clear()


def test_app_starts_without_errors(app):
    at = app.run()
    assert not at.exception
    assert "ASG" in at.title[0].value


def test_playground_runs_a_safe_question_end_to_end(app):
    at = app.run()
    at.button(key="go_playground").click().run()
    assert not at.exception
    last = at.session_state["last"]
    assert last["outcome"].decision.decision == "allow" and last["outcome"].executed


def test_scenarios_all_match_in_the_ui(app):
    at = app.run()
    at.button(key="run_scenarios").click().run()
    assert not at.exception
    assert all(r["match"] for r in at.session_state["scenario_results"])
