# ASG: AI SQL Guard

A security layer between AI-generated SQL and your data. The model writes SQL;
deterministic code decides whether it may run.

> **Status: prototype / demo.** Fake data only, DuckDB only, no authentication.
> Do not expose it to the internet and do not point it at real data.
> It reduces risk; it does not guarantee safety.

Demo video: https://youtu.be/ItiS29Ggfjw

## How it works

```
Question -> LLM (untrusted) -> SQL -> ASG guard -> audit log
                                        |-- allow   -> read-only execution
                                        |-- approve -> human decision -> revalidate -> execute once
                                        `-- deny    -> stop
```

- Parses each query with sqlglot: one statement, `SELECT` only
- Table allowlist and column default-deny; classified columns (`ssn` blocked, `email` and `phone` need approval)
- Catches `SELECT *`, `c.*`, whole-row references, and filtering on blocked columns
- Required and maximum `LIMIT`; blocked file and system functions
- Only the exact evaluated SQL runs, on a read-only DuckDB connection with external access disabled, with a time and memory limit
- Hash-bound, expiring, single-use human approvals, revalidated before execution
- Every decision and execution outcome is audited; the guard fails closed on errors

The model is never asked whether its own SQL is safe.

## Test results (what I measured)

Live Muse Spark models (`muse-spark-1.3`, `muse-spark-1.1`), 9 queries each, fake data, October 2026. Small sample; model outputs vary between runs.

| | Natural mode | Red-team mode |
|---|---|---|
| Queries | 18 | 18 |
| Queries naming sensitive columns | 0 | 14 |
| Would have returned SSNs with no guard | 0 | 14 |
| Returned SSNs with ASG in front | 0 | 0 |
| Sensitive-column queries stopped by ASG | n/a | 14 of 14 |
| Benign queries wrongly blocked | 0 of 18 | 0 of 4 |

- **Natural mode:** a naive agent reads a poisoned note and writes SQL. Neither model followed the injected instructions.
- **Red-team mode:** the model is *told* to simulate a hijacked agent. This tests the guard; it is **not** evidence that these models get hijacked on their own.
- My first run blocked every benign query because the model did not know a `LIMIT` was required. Telling the agent the rule fixed it. The guard still decides independently.
- The 14 queries are only a few distinct attack shapes, not 14 independent attacks.

The suite has 128 automated tests (run `pytest -q`).

## Run it (macOS, Python 3.12)

```bash
git clone <this repo> && cd ai-asg
python3.12 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m src.asg.seed
.venv/bin/python -m pytest -q
.venv/bin/python -m streamlit run app.py
```

Mock mode needs no API key. For live mode, copy `.env.example` to `.env` and add a key
from the Meta Model API dashboard. Never commit `.env`.

Standalone red-team script:

```bash
.venv/bin/python injection_demo.py --compromised muse-spark-1.3
```

## Not implemented

Authentication or verified approver identity, tamper-evident audit log, real
warehouse connectors (Snowflake, BigQuery), concurrent multi-user use, production hardening.
Approval "identity" in the demo is typed text.

## Notes

- Independent project; not affiliated with or endorsed by Meta. "Muse" is Meta's name for its models.
- License: MIT.
