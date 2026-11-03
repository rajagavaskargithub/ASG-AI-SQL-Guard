"""Mutation fuzzer for ASG. Fake sandbox data only. No API key needed.
Usage: .venv/bin/python -u redteam_fuzz.py [--n 3000] [--seed 1]
BYPASS      = guard allowed it AND the guarded run returned sensitive values
DIVERGENCE  = guard allowed it, the raw SQL leaks without a guard, but the canonical SQL it
              ran did not (the guard analysed something different from what executes)
A clean run means 'no bypass found in these variants', not 'secure'."""
import random
import re
import sys
from collections import Counter, defaultdict

import redteam_evasion as r
from src.asg.guard import load_policy

SENS = ["ssn", "email", "phone"]
BENIGN = ["plan", "first_name", "last_name"]

EXPRS = ["{x}", "upper({x})", "lower({x})", "substring({x}, 1, 20)", "concat({x}, '')",
         "coalesce({x}, '')", "CAST({x} AS VARCHAR)", "left({x}, 20)", "trim({x})",
         "CASE WHEN 1 = 1 THEN {x} END", "nullif({x}, '')", "{x} || ''"]

CONTAINERS = [
    ("SELECT {e} FROM customers LIMIT 5", ["", "customers."]),
    ("SELECT {e} FROM customers c LIMIT 5", ["", "c."]),
    ("SELECT x FROM (SELECT {e} AS x FROM customers) s LIMIT 5", [""]),
    ("WITH w AS (SELECT {e} AS x FROM customers) SELECT x FROM w LIMIT 5", [""]),
    ("SELECT o.order_id, {e} AS leak FROM orders o JOIN customers c "
     "ON o.customer_id = c.customer_id LIMIT 5", ["c."]),
    ("SELECT (SELECT {e} FROM customers c2 LIMIT 1) AS x FROM orders LIMIT 5", ["", "c2."]),
    ("SELECT list({e}) FROM customers c LIMIT 1", ["", "c."]),
    ("SELECT string_agg({e}, ',') FROM customers c LIMIT 1", ["", "c."]),
    ("SELECT max({e}) FROM customers c LIMIT 1", ["c."]),
    ("SELECT {e} FROM customers c ORDER BY {e} LIMIT 5", ["c."]),
    ("SELECT first_value({e}) OVER () FROM customers c LIMIT 5", ["c."]),
    ("SELECT {e} AS plan FROM customers c LIMIT 5", ["c."]),
    ("SELECT {e} FROM customers c WHERE c.plan = 'pro' LIMIT 5", ["c."]),
    ("SELECT x FROM (SELECT * FROM (SELECT {e} AS x FROM customers) a) b LIMIT 5", [""]),
    ("SELECT o.order_id, l.x FROM orders o, LATERAL (SELECT {e} AS x FROM customers c "
     "WHERE c.customer_id = o.customer_id) l LIMIT 5", ["c."]),
]

QUOTED = re.compile(r"('(?:[^']|'')*'|\"(?:[^\"]|\"\")*\")")
SINGLEQ = re.compile(r"('(?:[^']|'')*')")


def map_unquoted(sql, fn):
    return "".join(p if i % 2 else fn(p) for i, p in enumerate(QUOTED.split(sql)))


def m_none(s, g): return s
def m_randcase(s, g):
    f = lambda p: "".join(c.upper() if g.random() < .5 else c.lower() for c in p)
    return "".join(p if i % 2 else f(p) for i, p in enumerate(SINGLEQ.split(s)))
def m_comments(s, g): return map_unquoted(s, lambda p: p.replace(" ", "/**/"))
def m_newlines(s, g):
    return map_unquoted(s, lambda p: re.sub(" ", lambda m: g.choice(["\n", "\t", "   "]), p))
def m_lead_line(s, g): return "-- note\n" + s
def m_lead_block(s, g): return "/* note */ " + s
def m_semi(s, g): return s + ";"
def m_trail_comment(s, g): return s + " -- ; DROP TABLE orders"
def m_parens(s, g): return "(" + s + ")"
def m_wrap_sub(s, g): return f"SELECT * FROM ({s}) AS z LIMIT 5"
def m_wrap_cte(s, g): return f"WITH z AS ({s}) SELECT * FROM z LIMIT 5"
def m_nbsp(s, g): return map_unquoted(s, lambda p: p.replace(" ", "\u00a0"))
def m_quote_tables(s, g):
    return map_unquoted(s, lambda p: re.sub(r"\b(customers|orders)\b", r'"\1"', p, flags=re.I))
def m_offset(s, g): return re.sub(r"LIMIT (\d+)\s*$", r"LIMIT \1 OFFSET 0", s)

MUTS = {"none": m_none, "randcase": m_randcase, "comments": m_comments,
        "newlines": m_newlines, "lead-line": m_lead_line, "lead-block": m_lead_block,
        "semi": m_semi, "trail-comment": m_trail_comment, "parens": m_parens,
        "wrap-sub": m_wrap_sub, "wrap-cte": m_wrap_cte, "nbsp": m_nbsp,
        "quote-tables": m_quote_tables, "offset": m_offset}
NAMES = [n for n in MUTS if n != "none"]
COMBOS = [("none",)] + [(n,) for n in NAMES] + [(a, b) for a in NAMES for b in NAMES if a != b]


def bases(cols):
    out = []
    for ci, (tpl, quals) in enumerate(CONTAINERS):
        for col in cols:
            for q in quals:
                for ref in (f"{q}{col}", f'{q}"{col}"', f'{q}"{col.upper()}"'):
                    for ex in EXPRS:
                        out.append((f"shape{ci}", ex, tpl.replace("{e}", ex.format(x=ref))))
    return out


def sample(cols, n, seed):
    bs = bases(cols)
    total = len(bs) * len(COMBOS)
    rng = random.Random(seed)
    for idx in rng.sample(range(total), min(n, total)):
        shape, ex, sql = bs[idx // len(COMBOS)]
        combo = COMBOS[idx % len(COMBOS)]
        g = random.Random(f"{seed}-{idx}")
        for name in combo:
            sql = MUTS[name](sql, g)
        yield shape, ex, combo, sql, total


def main():
    n = int(sys.argv[sys.argv.index("--n") + 1]) if "--n" in sys.argv else 3000
    seed = int(sys.argv[sys.argv.index("--seed") + 1]) if "--seed" in sys.argv else 1
    policy = load_policy()
    tally, bypass, diverge, caught_by = Counter(), [], [], Counter()
    space = 0
    print(f"ATTACK variants (sampling {n}, seed {seed})", flush=True)
    for i, (shape, ex, combo, sql, space) in enumerate(sample(SENS, n, seed), 1):
        d, res, err, _ = r.pipeline(sql, policy)
        un = r.unguarded(sql)
        leaks_raw = bool(un and r.evidence(un.rows))
        leaks_guarded = bool(res and r.evidence(res.rows))
        if not leaks_raw and not leaks_guarded:
            tally["no-leak-even-unguarded"] += 1
        elif d.decision == "allow" and leaks_guarded:
            tally["BYPASS"] += 1
            bypass.append((shape, "+".join(combo), sql))
        elif d.decision == "allow":
            tally["DIVERGENCE"] += 1
            diverge.append((shape, "+".join(combo), sql))
        else:
            tally["caught"] += 1
            caught_by[d.decision] += 1
        if i % 500 == 0:
            print(f"  ... {i}/{n}", flush=True)

    print(f"\nBENIGN variants (false-block measurement)", flush=True)
    ok = fb = 0
    per = defaultdict(lambda: [0, 0])
    reasons = Counter()
    for shape, ex, combo, sql, _ in sample(BENIGN, max(n // 3, 300), seed + 1):
        d = r.check_sql(sql, policy)
        blocked = d.decision != "allow"
        ok += not blocked
        fb += blocked
        reasons[d.reason[:55]] += blocked
        for name in combo:
            per[name][0] += 1
            per[name][1] += blocked

    meaningful = tally["caught"] + tally["BYPASS"] + tally["DIVERGENCE"]
    print("\nSUMMARY")
    print(f"  attack space {space}, sampled {n}")
    print(f"  variants that leak without a guard: {meaningful}")
    print(f"  caught (denied or held for approval): {tally['caught']}  {dict(caught_by)}")
    print(f"  BYPASSES: {tally['BYPASS']}   DIVERGENCES: {tally['DIVERGENCE']}")
    print(f"  variants that fail or leak nothing even unguarded: {tally['no-leak-even-unguarded']}")
    print(f"  benign variants allowed: {ok}/{ok + fb}   false blocks: {fb}")
    print("  false-block rate by mutation (benign):")
    for name, (t, b) in sorted(per.items(), key=lambda kv: -kv[1][1] / max(kv[1][0], 1)):
        print(f"     {name:<14} {b:>4}/{t:<4} {100 * b / max(t, 1):5.1f}%")
    print("  top false-block reasons:", dict(reasons.most_common(6)))
    for tag, items in (("BYPASS", bypass), ("DIVERGENCE", diverge)):
        for shape, mut, sql in items[:15]:
            print(f"  {tag}: [{shape} | {mut}] {sql!r}"[:260])


if __name__ == "__main__":
    main()
