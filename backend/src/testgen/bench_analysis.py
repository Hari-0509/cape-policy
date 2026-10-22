"""Analysis-only benchmark on synthetic scan snapshots (no API calls).
Usage: python src/testgen/bench_analysis.py [ns_counts] [runs]"""
import sys, time, json, math, random, statistics as st
sys.path.insert(0, "src"); sys.path.insert(0, ".")
from graph.builder import build_full_graph, find_multi_team_nodes
from detection.subsumption import detect_subsumption
from detection.shadowing import detect_shadowing
from detection.cross_domain import detect_cross_domain
from testgen.hw import info

TEAMS = [f"team-{i}" for i in range(12)]
META = {"created_at": None, "last_update": None, "accepted_reason": None}


def synth(n_ns, seed=1):
    r = random.Random(seed)
    keys = ("rbac_roles", "rbac_bindings", "cluster_roles", "cluster_role_bindings",
            "gatekeeper_constraints", "network_policies", "namespaces")
    scan = {k: [] for k in keys}
    names = [f"ns-{i}" for i in range(n_ns)]
    for i, ns in enumerate(names):
        scan["namespaces"].append({"name": ns, "labels": {"cape-policy/class": "application"}})
        a, b = r.sample(TEAMS, 2)
        sa = f"sa-{i}"

        def role(nm, team, verbs):
            scan["rbac_roles"].append({**META, "name": nm, "namespace": ns, "owner": team,
                "rules": [{"resources": ["pods"], "verbs": verbs, "apiGroups": [""]}]})

        def bind(nm, rn, team, sub_ns):
            scan["rbac_bindings"].append({**META, "name": nm, "namespace": ns, "owner": team,
                "role_ref": rn, "role_ref_kind": "Role",
                "subjects": [{"kind": "ServiceAccount", "name": sa, "namespace": sub_ns}]})

        role(f"n{i}", a, ["get", "list"])
        bind(f"nb{i}", f"n{i}", a, ns)
        if i % 2 == 0:
            role(f"w{i}", b, ["*"]); bind(f"wb{i}", f"w{i}", b, ns)
        if i % 10 == 0:
            bind(f"xb{i}", f"n{i}", a, names[(i + 1) % n_ns])
        if i % 3 == 0:
            scan["network_policies"].append({**META, "name": f"dd{i}", "namespace": ns, "owner": b,
                                             "is_default_deny": True})
        if i % 50 == 0:
            scan["gatekeeper_constraints"].append({**META, "name": f"c{i}", "owner": a,
                "match_namespaces": names[i:i + 5], "excluded_namespaces": [], "namespace_selector": None,
                "allowed_repos": ["x/"]})
    return scan


def summarize(x):
    q = st.quantiles(x, n=4)
    return {"median_ms": round(st.median(x) * 1000, 2), "q1_ms": round(q[0] * 1000, 2), "q3_ms": round(q[2] * 1000, 2)}


def slope(xs, ys):
    lx, ly = [math.log(x) for x in xs], [math.log(max(y, 1e-3)) for y in ys]
    mx, my = st.mean(lx), st.mean(ly)
    return sum((a - mx) * (b - my) for a, b in zip(lx, ly)) / sum((a - mx) ** 2 for a in lx)


if __name__ == "__main__":
    scales = [int(x) for x in (sys.argv[1] if len(sys.argv) > 1 else "300,1500,3000,15000,30000").split(",")]
    runs = int(sys.argv[2]) if len(sys.argv) > 2 else 30
    out = {"hardware": info(), "runs": runs, "note": "synthetic snapshots, analysis only", "scales": []}
    for n in scales:
        scan = synth(n)
        objs = sum(len(v) for v in scan.values())
        team_ns = [x["name"] for x in scan["namespaces"]]
        t = {k: [] for k in ("graph", "subsumption", "shadowing", "cross_domain", "total")}
        for k in range(runs + 1):                       # run 0 is a discarded warm-up
            a0 = time.perf_counter()
            mt = find_multi_team_nodes(build_full_graph(scan)); a1 = time.perf_counter()
            detect_subsumption(mt); a2 = time.perf_counter()
            detect_shadowing(scan["gatekeeper_constraints"], team_ns, scan["namespaces"]); a3 = time.perf_counter()
            detect_cross_domain(scan); a4 = time.perf_counter()
            if k == 0: continue
            for key, v in (("graph", a1 - a0), ("subsumption", a2 - a1), ("shadowing", a3 - a2),
                           ("cross_domain", a4 - a3), ("total", a4 - a0)):
                t[key].append(v)
        row = {"namespaces": n, "objects": objs, **{k: summarize(v) for k, v in t.items()}}
        out["scales"].append(row)
        print(f"{objs:>7} objects  total {row['total']['median_ms']} ms [IQR {row['total']['q1_ms']}-{row['total']['q3_ms']}]"
              f" | graph {row['graph']['median_ms']} subs {row['subsumption']['median_ms']}"
              f" shad {row['shadowing']['median_ms']} xdom {row['cross_domain']['median_ms']}")
    if len(out["scales"]) >= 3:
        xs = [r["objects"] for r in out["scales"]]
        out["loglog_slope"] = {k: round(slope(xs, [r[k]["median_ms"] for r in out["scales"]]), 2)
                               for k in ("graph", "subsumption", "shadowing", "cross_domain", "total")}
        print("log-log slope of time vs objects:", out["loglog_slope"])
    json.dump(out, open("tests/bench_analysis.json", "w"), indent=2)
