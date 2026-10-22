"""Collection-only timing against the current kube context.
Usage: python src/testgen/bench_collect.py <runs> <n_pairs,n_pairs,...>"""
import sys, time, json, random, subprocess, statistics as st
sys.path.insert(0, "src"); sys.path.insert(0, ".")
from testgen.scalability_test import generate_bulk_policies, apply_bulk, cleanup_bulk
from ingestion.collector import run_full_scan
from testgen.hw import info

random.seed(1)
runs = int(sys.argv[1]); scales = [int(x) for x in sys.argv[2].split(",")]
ctx = subprocess.run(["kubectl", "config", "current-context"], capture_output=True, text=True).stdout.strip()
out = {"hardware_of_analyzer": info(), "kube_context": ctx, "runs": runs, "scales": []}
for n in scales:
    prefix = f"bench-{n}-run"
    fp = apply_bulk(generate_bulk_policies(n, namespace_prefix=prefix))
    time.sleep(5)
    run_full_scan()                                      # warm-up, discarded
    times, objs = [], 0
    for _ in range(runs):
        t = time.perf_counter(); scan = run_full_scan(); times.append(time.perf_counter() - t)
        objs = sum(len(v) for v in scan.values())
    q = st.quantiles(times, n=4)
    row = {"n_pairs": n, "objects_in_cluster": objs, "median_ms": round(st.median(times) * 1000, 1),
           "q1_ms": round(q[0] * 1000, 1), "q3_ms": round(q[2] * 1000, 1)}
    out["scales"].append(row); print(row)
    cleanup_bulk(fp, namespace_prefix=prefix + "-"); time.sleep(5)
json.dump(out, open("tests/bench_collect.json", "w"), indent=2)
