import sys, time, json, os, platform, statistics as st
sys.path.insert(0, "src"); sys.path.insert(0, ".")
from testgen.scalability_test import generate_bulk_policies, apply_bulk, cleanup_bulk, time_full_scan

RUNS = int(sys.argv[1]) if len(sys.argv) > 1 else 30


def ram_gb():
    for line in open("/proc/meminfo"):
        if line.startswith("MemTotal"):
            return round(int(line.split()[1]) / 1024 / 1024, 1)


def summ(v):
    return {"mean_ms": round(st.mean(v) * 1000, 1), "std_ms": round(st.stdev(v) * 1000, 1),
            "min_ms": round(min(v) * 1000, 1), "max_ms": round(max(v) * 1000, 1)}


res = {"hardware": {"platform": platform.platform(), "cpu_threads": os.cpu_count(),
                    "ram_gb": ram_gb(), "python": platform.python_version()},
       "runs_per_scale": RUNS, "scales": []}
for n in (10, 25, 50, 100, 200):
    prefix = f"scale-{n}-run"
    fp = apply_bulk(generate_bulk_policies(n, namespace_prefix=prefix))
    time.sleep(5)
    time_full_scan()  # warm-up run, discarded
    t = [time_full_scan() for _ in range(RUNS)]
    row = {"n_pairs": n, "policies": t[0]["policy_count"],
           "total": summ([x["total_seconds"] for x in t]),
           "ingestion": summ([x["ingestion_seconds"] for x in t]),
           "graph": summ([x["graph_build_seconds"] for x in t]),
           "detection": summ([x["detection_seconds"] for x in t])}
    res["scales"].append(row)
    print(f"{row['policies']:>4} policies: total {row['total']['mean_ms']} +/- {row['total']['std_ms']} ms")
    cleanup_bulk(fp, namespace_prefix=prefix + "-")
    time.sleep(3)
json.dump(res, open("tests/corpus/timing_repeated.json", "w"), indent=2)
print(res["hardware"])
