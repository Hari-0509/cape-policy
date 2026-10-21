import sys, yaml
sys.path.insert(0, "src"); sys.path.insert(0, ".")
from testgen.offline_eval import docs_to_scan, cfg_full, load_cases
wrong = 0
for path, _, expected in load_cases("independent"):
    scan, tns, ans = docs_to_scan([d for d in yaml.safe_load_all(open(path)) if d])
    got = cfg_full(scan, tns, ans)
    if got != expected:
        wrong += 1
        print(f"MISS {path}: expected {sorted(expected) or 'none'}, got {sorted(got) or 'none'}")
print(f"{wrong} case(s) wrong")
