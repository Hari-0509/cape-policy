import os, re, sys, csv, json, yaml, collections
sys.path.insert(0, "src"); sys.path.insert(0, ".")
from testgen import offline_eval as oe

mode = sys.argv[1] if len(sys.argv) > 1 else "independent"


def objects_of(path):
    out = {}
    for d in yaml.safe_load_all(open(path)):
        if d and d.get("kind") in ("Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding", "K8sAllowedRepos", "NetworkPolicy"):
            md = d.get("metadata", {})
            out[md["name"]] = (md.get("labels") or {}).get("owner-team", "unknown")
    return out


def strings(text):
    try:
        def walk(x):
            if isinstance(x, dict):
                for v in x.values(): yield from walk(v)
            elif isinstance(x, list):
                for v in x: yield from walk(v)
            elif isinstance(x, str): yield x
        yield from walk(json.loads(text[:text.rindex("}") + 1] if "}" in text else text))
    except Exception:
        yield from text.splitlines()


res, cands = collections.defaultdict(lambda: collections.Counter()), []
for path, ctype, expected in oe.load_cases(mode):
    objs = objects_of(path)
    pos = bool(expected)
    cat = next(iter(expected)) if expected else "none"
    for tool in sorted(os.listdir(f"tests/baselines/raw/{mode}")):
        fp = f"tests/baselines/raw/{mode}/{tool}/{os.path.basename(path)}.txt"
        if not os.path.exists(fp): continue
        text = open(fp).read()
        obj_flag = rel = False
        for line in strings(text):
            hit = {n for n in objs if re.search(rf"(?<![\w-]){re.escape(n)}(?![\w-])", line)}
            if hit: obj_flag = True
            if len({objs[n] for n in hit}) >= 2:
                rel = True
                cands.append({"tool": tool, "case": os.path.basename(path), "expected": cat, "line": line[:300], "confirmed": ""})
                break
        key = (tool, "positive" if pos else "clean")
        res[key]["n"] += 1; res[key]["object_flag"] += obj_flag; res[key]["relation_candidate"] += rel

print(f"{'tool':<14}{'set':<10}{'n':>4}{'object-level':>14}{'relation cand.':>16}")
for (tool, grp), c in sorted(res.items()):
    print(f"{tool:<14}{grp:<10}{c['n']:>4}{c['object_flag']:>14}{c['relation_candidate']:>16}")
with open(f"tests/baselines/candidates_{mode}.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=["tool", "case", "expected", "line", "confirmed"])
    w.writeheader(); w.writerows(cands)
print(f"\n{len(cands)} candidates written to tests/baselines/candidates_{mode}.csv; mark each confirmed=Y or N by hand.")
