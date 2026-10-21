import json, sys, collections
scan = json.load(open(sys.argv[1] if len(sys.argv) > 1 else "data/latest_scan.json"))
skip_system = "--skip-system" in sys.argv
rows, total = collections.Counter(), 0
for key in ("rbac_roles", "rbac_bindings", "cluster_roles", "cluster_role_bindings",
            "gatekeeper_constraints", "network_policies"):
    for r in scan.get(key, []):
        if skip_system and (str(r.get("name", "")).startswith("system:") or r.get("namespace") in ("kube-system", "kube-public")):
            continue
        rows[r.get("owner_source")] += 1; total += 1
print(f"objects counted: {total}")
for src, n in rows.most_common():
    print(f"  {src:<24}{n:>6}  {n/total*100:5.1f}%")
