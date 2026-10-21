import csv, yaml, os, collections
OK_KINDS = {"Namespace", "Role", "RoleBinding", "ServiceAccount", "K8sAllowedRepos", "NetworkPolicy"}
OK_EXP = {"subsumption", "shadowing", "cross_domain_misalignment", "none"}
rows = list(csv.DictReader(open("tests/independent/labels.csv")))
problems, count = [], collections.Counter()
for r in rows:
    f, e = r["file"].strip(), r["expected"].strip()
    count[e] += 1
    if e not in OK_EXP: problems.append(f"{f}: bad expected '{e}'")
    if not os.path.exists(f): problems.append(f"{f}: file missing"); continue
    try:
        docs = [d for d in yaml.safe_load_all(open(f)) if d]
    except Exception as ex:
        problems.append(f"{f}: YAML error {ex}"); continue
    for d in docs:
        k = d.get("kind")
        if k not in OK_KINDS: problems.append(f"{f}: kind {k} not allowed")
        elif k != "Namespace" and "owner-team" not in (d.get("metadata", {}).get("labels") or {}):
            problems.append(f"{f}: {k} missing owner-team label")
print("cases:", len(rows), dict(count))
print("PROBLEMS:" if problems else "no problems found")
for p in problems: print(" -", p)
