import json, csv, random, collections
random.seed(20261018)
rep = json.load(open("data/conflict_report.json"))
def owners(f):
    t = f["conflict_type"]
    if t == "subsumption": return {f["narrow_policy"]["owner"], f["overriding_policy"]["owner"]}
    if t == "cross_domain_misalignment": return {f["rbac_owner"], f["netpol_owner"]}
    return {f.get("owner") or "unknown"}
keep = [f for f in rep if "unknown" not in owners(f)]
print(f"{len(rep)} findings, {len(rep) - len(keep)} dropped for unknown owner (reported separately)")
by = collections.defaultdict(list)
for f in keep: by[f["conflict_type"]].append(f)
rows, i = [], 0
for cat, fs in by.items():
    for f in (fs if len(fs) <= 50 else random.sample(fs, 50)):
        i += 1
        rows.append({"id": i, "category": cat, "status": f["finding_status"], "owners": "|".join(sorted(owners(f))),
                     "explanation": f["explanation"], "label1": "", "label2": "", "final": ""})
    print(cat, "total", len(fs), "labeled", min(len(fs), 50))
with open("realworld/findings_to_label.csv", "w", newline="") as fh:
    w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()) if rows else ["id"]); w.writeheader(); w.writerows(rows)
