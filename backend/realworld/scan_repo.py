"""Offline scan of a cloned repo. Owner = top-level directory (our assumption, state it in the paper)."""
import sys, os, yaml, json
sys.path.insert(0, "src"); sys.path.insert(0, ".")
from testgen import offline_eval as oe
from graph.builder import build_full_graph, find_multi_team_nodes
from detection.subsumption import detect_subsumption
from detection.shadowing import detect_shadowing

root = sys.argv[1]
docs = []
for dp, _, fs in os.walk(root):
    if "/.git" in dp: continue
    for fn in fs:
        if not fn.endswith((".yaml", ".yml")): continue
        p = os.path.join(dp, fn); rel = os.path.relpath(p, root)
        owner = rel.split(os.sep)[0] if os.sep in rel else "root"
        try:
            txt = open(p, encoding="utf-8").read()
            if "{{" in txt: continue            # skip Helm templates
            for d in yaml.safe_load_all(txt):
                if isinstance(d, dict) and d.get("kind"):
                    d.setdefault("metadata", {}).setdefault("labels", {}).setdefault("owner-team", owner)
                    docs.append(d)
        except Exception:
            pass
names = {d["metadata"]["name"] for d in docs if d.get("kind") == "Namespace"}
for n in names:
    for d in docs:
        if d.get("kind") == "Namespace" and d["metadata"]["name"] == n:
            d["metadata"].setdefault("labels", {}).setdefault("cape-policy/class", "application")
scan, tns, ans = oe.docs_to_scan(docs)
sub = detect_subsumption(find_multi_team_nodes(build_full_graph(scan)))
shd = detect_shadowing(scan["gatekeeper_constraints"], tns, scan["namespaces"])
print(f"{root}: objects={len(docs)} namespaces={len(ans)} owners={len({d['metadata']['labels']['owner-team'] for d in docs})}")
print(f"  subsumption={len(sub)} shadowing={len(shd)}")
json.dump(sub + shd, open(f"realworld/findings_{os.path.basename(root.rstrip('/'))}.json", "w"), indent=1, default=str)
