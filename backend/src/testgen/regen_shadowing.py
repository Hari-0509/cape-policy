import sys, random, yaml
sys.path.insert(0, "src")
from testgen.generator import TEAMS

CLASS_LABEL = "cape-policy/class"
MANIFEST = "tests/corpus/_manifest.yaml"


def ns_doc(name, cls):
    return {"apiVersion": "v1", "kind": "Namespace",
            "metadata": {"name": name, "labels": {CLASS_LABEL: cls}}}


def constraint_doc(cid, team, covered):
    return {"apiVersion": "constraints.gatekeeper.sh/v1beta1", "kind": "K8sAllowedRepos",
            "metadata": {"name": f"img-policy-{cid}", "labels": {"owner-team": team, "cape-test-case": cid}},
            "spec": {"match": {"kinds": [{"apiGroups": [""], "kinds": ["Pod"]}], "namespaces": covered},
                     "parameters": {"repos": ["mycompany.com/"]}}}


m = yaml.safe_load(open(MANIFEST))
n = 0
for group in ("positive", "negative"):
    idx = 0
    for case in m[group]:
        if case["type"] != "shadowing":
            continue
        cid = case["case_id"]
        team = random.choice(TEAMS)
        names = [f"shadow-ns-{cid}-{j}" for j in range(3)]
        if group == "positive":
            classes = {nm: "application" for nm in names}
            covered, sub = [names[0]], "gap"
        elif idx < 7:
            classes = {nm: "application" for nm in names}
            covered, sub = names, "full-coverage"
        else:
            classes = {names[0]: "application", names[1]: "system", names[2]: "system"}
            covered, sub = [names[0]], "class-exclusion"
        if group == "negative":
            idx += 1
        docs = [ns_doc(nm, classes[nm]) for nm in names] + [constraint_doc(cid, team, covered)]
        with open(case["file"], "w") as f:
            yaml.dump_all(docs, f)
        case.update({"all_namespaces": names, "ns_classes": classes, "covered": covered, "subtype": sub})
        n += 1
yaml.safe_dump(m, open(MANIFEST, "w"))
print(f"Rewrote {n} shadowing cases")
