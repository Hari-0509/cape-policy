"""Offline scoring of the static detectors (no cluster). Configurations:
  full | no_wildcard_expansion | no_class_filter | crossdomain_any_netpol  (ablations)
  b1_same_subject | b2_any_explicit_ns | b3_any_cross_ns_grant            (naive baselines)
Usage: python src/testgen/offline_eval.py            # generated corpus
       python src/testgen/offline_eval.py independent  # tests/independent + labels.csv"""
import sys, glob, os, csv, json, yaml
sys.path.insert(0, "src"); sys.path.insert(0, ".")
from graph import builder
from detection.subsumption import detect_subsumption
from detection.shadowing import detect_shadowing
from detection.cross_domain import get_cross_namespace_rbac_grants

CLASS_LABEL = "cape-policy/class"
TYPES = ["subsumption", "shadowing", "cross_domain_misalignment"]


def docs_to_scan(docs):
    scan = {"rbac_roles": [], "rbac_bindings": [], "gatekeeper_constraints": [], "network_policies": []}
    team_ns, all_ns = [], []
    for d in docs:
        kind, md = d.get("kind"), d.get("metadata", {})
        labels = md.get("labels") or {}
        owner = labels.get("owner-team", "unknown")
        if kind == "Namespace":
            all_ns.append(md["name"])
            if labels.get(CLASS_LABEL) == "application":
                team_ns.append(md["name"])
        elif kind == "Role":
            scan["rbac_roles"].append({"name": md["name"], "namespace": md.get("namespace"), "owner": owner,
                "created_at": None, "rules": [{"resources": r.get("resources"), "verbs": r.get("verbs"),
                "apiGroups": r.get("apiGroups")} for r in d.get("rules", [])]})
        elif kind == "RoleBinding":
            scan["rbac_bindings"].append({"name": md["name"], "namespace": md.get("namespace"), "owner": owner,
                "created_at": None, "role_ref": d["roleRef"]["name"],
                "subjects": [{"kind": s["kind"], "name": s["name"], "namespace": s.get("namespace")}
                             for s in d.get("subjects", [])]})
        elif kind == "K8sAllowedRepos":
            sp = d.get("spec", {})
            scan["gatekeeper_constraints"].append({"name": md["name"], "owner": owner, "created_at": None,
                "match_namespaces": sp.get("match", {}).get("namespaces", []),
                "allowed_repos": sp.get("parameters", {}).get("repos", [])})
        elif kind == "NetworkPolicy":
            sp = d.get("spec", {})
            scan["network_policies"].append({"name": md["name"], "namespace": md.get("namespace"), "owner": owner,
                "is_default_deny": "Ingress" in sp.get("policyTypes", []) and not sp.get("ingress")})
    return scan, team_ns, all_ns


def _subsumption(scan, expand=True):
    orig = builder.expand_verbs
    if not expand:
        builder.expand_verbs = lambda v: v
    try:
        G = builder.build_full_graph(scan)
        return bool(detect_subsumption(builder.find_multi_team_nodes(G)))
    finally:
        builder.expand_verbs = orig


def _crossdomain(scan, need_deny=True):
    for g in get_cross_namespace_rbac_grants(scan["rbac_roles"], scan["rbac_bindings"]):
        nps = [n for n in scan["network_policies"]
               if n["namespace"] == g["target_namespace"] and n["owner"] != g["granting_role_owner"]]
        if (any(n["is_default_deny"] for n in nps) if need_deny else bool(nps)):
            return True
    return False


def cfg_full(scan, tns, ans, expand=True, cls=True, deny=True):
    f = set()
    if _subsumption(scan, expand): f.add("subsumption")
    if detect_shadowing(scan["gatekeeper_constraints"], tns if cls else ans): f.add("shadowing")
    if _crossdomain(scan, deny): f.add("cross_domain_misalignment")
    return f


def b1(scan, tns, ans):   # two owners hold bindings for the same subject
    seen = {}
    for b in scan["rbac_bindings"]:
        for s in b["subjects"]:
            seen.setdefault((b["namespace"], s["name"]), set()).add(b["owner"])
    return {"subsumption"} if any(len(o) > 1 for o in seen.values()) else set()


def b2(scan, tns, ans):   # any constraint with an explicit namespace list smaller than all namespaces
    return {"shadowing"} if any(0 < len(c["match_namespaces"]) < len(ans)
                                for c in scan["gatekeeper_constraints"]) else set()


def b3(scan, tns, ans):   # any cross-namespace grant at all
    return {"cross_domain_misalignment"} if get_cross_namespace_rbac_grants(
        scan["rbac_roles"], scan["rbac_bindings"]) else set()


CONFIGS = {
    "full": cfg_full,
    "no_wildcard_expansion": lambda s, t, a: cfg_full(s, t, a, expand=False),
    "no_class_filter": lambda s, t, a: cfg_full(s, t, a, cls=False),
    "crossdomain_any_netpol": lambda s, t, a: cfg_full(s, t, a, deny=False),
    "b1_same_subject": b1, "b2_any_explicit_ns": b2, "b3_any_cross_ns_grant": b3,
}


def load_cases(mode):
    cases = []
    if mode == "independent":
        for row in csv.DictReader(open("tests/independent/labels.csv")):
            exp = set() if row["expected"].strip() == "none" else {row["expected"].strip()}
            cases.append((row["file"], "independent", exp))
    else:
        m = yaml.safe_load(open("tests/corpus/_manifest.yaml"))
        for grp, pos in (("positive", True), ("negative", False)):
            for c in m[grp]:
                if c["type"] in TYPES:
                    cases.append((c["file"], c["type"], {c["type"]} if pos else set()))
    return cases


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "generated"
    cases, out = load_cases(mode), {}
    for name, fn in CONFIGS.items():
        by = {}
        for path, ctype, expected in cases:
            scan, tns, ans = docs_to_scan([d for d in yaml.safe_load_all(open(path)) if d])
            ok = fn(scan, tns, ans) == expected
            d = by.setdefault(ctype, [0, 0]); d[0] += ok; d[1] += 1
        out[name] = by
    cols = sorted({t for by in out.values() for t in by})
    print(f"{'config':<26}" + "".join(f"{c[:14]:>16}" for c in cols) + f"{'overall':>10}")
    for name, by in out.items():
        ok, n = sum(v[0] for v in by.values()), sum(v[1] for v in by.values())
        print(f"{name:<26}" + "".join(f"{by[c][0]}/{by[c][1]:>11}" for c in cols) + f"{ok}/{n:>6}")
    json.dump(out, open(f"tests/offline_eval_{mode}.json", "w"), indent=2)


if __name__ == "__main__":
    main()
