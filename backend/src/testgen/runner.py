"""Applies each corpus case, scopes the scan to that case, scores detection."""
import yaml, subprocess, time, json, sys, os

sys.path.insert(0, "src")
from ingestion.collector import run_full_scan
from ingestion.namespaces import get_team_namespaces
from graph.builder import build_full_graph, find_multi_team_nodes
from detection.subsumption import detect_subsumption
from detection.shadowing import detect_shadowing
from detection.cross_domain import detect_cross_domain

RESULTS_PATH = "tests/corpus/results.json"
MANIFEST_PATH = "tests/corpus/_manifest.yaml"


def load_results():
    if os.path.exists(RESULTS_PATH):
        return json.load(open(RESULTS_PATH))
    return {"completed_case_ids": [], "results": []}


def namespaces_in(filepath):
    """(all namespaces referenced, namespaces declared as Namespace objects)"""
    allns, declared = set(), set()
    for doc in yaml.safe_load_all(open(filepath)):
        if not doc:
            continue
        md = doc.get("metadata", {})
        if doc.get("kind") == "Namespace":
            declared.add(md["name"]); allns.add(md["name"])
        if md.get("namespace"):
            allns.add(md["namespace"])
        for s in doc.get("subjects", []) or []:
            if s.get("namespace"):
                allns.add(s["namespace"])
        allns.update(doc.get("spec", {}).get("match", {}).get("namespaces", []) or [])
    return allns, declared


def apply_case(case):
    allns, declared = namespaces_in(case["file"])
    for ns in allns - declared:
        subprocess.run(["kubectl", "create", "namespace", ns], capture_output=True)
    time.sleep(1)
    r = subprocess.run(["kubectl", "apply", "-f", case["file"]], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(r.stderr)
    return allns


def cleanup_case(case, allns):
    subprocess.run(["kubectl", "delete", "-f", case["file"], "--ignore-not-found=true",
                    "--wait=true", "--timeout=20s"], capture_output=True)
    for ns in allns:
        subprocess.run(["kubectl", "delete", "namespace", ns, "--ignore-not-found=true",
                        "--wait=false"], capture_output=True)


def scoped_scan(scan, case_id):
    return {k: [i for i in scan.get(k, []) if case_id in i.get("name", "")]
            for k in ("rbac_roles", "rbac_bindings", "gatekeeper_constraints", "network_policies")}


def detected_types(case):
    cid = case["case_id"]
    scoped = scoped_scan(run_full_scan(), cid)
    team_ns = [ns for ns in get_team_namespaces() if cid in ns]
    found = set()
    if detect_subsumption(find_multi_team_nodes(build_full_graph(scoped))):
        found.add("subsumption")
    if detect_shadowing(scoped["gatekeeper_constraints"], team_ns):
        found.add("shadowing")
    if detect_cross_domain(scoped):
        found.add("cross_domain_misalignment")
    return found


def run_case(case, is_positive):
    if case["type"] == "contradiction":
        return {"case_id": case["case_id"], "type": "contradiction", "expected": is_positive,
                "detected": None, "correct": None, "note": "run with contradiction_runner.py"}
    allns = apply_case(case)
    time.sleep(3)
    hit = case["type"] in detected_types(case)
    cleanup_case(case, allns)
    time.sleep(1)
    return {"case_id": case["case_id"], "type": case["type"], "expected": is_positive,
            "detected": hit, "correct": hit == is_positive, "subtype": case.get("subtype")}


def run_full_corpus(limit=None):
    m = yaml.safe_load(open(MANIFEST_PATH))
    state = load_results()
    done = set(state["completed_case_ids"])
    cases = [(c, True) for c in m["positive"]] + [(c, False) for c in m["negative"]]
    if limit:
        cases = cases[:limit]
    for i, (case, pos) in enumerate(cases):
        if case["case_id"] in done:
            continue
        print(f"[{i+1}/{len(cases)}] {case['case_id']} ({'pos' if pos else 'neg'})")
        try:
            res = run_case(case, pos)
            state["results"].append(res)
            state["completed_case_ids"].append(case["case_id"])
            json.dump(state, open(RESULTS_PATH, "w"), indent=2)
            print("   ->", res)
        except Exception as e:
            print("   -> ERROR:", e)
    print(f"\nCompleted {len(state['completed_case_ids'])} / {len(cases)}")


if __name__ == "__main__":
    run_full_corpus(int(sys.argv[1]) if len(sys.argv) > 1 else None)
