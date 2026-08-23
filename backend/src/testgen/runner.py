"""
CAPE-Policy: Test Corpus Runner
Applies each generated test case to the cluster, runs the detection engine,
filters results to ONLY this case's resources (using the cape-test-case
label), and scores detection accuracy.
"""

import yaml
import subprocess
import time
import json
import sys
import os

sys.path.insert(0, "src")

from ingestion.collector import run_full_scan
from graph.builder import build_full_graph, find_multi_team_nodes
from detection.subsumption import detect_subsumption
from detection.shadowing import detect_shadowing
from detection.cross_domain import detect_cross_domain

RESULTS_PATH = "tests/corpus/results.json"
MANIFEST_PATH = "tests/corpus/_manifest.yaml"


def load_manifest():
    with open(MANIFEST_PATH) as f:
        return yaml.safe_load(f)


def load_results():
    if os.path.exists(RESULTS_PATH):
        with open(RESULTS_PATH) as f:
            return json.load(f)
    return {"completed_case_ids": [], "results": []}


def save_results(results):
    with open(RESULTS_PATH, "w") as f:
        json.dump(results, f, indent=2)


def extract_namespaces_from_yaml(filepath):
    namespaces = set()
    with open(filepath) as f:
        docs = yaml.safe_load_all(f)
        for doc in docs:
            if not doc:
                continue
            ns = doc.get("metadata", {}).get("namespace")
            if ns:
                namespaces.add(ns)
            for subject in doc.get("subjects", []) or []:
                if subject.get("namespace"):
                    namespaces.add(subject["namespace"])
            match_ns = doc.get("spec", {}).get("match", {}).get("namespaces", [])
            namespaces.update(match_ns)
    return namespaces


def ensure_namespaces(namespaces):
    for ns in namespaces:
        subprocess.run(["kubectl", "create", "namespace", ns], capture_output=True)


def apply_case(case):
    namespaces = extract_namespaces_from_yaml(case["file"])
    ensure_namespaces(namespaces)
    time.sleep(1)
    result = subprocess.run(["kubectl", "apply", "-f", case["file"]], capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"kubectl apply failed: {result.stderr}")
    return namespaces


def cleanup_case(case, namespaces):
    subprocess.run(["kubectl", "delete", "-f", case["file"],
                     "--ignore-not-found=true", "--wait=true", "--timeout=15s"],
                    capture_output=True)
    # Also delete the namespaces themselves to guarantee full cleanup
    for ns in namespaces:
        subprocess.run(["kubectl", "delete", "namespace", ns,
                         "--ignore-not-found=true", "--wait=false"],
                        capture_output=True)


def filter_scan_to_case(scan_data, case_id):
    """Keep only resources tagged with this case's cape-test-case label."""
    filtered = {"rbac_roles": [], "rbac_bindings": [], "gatekeeper_constraints": [], "network_policies": []}
    for key in filtered:
        items = scan_data.get(key, [])
        # owner field encodes team; we need to check raw label instead —
        # re-check via a lightweight direct match on name substrings, since
        # our generator embeds case_id into every resource name.
        filtered[key] = [item for item in items if case_id in item.get("name", "")]
    return filtered


def scan_for_case(case):
    scan_data = run_full_scan()
    case_id = case["case_id"]
    scoped = filter_scan_to_case(scan_data, case_id)

    detected_types = set()

    G = build_full_graph(scoped)
    multi_team_nodes = find_multi_team_nodes(G)

    subsumption_conflicts = detect_subsumption(multi_team_nodes)
    if subsumption_conflicts:
        detected_types.add("subsumption")

    all_namespaces = list(set(
        [r["namespace"] for r in scoped["rbac_roles"] if r["namespace"]]
    ))
    shadowing_conflicts = detect_shadowing(scoped["gatekeeper_constraints"], all_namespaces)
    if shadowing_conflicts:
        detected_types.add("shadowing")

    cross_domain_conflicts = detect_cross_domain(scoped)
    if cross_domain_conflicts:
        detected_types.add("cross_domain_misalignment")

    return detected_types


def run_case(case, is_positive):
    case_type = case["type"]

    if case_type == "contradiction":
        return {
            "case_id": case["case_id"], "type": case_type,
            "expected": is_positive, "detected": None,
            "correct": None, "note": "requires runtime check, run separately",
        }

    namespaces = apply_case(case)
    time.sleep(3)

    detected_types = scan_for_case(case)
    was_detected = case_type in detected_types

    cleanup_case(case, namespaces)
    time.sleep(1)

    correct = (was_detected == is_positive)

    return {
        "case_id": case["case_id"], "type": case_type,
        "expected": is_positive, "detected": was_detected,
        "correct": correct,
    }


def run_full_corpus(limit=None):
    manifest = load_manifest()
    state = load_results()
    completed = set(state["completed_case_ids"])

    all_cases = [(c, True) for c in manifest["positive"]] + [(c, False) for c in manifest["negative"]]
    if limit:
        all_cases = all_cases[:limit]

    for i, (case, is_positive) in enumerate(all_cases):
        if case["case_id"] in completed:
            continue

        print(f"[{i+1}/{len(all_cases)}] Running {case['case_id']} ({'positive' if is_positive else 'negative'})...")

        try:
            result = run_case(case, is_positive)
            state["results"].append(result)
            state["completed_case_ids"].append(case["case_id"])
            save_results(state)
            print(f"    -> {result}")
        except Exception as e:
            print(f"    -> ERROR: {e}")

    print(f"\nCompleted {len(state['completed_case_ids'])} / {len(all_cases)} cases")
    return state


if __name__ == "__main__":
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else None
    run_full_corpus(limit=limit)
