"""
CAPE-Policy: Contradiction Case Runner
Handles the runtime-dependent Contradiction test cases separately, since
detection requires observing an actual pod failure rather than pure
static policy analysis.
"""

import yaml
import subprocess
import time
import json
import sys
import os

sys.path.insert(0, "src")
sys.path.insert(0, ".")

from detection.contradiction import get_restrictive_fs_policies, get_crashing_pods_writing_without_volume
from kubernetes import config

RESULTS_PATH = "tests/corpus/contradiction_results.json"
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
    for ns in namespaces:
        subprocess.run(["kubectl", "delete", "namespace", ns,
                         "--ignore-not-found=true", "--wait=false"],
                        capture_output=True)


def check_contradiction_for_case(case, namespace):
    """Run the contradiction detector scoped to just this case's namespace."""
    config.load_kube_config()
    restrictive_policies = get_restrictive_fs_policies()

    # Only consider the policy belonging to this case (by namespace match)
    case_policies = [p for p in restrictive_policies if namespace in p.get("namespaces", [])]
    if not case_policies:
        return False

    for policy in case_policies:
        failing_pods = get_crashing_pods_writing_without_volume([namespace])
        for fp in failing_pods:
            if fp["owner"] != policy["owner"]:
                return True
    return False


def run_case(case, is_positive, max_wait_seconds=45, poll_interval=5):
    namespaces = apply_case(case)
    namespace = list(namespaces)[0] if namespaces else None

    # Poll repeatedly instead of a single fixed wait, since CrashLoopBackOff
    # timing is inherently variable (container restart backoff intervals
    # increase over time: ~10s, 20s, 40s...). This avoids false negatives
    # from checking mid-restart.
    detected = False
    elapsed = 0
    while elapsed < max_wait_seconds:
        time.sleep(poll_interval)
        elapsed += poll_interval
        detected = check_contradiction_for_case(case, namespace)
        if detected:
            break

    cleanup_case(case, namespaces)
    time.sleep(1)

    correct = (detected == is_positive)

    return {
        "case_id": case["case_id"], "type": "contradiction",
        "expected": is_positive, "detected": detected, "correct": correct,
        "poll_time_seconds": elapsed,
    }


def run_contradiction_corpus(limit=None):
    manifest = load_manifest()
    state = load_results()
    completed = set(state["completed_case_ids"])

    contradiction_positive = [c for c in manifest["positive"] if c["type"] == "contradiction"]
    contradiction_negative = [c for c in manifest["negative"] if c["type"] == "contradiction"]
    all_cases = [(c, True) for c in contradiction_positive] + [(c, False) for c in contradiction_negative]

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
    run_contradiction_corpus(limit=limit)
