"""
CAPE-Policy: Scalability Benchmark
Measures scan time (ingestion + graph building + detection) as the number
of policies in the cluster grows, to characterize how the system performs
at increasing scale.
"""

import time
import json
import subprocess
import sys
import random

sys.path.insert(0, "src")
sys.path.insert(0, ".")

from ingestion.collector import run_full_scan
from graph.builder import build_full_graph, find_multi_team_nodes
from detection.subsumption import detect_subsumption
from detection.shadowing import detect_shadowing
from detection.cross_domain import detect_cross_domain

TEAMS = ["team-alpha", "team-beta", "team-gamma", "team-delta", "team-epsilon"]
RESOURCES = ["pods", "deployments", "services", "configmaps"]


def generate_bulk_policies(n_pairs, namespace_prefix):
    """Generate N pairs of (narrow role, broad role) RBAC bindings — half of
    them will be genuine subsumption conflicts, to keep realistic signal
    density as scale increases."""
    docs = []
    for i in range(n_pairs):
        ns = f"{namespace_prefix}-{i}"
        team_a, team_b = random.sample(TEAMS, 2)
        resource = random.choice(RESOURCES)
        sa_name = f"sa-{i}"

        docs.append({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": ns}})

        docs.append({
            "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
            "metadata": {"name": f"narrow-{i}", "namespace": ns,
                         "labels": {"owner-team": team_a}},
            "rules": [{"apiGroups": [""], "resources": [resource], "verbs": ["get", "list"]}],
        })
        docs.append({
            "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
            "metadata": {"name": f"narrow-binding-{i}", "namespace": ns,
                         "labels": {"owner-team": team_a}},
            "subjects": [{"kind": "ServiceAccount", "name": sa_name, "namespace": ns}],
            "roleRef": {"kind": "Role", "name": f"narrow-{i}", "apiGroup": "rbac.authorization.k8s.io"},
        })

        # Every other pair introduces a real conflict (50% conflict density)
        if i % 2 == 0:
            docs.append({
                "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                "metadata": {"name": f"broad-{i}", "namespace": ns,
                             "labels": {"owner-team": team_b}},
                "rules": [{"apiGroups": [""], "resources": [resource], "verbs": ["*"]}],
            })
            docs.append({
                "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                "metadata": {"name": f"broad-binding-{i}", "namespace": ns,
                             "labels": {"owner-team": team_b}},
                "subjects": [{"kind": "ServiceAccount", "name": sa_name, "namespace": ns}],
                "roleRef": {"kind": "Role", "name": f"broad-{i}", "apiGroup": "rbac.authorization.k8s.io"},
            })
    return docs


def apply_bulk(docs, filepath="tests/corpus/_scale_temp.yaml"):
    import yaml
    # Create all namespaces first, separately, and wait for them to be Active
    namespaces = [d["metadata"]["name"] for d in docs if d["kind"] == "Namespace"]
    for ns in namespaces:
        subprocess.run(["kubectl", "create", "namespace", ns], capture_output=True)
    time.sleep(3)

    # Now apply everything else (namespaces will just show "unchanged")
    with open(filepath, "w") as f:
        yaml.dump_all(docs, f)
    result = subprocess.run(["kubectl", "apply", "-f", filepath], capture_output=True, text=True)
    if result.returncode != 0:
        print(f"WARNING: apply had errors: {result.stderr[-500:]}")
    return filepath


def cleanup_bulk(filepath, namespace_prefix):
    subprocess.run(["kubectl", "delete", "-f", filepath, "--ignore-not-found=true", "--wait=false"],
                    capture_output=True)
    result = subprocess.run(["kubectl", "get", "namespaces", "-o", "name"], capture_output=True, text=True)
    for line in result.stdout.splitlines():
        if namespace_prefix in line:
            ns_name = line.split("/")[-1]
            subprocess.run(["kubectl", "delete", "namespace", ns_name, "--ignore-not-found=true", "--wait=false"],
                            capture_output=True)


def time_full_scan():
    """Time the complete pipeline: ingestion -> graph -> detection."""
    start = time.time()
    scan_data = run_full_scan()
    ingestion_time = time.time() - start

    t2 = time.time()
    G = build_full_graph(scan_data)
    multi_team_nodes = find_multi_team_nodes(G)
    graph_time = time.time() - t2

    t3 = time.time()
    conflicts = detect_subsumption(multi_team_nodes)
    detection_time = time.time() - t3

    total_time = time.time() - start

    return {
        "ingestion_seconds": round(ingestion_time, 3),
        "graph_build_seconds": round(graph_time, 3),
        "detection_seconds": round(detection_time, 3),
        "total_seconds": round(total_time, 3),
        "policy_count": len(scan_data["rbac_roles"]) + len(scan_data["rbac_bindings"]),
        "conflicts_found": len(conflicts),
    }


def run_scalability_benchmark(scale_points=(10, 25, 50, 100, 200)):
    results = []

    for n in scale_points:
        print(f"\n=== Testing scale: {n} policy pairs ===")
        docs = generate_bulk_policies(n, namespace_prefix=f"scale-{n}-run")
        filepath = apply_bulk(docs)
        print(f"Applied {n} pairs, waiting for propagation...")
        time.sleep(5)

        timing = time_full_scan()
        timing["n_pairs_requested"] = n
        results.append(timing)
        print(f"Result: {timing}")

        cleanup_bulk(filepath, namespace_prefix=f"scale-{n}-run-")
        time.sleep(3)

    with open("tests/corpus/scalability_results.json", "w") as f:
        json.dump(results, f, indent=2)

    print("\n\n=== SCALABILITY SUMMARY ===")
    print(f"{'N pairs':<10} {'Policies':<10} {'Total time (s)':<15} {'Conflicts':<10}")
    for r in results:
        print(f"{r['n_pairs_requested']:<10} {r['policy_count']:<10} {r['total_seconds']:<15} {r['conflicts_found']:<10}")

    return results


if __name__ == "__main__":
    run_scalability_benchmark()
