"""
CAPE-Policy: Test Corpus Generator
Generates synthetic multi-team Kubernetes policy sets — both conflicting
(positive) and clean (negative) — for rigorous evaluation of the detection
engine's accuracy and false-positive rate.
"""

import yaml
import random
import os

TEAMS = ["team-alpha", "team-beta", "team-gamma", "team-delta", "team-epsilon"]
RESOURCES = ["pods", "deployments", "services", "configmaps", "secrets"]
VERBS_NARROW = ["get", "list"]
VERBS_BROAD = ["*"]

OUTPUT_DIR = "tests/corpus"


def make_rbac_subsumption_case(case_id, team_a, team_b, namespace, resource):
    """POSITIVE case: team_a's narrow role gets subsumed by team_b's wildcard role."""
    subject_sa = f"app-sa-{case_id}"
    docs = [
        {
            "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
            "metadata": {"name": f"narrow-role-{case_id}", "namespace": namespace,
                         "labels": {"owner-team": team_a, "cape-test-case": case_id}},
            "rules": [{"apiGroups": [""], "resources": [resource], "verbs": VERBS_NARROW}],
        },
        {
            "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
            "metadata": {"name": f"narrow-binding-{case_id}", "namespace": namespace,
                         "labels": {"owner-team": team_a, "cape-test-case": case_id}},
            "subjects": [{"kind": "ServiceAccount", "name": subject_sa, "namespace": namespace}],
            "roleRef": {"kind": "Role", "name": f"narrow-role-{case_id}", "apiGroup": "rbac.authorization.k8s.io"},
        },
        {
            "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
            "metadata": {"name": f"broad-role-{case_id}", "namespace": namespace,
                         "labels": {"owner-team": team_b, "cape-test-case": case_id}},
            "rules": [{"apiGroups": [""], "resources": [resource], "verbs": VERBS_BROAD}],
        },
        {
            "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
            "metadata": {"name": f"broad-binding-{case_id}", "namespace": namespace,
                         "labels": {"owner-team": team_b, "cape-test-case": case_id}},
            "subjects": [{"kind": "ServiceAccount", "name": subject_sa, "namespace": namespace}],
            "roleRef": {"kind": "Role", "name": f"broad-role-{case_id}", "apiGroup": "rbac.authorization.k8s.io"},
        },
    ]
    return docs


def make_rbac_clean_case(case_id, team_a, team_b, namespace):
    """NEGATIVE case: two teams' roles on completely different resources — no overlap, no conflict."""
    subject_a = f"app-sa-a-{case_id}"
    subject_b = f"app-sa-b-{case_id}"
    resource_a, resource_b = random.sample(RESOURCES, 2)
    docs = [
        {
            "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
            "metadata": {"name": f"clean-role-a-{case_id}", "namespace": namespace,
                         "labels": {"owner-team": team_a, "cape-test-case": case_id}},
            "rules": [{"apiGroups": [""], "resources": [resource_a], "verbs": VERBS_NARROW}],
        },
        {
            "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
            "metadata": {"name": f"clean-binding-a-{case_id}", "namespace": namespace,
                         "labels": {"owner-team": team_a, "cape-test-case": case_id}},
            "subjects": [{"kind": "ServiceAccount", "name": subject_a, "namespace": namespace}],
            "roleRef": {"kind": "Role", "name": f"clean-role-a-{case_id}", "apiGroup": "rbac.authorization.k8s.io"},
        },
        {
            "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
            "metadata": {"name": f"clean-role-b-{case_id}", "namespace": namespace,
                         "labels": {"owner-team": team_b, "cape-test-case": case_id}},
            "rules": [{"apiGroups": [""], "resources": [resource_b], "verbs": VERBS_NARROW}],
        },
        {
            "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
            "metadata": {"name": f"clean-binding-b-{case_id}", "namespace": namespace,
                         "labels": {"owner-team": team_b, "cape-test-case": case_id}},
            "subjects": [{"kind": "ServiceAccount", "name": subject_b, "namespace": namespace}],
            "roleRef": {"kind": "Role", "name": f"clean-role-b-{case_id}", "apiGroup": "rbac.authorization.k8s.io"},
        },
    ]
    return docs


def make_gatekeeper_shadowing_case(case_id, team_a, covered_namespaces, all_namespaces):
    """POSITIVE case: image policy only covers some namespaces, leaving others exposed."""
    return [{
        "apiVersion": "constraints.gatekeeper.sh/v1beta1", "kind": "K8sAllowedRepos",
        "metadata": {"name": f"img-policy-{case_id}",
                     "labels": {"owner-team": team_a, "cape-test-case": case_id}},
        "spec": {
            "match": {"kinds": [{"apiGroups": [""], "kinds": ["Pod"]}], "namespaces": covered_namespaces},
            "parameters": {"repos": ["mycompany.com/"]},
        },
    }]


def make_gatekeeper_clean_case(case_id, team_a, all_namespaces):
    """NEGATIVE case: image policy correctly covers ALL relevant namespaces — no gap."""
    return [{
        "apiVersion": "constraints.gatekeeper.sh/v1beta1", "kind": "K8sAllowedRepos",
        "metadata": {"name": f"img-policy-clean-{case_id}",
                     "labels": {"owner-team": team_a, "cape-test-case": case_id}},
        "spec": {
            "match": {"kinds": [{"apiGroups": [""], "kinds": ["Pod"]}], "namespaces": all_namespaces},
            "parameters": {"repos": ["mycompany.com/"]},
        },
    }]


def generate_corpus(n_positive_per_type=8, n_negative_per_type=8):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    manifest = {"positive": [], "negative": []}

    # --- Subsumption: positive + negative ---
    for i in range(n_positive_per_type):
        case_id = f"subsumption-pos-{i:03d}"
        team_a, team_b = random.sample(TEAMS, 2)
        ns = f"ns-{case_id}"
        resource = random.choice(RESOURCES)
        docs = make_rbac_subsumption_case(case_id, team_a, team_b, ns, resource)
        path = os.path.join(OUTPUT_DIR, f"{case_id}.yaml")
        with open(path, "w") as f:
            yaml.dump_all(docs, f)
        manifest["positive"].append({"case_id": case_id, "type": "subsumption", "namespace": ns, "file": path})

    for i in range(n_negative_per_type):
        case_id = f"subsumption-neg-{i:03d}"
        team_a, team_b = random.sample(TEAMS, 2)
        ns = f"ns-{case_id}"
        docs = make_rbac_clean_case(case_id, team_a, team_b, ns)
        path = os.path.join(OUTPUT_DIR, f"{case_id}.yaml")
        with open(path, "w") as f:
            yaml.dump_all(docs, f)
        manifest["negative"].append({"case_id": case_id, "type": "subsumption", "namespace": ns, "file": path})

    # --- Shadowing: positive + negative ---
    for i in range(n_positive_per_type):
        case_id = f"shadowing-pos-{i:03d}"
        team_a = random.choice(TEAMS)
        all_ns = [f"shadow-ns-{case_id}-{j}" for j in range(3)]
        covered = all_ns[:1]  # only covers 1 of 3 — gap exists
        docs = make_gatekeeper_shadowing_case(case_id, team_a, covered, all_ns)
        path = os.path.join(OUTPUT_DIR, f"{case_id}.yaml")
        with open(path, "w") as f:
            yaml.dump_all(docs, f)
        manifest["positive"].append({"case_id": case_id, "type": "shadowing",
                                       "all_namespaces": all_ns, "covered": covered, "file": path})

    for i in range(n_negative_per_type):
        case_id = f"shadowing-neg-{i:03d}"
        team_a = random.choice(TEAMS)
        all_ns = [f"shadow-ns-{case_id}-{j}" for j in range(3)]
        docs = make_gatekeeper_clean_case(case_id, team_a, all_ns)
        path = os.path.join(OUTPUT_DIR, f"{case_id}.yaml")
        with open(path, "w") as f:
            yaml.dump_all(docs, f)
        manifest["negative"].append({"case_id": case_id, "type": "shadowing",
                                       "all_namespaces": all_ns, "file": path})

    # Save manifest for the test runner to use
    with open(os.path.join(OUTPUT_DIR, "_manifest.yaml"), "w") as f:
        yaml.dump(manifest, f)

    print(f"Generated {len(manifest['positive'])} positive cases")
    print(f"Generated {len(manifest['negative'])} negative cases")
    print(f"Manifest saved to {OUTPUT_DIR}/_manifest.yaml")
    return manifest


if __name__ == "__main__":
    generate_corpus(n_positive_per_type=8, n_negative_per_type=8)
