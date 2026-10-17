"""
CAPE-Policy: Cross-Domain Misalignment Detector
Detects when RBAC grants access that a NetworkPolicy silently blocks at
the network layer. Now attaches a confidence-scored attribution decision.
"""

import json
import sys
from kubernetes import client, config

sys.path.insert(0, "src")
sys.path.insert(0, ".")

from attribution.attribution import confidence_label


def get_cross_namespace_rbac_grants(roles, bindings):
    role_index = {(r["namespace"], r["name"]): r for r in roles}
    cross_ns_grants = []

    for binding in bindings:
        role_key = (binding["namespace"], binding["role_ref"])
        role = role_index.get(role_key)
        if not role:
            continue

        for subject in binding["subjects"]:
            if subject.get("namespace") and subject["namespace"] != binding["namespace"]:
                cross_ns_grants.append({
                    "granting_role": role["name"],
                    "granting_role_owner": binding["owner"],
                    "target_namespace": binding["namespace"],
                    "subject_namespace": subject["namespace"],
                    "subject_name": subject["name"],
                })

    return cross_ns_grants


def get_default_deny_netpols(target_namespaces):
    config.load_kube_config()
    net_api = client.NetworkingV1Api()

    deny_policies = {}
    for ns in target_namespaces:
        policies = net_api.list_namespaced_network_policy(ns)
        for policy in policies.items:
            spec = policy.spec
            is_default_deny = (
                "Ingress" in (spec.policy_types or [])
                and not spec.ingress
            )
            if is_default_deny:
                labels = policy.metadata.labels or {}
                deny_policies[ns] = {
                    "policy_name": policy.metadata.name,
                    "owner": labels.get("owner-team", "unknown"),
                }
    return deny_policies


def detect_cross_domain(scan_data):
    grants = get_cross_namespace_rbac_grants(scan_data["rbac_roles"], scan_data["rbac_bindings"])
    deny_policies = get_default_deny_netpols(list(set(g["target_namespace"] for g in grants)))
    found = []
    for g in grants:
        ns = g["target_namespace"]
        deny = deny_policies.get(ns)
        if not deny or deny["owner"] == g["granting_role_owner"]:
            continue
        conf = 0.55
        found.append({
            "conflict_type": "cross_domain_misalignment",
            "finding_status": "advisory (review needed)",
            "rbac_grant": g["granting_role"],
            "rbac_owner": g["granting_role_owner"],
            "netpol_name": deny["policy_name"],
            "netpol_owner": deny["owner"],
            "affected_namespace": ns,
            "affected_subject": f"{g['subject_namespace']}/{g['subject_name']}",
            "explanation": (
                f"Team '{g['granting_role_owner']}' granted RBAC access (role '{g['granting_role']}') in "
                f"namespace '{ns}' to '{g['subject_namespace']}/{g['subject_name']}'. Team '{deny['owner']}' "
                f"applies default-deny ingress ('{deny['policy_name']}') in the same namespace. RBAC governs "
                f"Kubernetes API calls and NetworkPolicy governs pod-to-pod traffic, so these are different "
                f"properties and not a direct contradiction. If this subject also needs network access to "
                f"pods in '{ns}', the default-deny policy may block it. Review."
            ),
            "at_fault_team": f"shared: {g['granting_role_owner']} and {deny['owner']}",
            "severity": "low",
            "formal_attribution": {
                "at_fault_owner": f"joint: {g['granting_role_owner']} + {deny['owner']}",
                "confidence_score": conf,
                "confidence_label": confidence_label(conf),
                "reasoning": ("Two independently evaluated mechanisms written by different teams; "
                              "neither policy is wrong alone, so no single owner is named."),
            },
        })
    return found

if __name__ == "__main__":
    with open("data/latest_scan.json") as f:
        scan_data = json.load(f)

    conflicts = detect_cross_domain(scan_data)
    print(f"Cross-domain misalignment conflicts found: {len(conflicts)}\n")
    for c in conflicts:
        print(f"--- CONFLICT: {c['conflict_type'].upper()} ---")
        print(f"At fault: {c['at_fault_team']}")
        print(f"Confidence: {c['formal_attribution']['confidence_label']} ({c['formal_attribution']['confidence_score']})")
        print(f"Reasoning: {c['formal_attribution']['reasoning']}")
        print()
