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
    cross_ns_grants = get_cross_namespace_rbac_grants(
        scan_data["rbac_roles"], scan_data["rbac_bindings"]
    )

    target_namespaces = list(set(g["target_namespace"] for g in cross_ns_grants))
    deny_policies = get_default_deny_netpols(target_namespaces)

    conflicts = []
    for grant in cross_ns_grants:
        ns = grant["target_namespace"]
        if ns in deny_policies:
            deny = deny_policies[ns]
            if deny["owner"] == grant["granting_role_owner"]:
                continue

            # Cross-domain confidence: this is inherently a "both sides are
            # individually reasonable" conflict, since RBAC and NetworkPolicy
            # are evaluated by completely independent systems that were never
            # designed to be consistency-checked against each other. Neither
            # policy is more "at fault" in a temporal sense — the conflict is
            # structural, not a mistake by whoever acted later. We reflect this
            # with a fixed, moderate confidence and explicitly note the shared
            # responsibility in the reasoning, rather than forcing a single
            # named "culprit" the way subsumption/shadowing do.
            confidence = 0.55

            conflicts.append({
                "conflict_type": "cross_domain_misalignment",
                "rbac_grant": grant["granting_role"],
                "rbac_owner": grant["granting_role_owner"],
                "netpol_name": deny["policy_name"],
                "netpol_owner": deny["owner"],
                "affected_namespace": ns,
                "affected_subject": f"{grant['subject_namespace']}/{grant['subject_name']}",
                "explanation": (
                    f"Team '{grant['granting_role_owner']}' granted RBAC access "
                    f"(role '{grant['granting_role']}') for "
                    f"'{grant['subject_namespace']}/{grant['subject_name']}' to act in "
                    f"namespace '{ns}'. However, team '{deny['owner']}' has a "
                    f"default-deny NetworkPolicy ('{deny['policy_name']}') in that "
                    f"same namespace. RBAC authorization will succeed, but any "
                    f"actual network traffic will be silently dropped at the "
                    f"network layer."
                ),
                "at_fault_team": "cross-team coordination gap "
                                  f"({grant['granting_role_owner']} + {deny['owner']})",
                "severity": "medium",
                "formal_attribution": {
                    "at_fault_owner": f"joint: {grant['granting_role_owner']} + {deny['owner']}",
                    "confidence_score": confidence,
                    "confidence_label": confidence_label(confidence),
                    "reasoning": (
                        f"This is a structural cross-layer conflict between independently "
                        f"evaluated systems (RBAC and NetworkPolicy), not a timing-based "
                        f"fault. Neither '{grant['granting_role_owner']}' nor '{deny['owner']}' "
                        f"acted incorrectly in isolation; responsibility is shared and "
                        f"resolution requires coordination between both teams."
                    ),
                },
            })

    return conflicts


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
