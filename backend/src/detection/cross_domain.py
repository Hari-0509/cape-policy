"""Cross-Domain (advisory): a cross-namespace RBAC grant plus a default-deny ingress
NetworkPolicy from a different team in the target namespace. Different properties
(API access vs pod traffic), so reported for review, not as a contradiction."""
import json, sys
from kubernetes import client, config

sys.path.insert(0, "src"); sys.path.insert(0, ".")
ACCEPT_KEY = "cape-policy/accepted"


def get_cross_namespace_rbac_grants(roles, bindings, cluster_roles=None):
    role_index = {(r["namespace"], r["name"]): r for r in roles}
    croles = {r["name"]: r for r in (cluster_roles or [])}
    out = []
    for b in bindings:
        role = croles.get(b["role_ref"]) if b.get("role_ref_kind") == "ClusterRole" \
            else role_index.get((b["namespace"], b["role_ref"]))
        if not role:
            continue
        for s in b["subjects"]:
            if s.get("namespace") and s["namespace"] != b["namespace"]:
                out.append({"granting_role": role["name"], "granting_role_owner": b["owner"],
                            "target_namespace": b["namespace"], "subject_namespace": s["namespace"],
                            "subject_name": s["name"],
                            "accepted_reason": b.get("accepted_reason") or role.get("accepted_reason")})
    return out


def get_default_deny_netpols(target_namespaces):
    config.load_kube_config()
    api = client.NetworkingV1Api()
    deny = {}
    for ns in target_namespaces:
        for p in api.list_namespaced_network_policy(ns).items:
            spec = p.spec
            if "Ingress" in (spec.policy_types or []) and not spec.ingress:
                deny[ns] = {"policy_name": p.metadata.name,
                            "owner": (p.metadata.labels or {}).get("owner-team", "unknown"),
                            "accepted_reason": (p.metadata.annotations or {}).get(ACCEPT_KEY)}
    return deny


def detect_cross_domain(scan_data):
    grants = get_cross_namespace_rbac_grants(scan_data["rbac_roles"], scan_data["rbac_bindings"],
                                             scan_data.get("cluster_roles"))
    deny_by_ns = get_default_deny_netpols(list({g["target_namespace"] for g in grants}))
    found = []
    for g in grants:
        ns = g["target_namespace"]
        deny = deny_by_ns.get(ns)
        if not deny or deny["owner"] == g["granting_role_owner"]:
            continue
        found.append({
            "conflict_type": "cross_domain_misalignment",
            "finding_status": "advisory (review needed)",
            "rbac_grant": g["granting_role"], "rbac_owner": g["granting_role_owner"],
            "netpol_name": deny["policy_name"], "netpol_owner": deny["owner"],
            "affected_namespace": ns,
            "affected_subject": f"{g['subject_namespace']}/{g['subject_name']}",
            "explanation": (
                f"Team '{g['granting_role_owner']}' granted RBAC access (role '{g['granting_role']}') in namespace "
                f"'{ns}' to '{g['subject_namespace']}/{g['subject_name']}'. Team '{deny['owner']}' applies default-deny "
                f"ingress ('{deny['policy_name']}') in the same namespace. RBAC governs Kubernetes API calls and "
                f"NetworkPolicy governs pod traffic, so this is not a direct contradiction. If the subject also needs "
                f"network access to pods in '{ns}', the policy may block it. Review."),
            "at_fault_team": f"shared: {g['granting_role_owner']} and {deny['owner']}",
            "severity": "low",
            "accepted_reason": g.get("accepted_reason") or deny.get("accepted_reason"),
            "formal_attribution": {
                "at_fault_owner": f"joint: {g['granting_role_owner']} + {deny['owner']}",
                "confidence_label": "Shared", "evidence": "none",
                "reasoning": "Two independently evaluated mechanisms written by different teams; no single owner is named."},
        })
    return found


if __name__ == "__main__":
    scan = json.load(open("data/latest_scan.json"))
    res = detect_cross_domain(scan)
    print(f"Cross-domain advisories: {len(res)}")
    for c in res:
        print(c["affected_subject"], "->", c["affected_namespace"], c["finding_status"])
