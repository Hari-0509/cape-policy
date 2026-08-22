"""
CAPE-Policy: Policy Ingestion Module
Pulls RBAC, NetworkPolicy, and Gatekeeper/Kyverno policies from the cluster,
tagged with ownership metadata.
"""

from kubernetes import client, config
import json


def load_cluster():
    """Connect to the currently active kubeconfig context."""
    config.load_kube_config()


def get_rbac_roles():
    """Pull all Roles across all namespaces, with owner-team label if present."""
    rbac_api = client.RbacAuthorizationV1Api()
    roles = rbac_api.list_role_for_all_namespaces()

    results = []
    for role in roles.items:
        labels = role.metadata.labels or {}
        results.append({
            "type": "RBAC-Role",
            "name": role.metadata.name,
            "namespace": role.metadata.namespace,
            "owner": labels.get("owner-team", "unknown"),
            "managed": labels.get("cape-policy/managed", "false"),
            "rules": [
                {
                    "resources": rule.resources,
                    "verbs": rule.verbs,
                    "apiGroups": rule.api_groups,
                }
                for rule in (role.rules or [])
            ],
        })
    return results


def get_rbac_bindings():
    """Pull all RoleBindings across all namespaces."""
    rbac_api = client.RbacAuthorizationV1Api()
    bindings = rbac_api.list_role_binding_for_all_namespaces()

    results = []
    for binding in bindings.items:
        labels = binding.metadata.labels or {}
        results.append({
            "type": "RBAC-RoleBinding",
            "name": binding.metadata.name,
            "namespace": binding.metadata.namespace,
            "owner": labels.get("owner-team", "unknown"),
            "role_ref": binding.role_ref.name,
            "subjects": [
                {"kind": s.kind, "name": s.name, "namespace": s.namespace}
                for s in (binding.subjects or [])
            ],
        })
    return results


def get_gatekeeper_constraints():
    """Pull all K8sAllowedRepos constraints (Gatekeeper CRD) across the cluster."""
    custom_api = client.CustomObjectsApi()
    try:
        constraints = custom_api.list_cluster_custom_object(
            group="constraints.gatekeeper.sh",
            version="v1beta1",
            plural="k8sallowedrepos",
        )
    except client.exceptions.ApiException as e:
        print(f"Warning: could not fetch Gatekeeper constraints: {e}")
        return []

    results = []
    for item in constraints.get("items", []):
        metadata = item.get("metadata", {})
        labels = metadata.get("labels", {})
        spec = item.get("spec", {})
        results.append({
            "type": "Gatekeeper-K8sAllowedRepos",
            "name": metadata.get("name"),
            "owner": labels.get("owner-team", "unknown"),
            "managed": labels.get("cape-policy/managed", "false"),
            "match_namespaces": spec.get("match", {}).get("namespaces", []),
            "allowed_repos": spec.get("parameters", {}).get("repos", []),
        })
    return results


def run_full_scan():
    """Run the full ingestion pass and return everything collected."""
    load_cluster()

    data = {
        "rbac_roles": get_rbac_roles(),
        "rbac_bindings": get_rbac_bindings(),
        "gatekeeper_constraints": get_gatekeeper_constraints(),
    }
    return data


if __name__ == "__main__":
    result = run_full_scan()
    print(json.dumps(result, indent=2))
