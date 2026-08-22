"""
CAPE-Policy: Policy Ingestion Module
Pulls RBAC, NetworkPolicy, and Gatekeeper/Kyverno policies from the cluster,
tagged with ownership metadata, creation timestamps, and fallback attribution
sources (GitOps tracking ID, Helm release, last-applied-configuration).
"""

from kubernetes import client, config
import json


def load_cluster():
    config.load_kube_config()


def resolve_owner(labels, annotations):
    """
    Resolve the owning team using a fallback chain:
    1. Explicit owner-team label (best case)
    2. ArgoCD tracking-id annotation (GitOps-managed resources)
    3. Helm release name annotation (Helm-managed resources)
    4. 'unknown' if nothing is found
    """
    labels = labels or {}
    annotations = annotations or {}

    if "owner-team" in labels:
        return labels["owner-team"], "explicit-label"

    if "argocd.argoproj.io/tracking-id" in annotations:
        tracking_id = annotations["argocd.argoproj.io/tracking-id"]
        return f"gitops:{tracking_id}", "argocd-tracking-id"

    if "meta.helm.sh/release-name" in annotations:
        release = annotations["meta.helm.sh/release-name"]
        return f"helm-release:{release}", "helm-release-name"

    return "unknown", "no-attribution-source"


def get_rbac_roles():
    rbac_api = client.RbacAuthorizationV1Api()
    roles = rbac_api.list_role_for_all_namespaces()

    results = []
    for role in roles.items:
        labels = role.metadata.labels or {}
        annotations = role.metadata.annotations or {}
        owner, owner_source = resolve_owner(labels, annotations)

        results.append({
            "type": "RBAC-Role",
            "name": role.metadata.name,
            "namespace": role.metadata.namespace,
            "owner": owner,
            "owner_source": owner_source,
            "managed": labels.get("cape-policy/managed", "false"),
            "created_at": role.metadata.creation_timestamp.isoformat()
                if role.metadata.creation_timestamp else None,
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
    rbac_api = client.RbacAuthorizationV1Api()
    bindings = rbac_api.list_role_binding_for_all_namespaces()

    results = []
    for binding in bindings.items:
        labels = binding.metadata.labels or {}
        annotations = binding.metadata.annotations or {}
        owner, owner_source = resolve_owner(labels, annotations)

        results.append({
            "type": "RBAC-RoleBinding",
            "name": binding.metadata.name,
            "namespace": binding.metadata.namespace,
            "owner": owner,
            "owner_source": owner_source,
            "created_at": binding.metadata.creation_timestamp.isoformat()
                if binding.metadata.creation_timestamp else None,
            "role_ref": binding.role_ref.name,
            "subjects": [
                {"kind": s.kind, "name": s.name, "namespace": s.namespace}
                for s in (binding.subjects or [])
            ],
        })
    return results


def get_gatekeeper_constraints():
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
        annotations = metadata.get("annotations", {})
        owner, owner_source = resolve_owner(labels, annotations)
        spec = item.get("spec", {})

        results.append({
            "type": "Gatekeeper-K8sAllowedRepos",
            "name": metadata.get("name"),
            "owner": owner,
            "owner_source": owner_source,
            "managed": labels.get("cape-policy/managed", "false"),
            "created_at": metadata.get("creationTimestamp"),
            "match_namespaces": spec.get("match", {}).get("namespaces", []),
            "allowed_repos": spec.get("parameters", {}).get("repos", []),
        })
    return results


def get_network_policies():
    net_api = client.NetworkingV1Api()
    policies = net_api.list_network_policy_for_all_namespaces()

    results = []
    for policy in policies.items:
        labels = policy.metadata.labels or {}
        annotations = policy.metadata.annotations or {}
        owner, owner_source = resolve_owner(labels, annotations)

        is_default_deny = (
            "Ingress" in (policy.spec.policy_types or [])
            and not policy.spec.ingress
        )

        results.append({
            "type": "NetworkPolicy",
            "name": policy.metadata.name,
            "namespace": policy.metadata.namespace,
            "owner": owner,
            "owner_source": owner_source,
            "created_at": policy.metadata.creation_timestamp.isoformat()
                if policy.metadata.creation_timestamp else None,
            "is_default_deny": is_default_deny,
        })
    return results


def run_full_scan():
    load_cluster()
    data = {
        "rbac_roles": get_rbac_roles(),
        "rbac_bindings": get_rbac_bindings(),
        "gatekeeper_constraints": get_gatekeeper_constraints(),
        "network_policies": get_network_policies(),
    }
    return data


if __name__ == "__main__":
    result = run_full_scan()
    print(json.dumps(result, indent=2))
