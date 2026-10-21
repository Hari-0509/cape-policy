"""Collector: RBAC (Roles, ClusterRoles, bindings), Gatekeeper constraints, NetworkPolicies, namespaces."""
from kubernetes import client, config
import json

ACCEPT_KEY = "cape-policy/accepted"


def load_cluster():
    config.load_kube_config()


def resolve_owner(labels, annotations):
    labels, annotations = labels or {}, annotations or {}
    if "owner-team" in labels:
        return labels["owner-team"], "explicit-label"
    if "argocd.argoproj.io/tracking-id" in annotations:
        return f"gitops:{annotations['argocd.argoproj.io/tracking-id']}", "argocd-tracking-id"
    if "meta.helm.sh/release-name" in annotations:
        return f"helm-release:{annotations['meta.helm.sh/release-name']}", "helm-release-name"
    return "unknown", "no-attribution-source"


def _ts(x):
    return x.isoformat() if x else None


def _common(meta):
    labels, ann = meta.labels or {}, meta.annotations or {}
    owner, src = resolve_owner(labels, ann)
    times = [e.time for e in (meta.managed_fields or []) if e.time]
    return {"name": meta.name, "namespace": meta.namespace, "owner": owner, "owner_source": src,
            "created_at": _ts(meta.creation_timestamp),
            "last_update": _ts(max(times)) if times else None,
            "managers": sorted({e.manager for e in (meta.managed_fields or []) if e.manager}),
            "accepted_reason": ann.get(ACCEPT_KEY)}


def _rules(rules):
    return [{"resources": r.resources, "verbs": r.verbs, "apiGroups": r.api_groups} for r in (rules or [])]


def _subjects(subs):
    return [{"kind": s.kind, "name": s.name, "namespace": s.namespace} for s in (subs or [])]


def get_rbac_roles():
    api = client.RbacAuthorizationV1Api()
    return [{**_common(r.metadata), "type": "RBAC-Role", "rules": _rules(r.rules)}
            for r in api.list_role_for_all_namespaces().items]


def get_cluster_roles():
    api = client.RbacAuthorizationV1Api()
    return [{**_common(r.metadata), "type": "RBAC-ClusterRole", "rules": _rules(r.rules)}
            for r in api.list_cluster_role().items]


def get_rbac_bindings():
    api = client.RbacAuthorizationV1Api()
    return [{**_common(b.metadata), "type": "RBAC-RoleBinding", "role_ref": b.role_ref.name,
             "role_ref_kind": b.role_ref.kind, "subjects": _subjects(b.subjects)}
            for b in api.list_role_binding_for_all_namespaces().items]


def get_cluster_role_bindings():
    api = client.RbacAuthorizationV1Api()
    return [{**_common(b.metadata), "type": "RBAC-ClusterRoleBinding", "role_ref": b.role_ref.name,
             "role_ref_kind": b.role_ref.kind, "subjects": _subjects(b.subjects)}
            for b in api.list_cluster_role_binding().items]


def get_gatekeeper_constraints():
    out = []
    try:
        crds = client.ApiextensionsV1Api().list_custom_resource_definition().items
        custom = client.CustomObjectsApi()
        for crd in crds:
            if crd.spec.group != "constraints.gatekeeper.sh":
                continue
            ver = next((v.name for v in crd.spec.versions if v.served), None)
            if not ver:
                continue
            items = custom.list_cluster_custom_object("constraints.gatekeeper.sh", ver, crd.spec.names.plural)
            for item in items.get("items", []):
                md, sp = item.get("metadata", {}), item.get("spec", {})
                labels, ann = md.get("labels", {}), md.get("annotations", {}) or {}
                owner, src = resolve_owner(labels, ann)
                m = sp.get("match", {}) or {}
                out.append({"type": "Gatekeeper-" + item.get("kind", ""), "kind": item.get("kind"),
                            "name": md.get("name"), "owner": owner, "owner_source": src,
                            "created_at": md.get("creationTimestamp"), "accepted_reason": ann.get(ACCEPT_KEY),
                            "match_namespaces": m.get("namespaces", []) or [],
                            "excluded_namespaces": m.get("excludedNamespaces", []) or [],
                            "namespace_selector": m.get("namespaceSelector"),
                            "allowed_repos": (sp.get("parameters") or {}).get("repos", [])})
    except client.exceptions.ApiException as e:
        print(f"Warning: could not read Gatekeeper constraints: {e}")
    return out


def get_network_policies():
    api = client.NetworkingV1Api()
    out = []
    for p in api.list_network_policy_for_all_namespaces().items:
        deny = "Ingress" in (p.spec.policy_types or []) and not p.spec.ingress
        out.append({**_common(p.metadata), "type": "NetworkPolicy", "is_default_deny": deny})
    return out


def get_namespaces():
    return [{"name": n.metadata.name, "labels": n.metadata.labels or {}}
            for n in client.CoreV1Api().list_namespace().items]


def run_full_scan():
    load_cluster()
    return {"rbac_roles": get_rbac_roles(), "rbac_bindings": get_rbac_bindings(),
            "cluster_roles": get_cluster_roles(), "cluster_role_bindings": get_cluster_role_bindings(),
            "gatekeeper_constraints": get_gatekeeper_constraints(),
            "network_policies": get_network_policies(), "namespaces": get_namespaces()}


if __name__ == "__main__":
    print(json.dumps(run_full_scan(), indent=2))
