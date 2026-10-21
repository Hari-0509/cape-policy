"""Decision-point index. Keys are namespace:resource:verb. Handles namespaced Roles, ClusterRoles
(through RoleBindings or ClusterRoleBindings), wildcard verbs and resources. Subjects are
namespace-qualified. apiGroups are not used in the key (documented limitation)."""
import json
import networkx as nx

COMMON_VERBS = ["get", "list", "watch", "create", "update", "patch", "delete"]


def expand_verbs(verbs):
    return COMMON_VERBS if "*" in (verbs or []) else list(verbs or [])


def _expand_resources(resources, observed):
    return list(observed) if "*" in (resources or []) else list(resources or [])


def subject_key(s, default_ns):
    if s.get("kind") == "ServiceAccount":
        return f"{s.get('namespace') or default_ns}/{s['name']}"
    return f"{s.get('kind')}:{s['name']}"


def _observed_resources(scan):
    res = set()
    for r in scan.get("rbac_roles", []) + scan.get("cluster_roles", []):
        for rule in r["rules"]:
            res.update(x for x in (rule.get("resources") or []) if x != "*")
    return sorted(res)


def _record(role, binding, subj, res, verb, wild, scope):
    return {"engine": "RBAC", "role_name": role["name"], "binding_name": binding["name"],
            "owner": binding["owner"], "created_at": binding.get("created_at"),
            "last_update": binding.get("last_update"),
            "accepted_reason": binding.get("accepted_reason") or role.get("accepted_reason"),
            "subject": subj, "verb": verb, "resource": res, "is_wildcard_grant": wild, "scope": scope}


def build_rbac_decision_points(scan):
    G = nx.DiGraph()
    roles = {(r["namespace"], r["name"]): r for r in scan.get("rbac_roles", [])}
    croles = {r["name"]: r for r in scan.get("cluster_roles", [])}
    observed = _observed_resources(scan)
    ns_names = [n["name"] for n in scan.get("namespaces", [])] or sorted(
        {r["namespace"] for r in scan.get("rbac_roles", []) if r.get("namespace")}
        | {b["namespace"] for b in scan.get("rbac_bindings", []) if b.get("namespace")})

    def add(ns, role, binding, subjects, scope):
        for rule in role["rules"]:
            raw_v = rule.get("verbs") or []
            wild = "*" in raw_v
            for res in _expand_resources(rule.get("resources"), observed):
                for verb in expand_verbs(raw_v):
                    dp = f"{ns}:{res}:{verb}"
                    if dp not in G:
                        G.add_node(dp, policies=[])
                    for subj in subjects:
                        G.nodes[dp]["policies"].append(_record(role, binding, subj, res, verb, wild, scope))

    for b in scan.get("rbac_bindings", []):
        role = croles.get(b["role_ref"]) if b.get("role_ref_kind") == "ClusterRole" \
            else roles.get((b["namespace"], b["role_ref"]))
        if role:
            add(b["namespace"], role, b, [subject_key(s, b["namespace"]) for s in b["subjects"]], "namespace")
    for b in scan.get("cluster_role_bindings", []):
        role = croles.get(b["role_ref"])
        if role:
            for ns in ns_names:
                add(ns, role, b, [subject_key(s, None) for s in b["subjects"]], "cluster")
    return G


def build_gatekeeper_decision_points(G, constraints):
    for c in constraints:
        for ns in c.get("match_namespaces", []) or []:
            dp = f"{ns}:pods:image-policy"
            if dp not in G:
                G.add_node(dp, policies=[])
            G.nodes[dp]["policies"].append({"engine": "Gatekeeper", "constraint_name": c["name"],
                                            "owner": c["owner"], "created_at": c.get("created_at"),
                                            "allowed_repos": c.get("allowed_repos", [])})
    return G


def find_multi_team_nodes(G):
    out = []
    for node, data in G.nodes(data=True):
        owners = {p["owner"] for p in data["policies"]}
        if len(owners) > 1:
            out.append({"decision_point": node, "teams_involved": list(owners), "policies": data["policies"]})
    return out


def build_full_graph(scan_data):
    G = build_rbac_decision_points(scan_data)
    return build_gatekeeper_decision_points(G, scan_data.get("gatekeeper_constraints", []))


if __name__ == "__main__":
    scan = json.load(open("data/latest_scan.json"))
    G = build_full_graph(scan)
    print(f"Decision points: {G.number_of_nodes()}, multi-team: {len(find_multi_team_nodes(G))}")
