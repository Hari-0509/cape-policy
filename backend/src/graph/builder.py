"""Decision-point graph. Each node = namespace:resource:verb.
Policy records now carry created_at so attribution can use timestamps."""
import json
import networkx as nx

COMMON_VERBS = ["get", "list", "watch", "create", "update", "patch", "delete"]


def expand_verbs(verbs):
    return COMMON_VERBS if "*" in verbs else verbs


def build_rbac_decision_points(roles, bindings):
    G = nx.DiGraph()
    role_index = {(r["namespace"], r["name"]): r for r in roles}
    for binding in bindings:
        role = role_index.get((binding["namespace"], binding["role_ref"]))
        if not role:
            continue
        for rule in role["rules"]:
            resources = rule.get("resources") or []
            raw_verbs = rule.get("verbs") or []
            is_wildcard = "*" in raw_verbs
            for resource in resources:
                for verb in expand_verbs(raw_verbs):
                    dp = f"{binding['namespace']}:{resource}:{verb}"
                    if dp not in G:
                        G.add_node(dp, policies=[])
                    G.nodes[dp]["policies"].append({
                        "engine": "RBAC",
                        "role_name": role["name"],
                        "binding_name": binding["name"],
                        "owner": binding["owner"],
                        "created_at": binding.get("created_at"),
                        "subject": binding["subjects"][0]["name"] if binding["subjects"] else None,
                        "verb": verb,
                        "resource": resource,
                        "is_wildcard_grant": is_wildcard,
                    })
    return G


def build_gatekeeper_decision_points(G, constraints):
    for c in constraints:
        for ns in c.get("match_namespaces", []):
            dp = f"{ns}:pods:image-policy"
            if dp not in G:
                G.add_node(dp, policies=[])
            G.nodes[dp]["policies"].append({
                "engine": "Gatekeeper",
                "constraint_name": c["name"],
                "owner": c["owner"],
                "created_at": c.get("created_at"),
                "allowed_repos": c["allowed_repos"],
            })
    return G


def find_multi_team_nodes(G):
    out = []
    for node, data in G.nodes(data=True):
        owners = set(p["owner"] for p in data["policies"])
        if len(owners) > 1:
            out.append({"decision_point": node, "teams_involved": list(owners),
                        "policies": data["policies"]})
    return out


def build_full_graph(scan_data):
    G = build_rbac_decision_points(scan_data["rbac_roles"], scan_data["rbac_bindings"])
    return build_gatekeeper_decision_points(G, scan_data["gatekeeper_constraints"])


if __name__ == "__main__":
    scan = json.load(open("data/latest_scan.json"))
    G = build_full_graph(scan)
    multi = find_multi_team_nodes(G)
    print(f"Decision points: {G.number_of_nodes()}, multi-team: {len(multi)}")
