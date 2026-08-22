"""
CAPE-Policy: Graph Builder Module
Groups policies by "decision point" — e.g., (namespace, resource, verb) —
so policies written by different teams that affect the same thing can be
compared directly, regardless of which team or engine authored them.

Handles RBAC wildcard expansion: a "*" verb is treated as covering all
common verbs, since RBAC evaluates it that way in practice.
"""

import json
import networkx as nx

COMMON_VERBS = ["get", "list", "watch", "create", "update", "patch", "delete"]


def expand_verbs(verbs):
    """Expand '*' into the full set of common verbs it actually covers."""
    if "*" in verbs:
        return COMMON_VERBS
    return verbs


def build_rbac_decision_points(roles, bindings):
    G = nx.DiGraph()
    role_index = {(r["namespace"], r["name"]): r for r in roles}

    for binding in bindings:
        role_key = (binding["namespace"], binding["role_ref"])
        role = role_index.get(role_key)
        if not role:
            continue

        for rule in role["rules"]:
            resources = rule.get("resources") or []
            raw_verbs = rule.get("verbs") or []
            expanded_verbs = expand_verbs(raw_verbs)
            is_wildcard = "*" in raw_verbs

            for resource in resources:
                for verb in expanded_verbs:
                    decision_point = f"{binding['namespace']}:{resource}:{verb}"

                    if decision_point not in G:
                        G.add_node(decision_point, policies=[])

                    G.nodes[decision_point]["policies"].append({
                        "engine": "RBAC",
                        "role_name": role["name"],
                        "binding_name": binding["name"],
                        "owner": binding["owner"],
                        "subject": binding["subjects"][0]["name"] if binding["subjects"] else None,
                        "verb": verb,
                        "resource": resource,
                        "is_wildcard_grant": is_wildcard,
                    })

    return G


def build_gatekeeper_decision_points(G, constraints):
    for constraint in constraints:
        namespaces = constraint.get("match_namespaces", [])
        for ns in namespaces:
            decision_point = f"{ns}:pods:image-policy"
            if decision_point not in G:
                G.add_node(decision_point, policies=[])
            G.nodes[decision_point]["policies"].append({
                "engine": "Gatekeeper",
                "constraint_name": constraint["name"],
                "owner": constraint["owner"],
                "allowed_repos": constraint["allowed_repos"],
            })
    return G


def find_multi_team_nodes(G):
    multi_team_nodes = []
    for node, data in G.nodes(data=True):
        owners = set(p["owner"] for p in data["policies"])
        if len(owners) > 1:
            multi_team_nodes.append({
                "decision_point": node,
                "teams_involved": list(owners),
                "policies": data["policies"],
            })
    return multi_team_nodes


def build_full_graph(scan_data):
    G = build_rbac_decision_points(scan_data["rbac_roles"], scan_data["rbac_bindings"])
    G = build_gatekeeper_decision_points(G, scan_data["gatekeeper_constraints"])
    return G


if __name__ == "__main__":
    with open("data/latest_scan.json") as f:
        scan_data = json.load(f)

    G = build_full_graph(scan_data)
    print(f"Total decision points: {G.number_of_nodes()}\n")

    multi_team = find_multi_team_nodes(G)
    print(f"Decision points touched by multiple teams: {len(multi_team)}\n")

    for item in multi_team:
        print(f"--- {item['decision_point']} ---")
        print(f"Teams involved: {item['teams_involved']}")
        for p in item["policies"]:
            print(f"  {p}")
        print()
