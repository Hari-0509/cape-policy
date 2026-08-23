"""
CAPE-Policy: Subsumption Detector
Detects when a broad/wildcard RBAC grant from one team silently renders
another team's narrower, intentional restriction meaningless.
"""

import json
from datetime import datetime


def detect_subsumption(multi_team_nodes):
    """
    For each multi-team decision point, check if one policy is a wildcard
    grant while another is a narrow grant from a different team — that's
    a subsumption conflict: the narrow policy is functionally overridden.
    """
    conflicts = []

    for node in multi_team_nodes:
        policies = node["policies"]

        wildcard_policies = [p for p in policies if p.get("is_wildcard_grant")]
        narrow_policies = [p for p in policies if not p.get("is_wildcard_grant")]

        if wildcard_policies and narrow_policies:
            for wide in wildcard_policies:
                for narrow in narrow_policies:
                    if wide["owner"] == narrow["owner"]:
                        continue  # same team, not a cross-team conflict

                    conflicts.append({
                        "conflict_type": "subsumption",
                        "decision_point": node["decision_point"],
                        "subject": wide.get("subject"),
                        "narrow_policy": {
                            "role": narrow["role_name"],
                            "binding": narrow["binding_name"],
                            "owner": narrow["owner"],
                        },
                        "overriding_policy": {
                            "role": wide["role_name"],
                            "binding": wide["binding_name"],
                            "owner": wide["owner"],
                        },
                        "explanation": (
                            f"Team '{narrow['owner']}' granted a narrow permission "
                            f"({narrow['verb']} on {narrow['resource']}) via role "
                            f"'{narrow['role_name']}', but team '{wide['owner']}' "
                            f"granted a wildcard permission via role '{wide['role_name']}' "
                            f"to the same subject '{wide.get('subject')}'. "
                            f"Since Kubernetes RBAC is purely additive, the wildcard grant "
                            f"makes the narrow restriction meaningless."
                        ),
                        "at_fault_team": wide["owner"],
                        "severity": "high",
                    })

    # Deduplicate conflicts that appear once per verb (get, list, etc.)
    # into one conflict per (subject, narrow_role, wide_role) pair
    deduped = {}
    for c in conflicts:
        key = (c["subject"], c["narrow_policy"]["role"], c["overriding_policy"]["role"])
        if key not in deduped:
            deduped[key] = c
            deduped[key]["affected_decision_points"] = [c["decision_point"]]
        else:
            deduped[key]["affected_decision_points"].append(c["decision_point"])

    return list(deduped.values())


if __name__ == "__main__":
    import sys
    sys.path.insert(0, "src")
    from graph.builder import build_full_graph, find_multi_team_nodes

    with open("data/latest_scan.json") as f:
        scan_data = json.load(f)

    G = build_full_graph(scan_data)
    multi_team_nodes = find_multi_team_nodes(G)

    conflicts = detect_subsumption(multi_team_nodes)

    print(f"Subsumption conflicts found: {len(conflicts)}\n")
    for c in conflicts:
        print(f"--- CONFLICT: {c['conflict_type'].upper()} ---")
        print(f"Subject: {c['subject']}")
        print(f"At fault: {c['at_fault_team']}")
        print(f"Severity: {c['severity']}")
        print(f"Affected decision points: {c['affected_decision_points']}")
        print(f"Explanation: {c['explanation']}")
        print()
