"""
CAPE-Policy: Subsumption Detector
Detects when a broad/wildcard RBAC grant from one team silently renders
another team's narrower, intentional restriction meaningless. Now attaches
a confidence-scored attribution decision to each finding.
"""

import json
import sys

sys.path.insert(0, "src")
sys.path.insert(0, ".")

from attribution.attribution import enrich_conflict_with_attribution


def detect_subsumption(multi_team_nodes):
    conflicts = []

    for node in multi_team_nodes:
        policies = node["policies"]

        wildcard_policies = [p for p in policies if p.get("is_wildcard_grant")]
        narrow_policies = [p for p in policies if not p.get("is_wildcard_grant")]

        if wildcard_policies and narrow_policies:
            for wide in wildcard_policies:
                for narrow in narrow_policies:
                    if wide["owner"] == narrow["owner"]:
                        continue

                    conflict = {
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
                    }

                    # Attach confidence-scored attribution using timestamps
                    # if available, falling back to wildcard-scope tie-breaker
                    policy_a = {
                        "owner": narrow["owner"],
                        "created_at": narrow.get("created_at"),
                        "is_wildcard_grant": False,
                    }
                    policy_b = {
                        "owner": wide["owner"],
                        "created_at": wide.get("created_at"),
                        "is_wildcard_grant": True,
                    }
                    conflict = enrich_conflict_with_attribution(
                        conflict, policy_a, policy_b, tie_breaker_key="is_wildcard_grant"
                    )

                    conflicts.append(conflict)

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
        print(f"At fault: {c['at_fault_team']}")
        print(f"Confidence: {c['formal_attribution']['confidence_label']} ({c['formal_attribution']['confidence_score']})")
        print(f"Reasoning: {c['formal_attribution']['reasoning']}")
        print()
