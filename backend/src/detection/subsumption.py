"""Subsumption: a subject holds a broad (wildcard) grant from one team and a
narrower grant from another team. RBAC is additive, so the narrow rule adds no
restriction. Reported as excess effective privilege needing review."""
import json
import sys

sys.path.insert(0, "src")
sys.path.insert(0, ".")
from attribution.attribution import enrich_conflict_with_attribution, confidence_label


def detect_subsumption(multi_team_nodes):
    found = []
    for node in multi_team_nodes:
        pols = node["policies"]
        wides = [p for p in pols if p.get("is_wildcard_grant")]
        narrows = [p for p in pols if not p.get("is_wildcard_grant") and p.get("engine") == "RBAC"]
        for wide in wides:
            for narrow in narrows:
                if wide["owner"] == narrow["owner"] or wide.get("subject") != narrow.get("subject"):
                    continue
                c = {
                    "conflict_type": "subsumption",
                    "finding_status": "potential anomaly (review needed)",
                    "decision_point": node["decision_point"],
                    "subject": wide.get("subject"),
                    "narrow_policy": {"role": narrow["role_name"], "binding": narrow["binding_name"], "owner": narrow["owner"]},
                    "overriding_policy": {"role": wide["role_name"], "binding": wide["binding_name"], "owner": wide["owner"]},
                    "explanation": (
                        f"Subject '{wide.get('subject')}' holds a wildcard grant from team "
                        f"'{wide['owner']}' (role '{wide['role_name']}') and a narrower grant from team "
                        f"'{narrow['owner']}' (role '{narrow['role_name']}'). RBAC permissions only add up, "
                        f"so the narrower grant adds no restriction and the subject's effective access is "
                        f"the wildcard's. Review whether the broader grant was intended."
                    ),
                    "at_fault_team": wide["owner"],
                    "severity": "high",
                }
                a = {"owner": narrow["owner"], "created_at": narrow.get("created_at"), "is_wildcard_grant": False}
                b = {"owner": wide["owner"], "created_at": wide.get("created_at"), "is_wildcard_grant": True}
                c = enrich_conflict_with_attribution(c, a, b, tie_breaker_key="is_wildcard_grant")
                fa = c["formal_attribution"]
                if fa["at_fault_owner"] != wide["owner"]:
                    fa.update({
                        "at_fault_owner": wide["owner"],
                        "confidence_score": 0.60,
                        "confidence_label": confidence_label(0.60),
                        "reasoning": ("The broader grant is not newer than the narrower rule, so the excess "
                                      "privilege existed first. Responsibility goes to the owner of the broader "
                                      "grant at reduced confidence."),
                    })
                found.append(c)

    dedup = {}
    for c in found:
        key = (c["subject"], c["narrow_policy"]["role"], c["overriding_policy"]["role"])
        if key not in dedup:
            dedup[key] = c
            c["affected_decision_points"] = [c["decision_point"]]
        else:
            dedup[key]["affected_decision_points"].append(c["decision_point"])
    return list(dedup.values())


if __name__ == "__main__":
    from graph.builder import build_full_graph, find_multi_team_nodes
    scan = json.load(open("data/latest_scan.json"))
    res = detect_subsumption(find_multi_team_nodes(build_full_graph(scan)))
    print(f"Subsumption findings: {len(res)}")
    for c in res:
        fa = c["formal_attribution"]
        print(c["subject"], "->", fa["at_fault_owner"], fa["confidence_label"], fa["confidence_score"])
        print(" ", fa["reasoning"])
