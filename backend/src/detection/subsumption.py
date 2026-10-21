"""Subsumption (potential anomaly): a subject holds a wildcard-verb grant from one team and
a narrower grant on the same resource from another. RBAC is additive, so the narrow grant
adds no restriction. The wildcard grant is the issue."""
import json, sys
from datetime import datetime

sys.path.insert(0, "src"); sys.path.insert(0, ".")
from attribution.attribution import enrich_conflict_with_attribution


def _dt(x):
    try:
        return datetime.fromisoformat(x.replace("Z", "+00:00")) if x else None
    except Exception:
        return None


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
                        f"Subject '{wide.get('subject')}' holds a wildcard grant from team '{wide['owner']}' "
                        f"(role '{wide['role_name']}') and a narrower grant from team '{narrow['owner']}' "
                        f"(role '{narrow['role_name']}'). RBAC permissions only add up, so the narrower grant adds "
                        f"no restriction and the subject's effective access is the wildcard's. "
                        f"Review whether the broader grant was intended."),
                    "at_fault_team": wide["owner"],
                    "severity": "high",
                    "accepted_reason": wide.get("accepted_reason"),
                }
                # corroborated: the wildcard grant appeared after the narrow rule's most recent change
                w_created = _dt(wide.get("created_at"))
                n_latest = _dt(narrow.get("last_update")) or _dt(narrow.get("created_at"))
                corr = bool(w_created and n_latest and w_created > n_latest)
                a = {"owner": narrow["owner"], "created_at": narrow.get("created_at"), "is_wildcard_grant": False}
                b = {"owner": wide["owner"], "created_at": wide.get("created_at"), "is_wildcard_grant": True}
                c = enrich_conflict_with_attribution(c, a, b, "is_wildcard_grant", corroborated=corr)
                fa = c["formal_attribution"]
                if fa["at_fault_owner"] != wide["owner"]:
                    fa.update({"at_fault_owner": wide["owner"], "confidence_label": "Medium",
                               "evidence": "fallback rule", "internal_score": 0.60,
                               "reasoning": ("The broader grant is not newer than the narrower rule, so the excess "
                                             "privilege existed first. The owner of the broader grant is named at reduced confidence.")})
                found.append(c)
    dedup = {}
    for c in found:
        key = (c["subject"], c["narrow_policy"]["role"], c["overriding_policy"]["role"])
        if key not in dedup:
            dedup[key] = c; c["affected_decision_points"] = [c["decision_point"]]
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
        print(c["subject"], "->", fa["at_fault_owner"], fa["confidence_label"], "|", fa["reasoning"])
