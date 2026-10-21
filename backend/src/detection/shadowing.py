"""Shadowing (potential anomaly): a constraint covers some, not all, namespaces of the class
cape-policy/class=application. Honours include list, namespaceSelector, excludedNamespaces."""
import json, sys

sys.path.insert(0, "src"); sys.path.insert(0, ".")
from ingestion.scope import effective_namespaces


def detect_shadowing(constraints, team_namespaces, namespaces=None):
    team = list(team_namespaces)
    all_ns = namespaces or [{"name": n, "labels": {}} for n in team]
    found = []
    for con in constraints:
        scope = effective_namespaces(con.get("match_namespaces"), con.get("namespace_selector"),
                                     con.get("excluded_namespaces"), all_ns)
        covered = scope & set(team)
        missing = set(team) - covered
        if not (missing and covered):
            continue
        ratio = len(covered) / len(team)
        if ratio <= 0.34:
            prio, note = "High", "covers a small minority of same-class namespaces"
        elif ratio <= 0.67:
            prio, note = "Medium", "covers about half of same-class namespaces"
        else:
            prio, note = "Low", "covers most same-class namespaces; the gap may be deliberate"
        found.append({
            "conflict_type": "shadowing",
            "finding_status": "potential anomaly (review needed)",
            "policy_name": con["name"], "owner": con["owner"],
            "covered_namespaces": sorted(covered), "uncovered_namespaces": sorted(missing),
            "explanation": (f"Team '{con['owner']}' scoped constraint '{con['name']}' to {sorted(covered)}. "
                            f"Namespaces {sorted(missing)} carry the same class label but have no equivalent "
                            f"constraint. Review whether the gap is intended."),
            "at_fault_team": con["owner"], "severity": "high",
            "accepted_reason": con.get("accepted_reason"),
            "formal_attribution": {
                "at_fault_owner": con["owner"], "review_priority": prio,
                "reasoning": f"Coverage {len(covered)}/{len(team)} ({ratio*100:.0f}%): policy {note}."},
        })
    return found


if __name__ == "__main__":
    from ingestion.namespaces import get_team_namespaces
    scan = json.load(open("data/latest_scan.json"))
    ns = get_team_namespaces()
    res = detect_shadowing(scan["gatekeeper_constraints"], ns, scan.get("namespaces"))
    print(f"Shadowing findings: {len(res)} (team namespaces: {ns})")
    for c in res:
        print(c["policy_name"], c["uncovered_namespaces"], c["formal_attribution"]["review_priority"])
