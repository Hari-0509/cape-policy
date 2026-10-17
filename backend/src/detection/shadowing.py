"""Shadowing: a constraint covers only some of the team namespaces (those labelled
cape-policy/class=application), leaving same-class namespaces uncovered.
A constraint with no namespace list applies cluster-wide and is not flagged."""
import json
import sys

sys.path.insert(0, "src")
sys.path.insert(0, ".")
from attribution.attribution import confidence_label


def detect_shadowing(gatekeeper_constraints, team_namespaces):
    found = []
    team_namespaces = list(team_namespaces)
    for con in gatekeeper_constraints:
        covered = set(con.get("match_namespaces", [])) & set(team_namespaces)
        missing = set(team_namespaces) - covered
        if not (missing and covered):
            continue
        ratio = len(covered) / len(team_namespaces)
        if ratio <= 0.34:
            conf, note = 0.85, "covers a small minority of same-class namespaces"
        elif ratio <= 0.67:
            conf, note = 0.65, "covers about half of same-class namespaces"
        else:
            conf, note = 0.45, "covers most same-class namespaces; the gap may be a deliberate exclusion"
        found.append({
            "conflict_type": "shadowing",
            "finding_status": "potential anomaly (review needed)",
            "policy_name": con["name"],
            "owner": con["owner"],
            "covered_namespaces": sorted(covered),
            "uncovered_namespaces": sorted(missing),
            "explanation": (
                f"Team '{con['owner']}' scoped constraint '{con['name']}' to {sorted(covered)}. "
                f"Namespaces {sorted(missing)} carry the same class label (cape-policy/class=application) "
                f"but have no equivalent constraint. Review whether the gap is intended."
            ),
            "at_fault_team": con["owner"],
            "severity": "high",
            "formal_attribution": {
                "at_fault_owner": con["owner"],
                "confidence_score": conf,
                "confidence_label": confidence_label(conf),
                "reasoning": f"Coverage {len(covered)}/{len(team_namespaces)} ({ratio*100:.0f}%): policy {note}.",
            },
        })
    return found


if __name__ == "__main__":
    from ingestion.namespaces import get_team_namespaces
    scan = json.load(open("data/latest_scan.json"))
    ns = get_team_namespaces()
    res = detect_shadowing(scan["gatekeeper_constraints"], ns)
    print(f"Shadowing findings: {len(res)}  (team namespaces: {ns})")
    for c in res:
        print(c["policy_name"], "uncovered:", c["uncovered_namespaces"], c["formal_attribution"]["confidence_label"])
