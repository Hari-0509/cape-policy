"""
CAPE-Policy: Shadowing Detector
Detects when a security-critical policy (e.g., Gatekeeper image allow-list)
is scoped to cover only some team namespaces, silently leaving others
unprotected. Now attaches a confidence-scored attribution decision.
"""

import json
import sys

sys.path.insert(0, "src")
sys.path.insert(0, ".")

from attribution.attribution import confidence_label


def detect_shadowing(gatekeeper_constraints, all_team_namespaces):
    conflicts = []

    for constraint in gatekeeper_constraints:
        covered = set(constraint.get("match_namespaces", []))
        missing = set(all_team_namespaces) - covered

        if missing and covered:
            # Shadowing attribution is different from subsumption: there's
            # only ONE policy involved (the gap is an omission, not a
            # competing second policy), so confidence reflects how certain
            # we are that the omission is unintentional rather than a
            # deliberate scoping choice. We use coverage ratio as the signal:
            # covering very few of many namespaces suggests an oversight;
            # covering most but missing one or two is more ambiguous.
            coverage_ratio = len(covered) / len(all_team_namespaces) if all_team_namespaces else 0

            if coverage_ratio <= 0.34:
                confidence = 0.85
                certainty_note = "policy covers a small minority of active namespaces, strongly suggesting an unintentional gap"
            elif coverage_ratio <= 0.67:
                confidence = 0.65
                certainty_note = "policy covers roughly half of active namespaces; gap may be intentional or accidental"
            else:
                confidence = 0.45
                certainty_note = "policy covers most namespaces; the small remaining gap could be an intentional exclusion"

            conflicts.append({
                "conflict_type": "shadowing",
                "policy_name": constraint["name"],
                "owner": constraint["owner"],
                "covered_namespaces": list(covered),
                "uncovered_namespaces": list(missing),
                "explanation": (
                    f"Team '{constraint['owner']}' created the policy "
                    f"'{constraint['name']}' (allowed image repos: "
                    f"{constraint.get('allowed_repos')}), but it only applies to "
                    f"{list(covered)}. The namespace(s) {list(missing)} have no "
                    f"equivalent protection, even though they run similar workloads. "
                    f"Deployments in {list(missing)} can silently bypass this "
                    f"security control."
                ),
                "at_fault_team": constraint["owner"],
                "severity": "high",
                "formal_attribution": {
                    "at_fault_owner": constraint["owner"],
                    "confidence_score": confidence,
                    "confidence_label": confidence_label(confidence),
                    "reasoning": (
                        f"Coverage ratio: {len(covered)}/{len(all_team_namespaces)} "
                        f"namespaces ({coverage_ratio*100:.0f}%). {certainty_note}."
                    ),
                },
            })

    return conflicts


if __name__ == "__main__":
    with open("data/latest_scan.json") as f:
        scan_data = json.load(f)

    all_team_namespaces = ["team-security", "team-backend", "team-data"]

    conflicts = detect_shadowing(
        scan_data["gatekeeper_constraints"], all_team_namespaces
    )

    print(f"Shadowing conflicts found: {len(conflicts)}\n")
    for c in conflicts:
        print(f"--- CONFLICT: {c['conflict_type'].upper()} ---")
        print(f"At fault: {c['at_fault_team']}")
        print(f"Confidence: {c['formal_attribution']['confidence_label']} ({c['formal_attribution']['confidence_score']})")
        print(f"Reasoning: {c['formal_attribution']['reasoning']}")
        print()
