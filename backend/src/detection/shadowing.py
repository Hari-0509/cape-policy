"""
CAPE-Policy: Shadowing Detector
Detects when a security-critical policy (e.g., Gatekeeper image allow-list)
is scoped to cover only some team namespaces, silently leaving others
unprotected — even though the policy "looks like" it's enforced cluster-wide.
"""

import json


def detect_shadowing(gatekeeper_constraints, all_team_namespaces):
    """
    For each Gatekeeper constraint, check if it covers all known team
    namespaces. If it's missing coverage for some, flag it as a shadowing
    gap — the policy exists and looks active, but isn't protecting everyone
    it plausibly should.
    """
    conflicts = []

    for constraint in gatekeeper_constraints:
        covered = set(constraint.get("match_namespaces", []))
        missing = set(all_team_namespaces) - covered

        if missing and covered:
            # Policy IS active somewhere, but not everywhere it should be
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
            })

    return conflicts


if __name__ == "__main__":
    with open("data/latest_scan.json") as f:
        scan_data = json.load(f)

    # In a real system this would come from listing all namespaces with an
    # "owner" label. For now, we know our 3 seeded teams.
    all_team_namespaces = ["team-security", "team-backend", "team-data"]

    conflicts = detect_shadowing(
        scan_data["gatekeeper_constraints"], all_team_namespaces
    )

    print(f"Shadowing conflicts found: {len(conflicts)}\n")
    for c in conflicts:
        print(f"--- CONFLICT: {c['conflict_type'].upper()} ---")
        print(f"Policy: {c['policy_name']}")
        print(f"At fault: {c['at_fault_team']}")
        print(f"Severity: {c['severity']}")
        print(f"Covered: {c['covered_namespaces']}")
        print(f"Uncovered (gap): {c['uncovered_namespaces']}")
        print(f"Explanation: {c['explanation']}")
        print()
