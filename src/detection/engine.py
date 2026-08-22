"""
CAPE-Policy: Unified Detection Engine
Runs all 4 conflict detectors and returns a single consolidated report.
"""

import json
import sys
sys.path.insert(0, "src")

from graph.builder import build_full_graph, find_multi_team_nodes
from detection.subsumption import detect_subsumption
from detection.shadowing import detect_shadowing
from detection.contradiction import detect_contradiction
from detection.cross_domain import detect_cross_domain


def run_full_scan(scan_data):
    G = build_full_graph(scan_data)
    multi_team_nodes = find_multi_team_nodes(G)

    all_conflicts = []
    all_conflicts += detect_subsumption(multi_team_nodes)
    all_conflicts += detect_shadowing(
        scan_data["gatekeeper_constraints"],
        ["team-security", "team-backend", "team-data"],
    )
    all_conflicts += detect_contradiction()
    all_conflicts += detect_cross_domain(scan_data)

    return all_conflicts


if __name__ == "__main__":
    with open("data/latest_scan.json") as f:
        scan_data = json.load(f)

    conflicts = run_full_scan(scan_data)

    print(f"CAPE-Policy Scan Complete")
    print(f"Total conflicts found: {len(conflicts)}\n")

    for c in conflicts:
        print(f"[{c['conflict_type'].upper()}] {c.get('at_fault_team', 'unknown')}")

    with open("data/conflict_report.json", "w") as f:
        json.dump(conflicts, f, indent=2)
    print(f"\nFull report saved to data/conflict_report.json")
