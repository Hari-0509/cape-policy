"""Runs all four detectors, adds finding status, writes the report."""
import json
import sys

sys.path.insert(0, "src")
from graph.builder import build_full_graph, find_multi_team_nodes
from ingestion.namespaces import get_team_namespaces
from detection.subsumption import detect_subsumption
from detection.shadowing import detect_shadowing
from detection.contradiction import detect_contradiction
from detection.cross_domain import detect_cross_domain


def run_full_scan(scan_data, team_namespaces=None):
    if team_namespaces is None:
        team_namespaces = get_team_namespaces()
    G = build_full_graph(scan_data)
    findings = []
    findings += detect_subsumption(find_multi_team_nodes(G))
    findings += detect_shadowing(scan_data["gatekeeper_constraints"], team_namespaces)
    findings += detect_contradiction()
    findings += detect_cross_domain(scan_data)
    for f in findings:
        f.setdefault("finding_status", "potential anomaly (review needed)")
    return findings


if __name__ == "__main__":
    scan = json.load(open("data/latest_scan.json"))
    findings = run_full_scan(scan)
    print(f"CAPE-Policy scan complete: {len(findings)} findings\n")
    for f in findings:
        print(f"[{f['conflict_type'].upper()}] {f['finding_status']} | {f.get('at_fault_team')}")
    json.dump(findings, open("data/conflict_report.json", "w"), indent=2)
    print("\nReport saved to data/conflict_report.json")
