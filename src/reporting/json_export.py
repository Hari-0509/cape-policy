"""
CAPE-Policy: JSON Report Exporter
Formats conflict data into a clean, machine-readable JSON report suitable
for CI/CD pipeline consumption.
"""

import json
from datetime import datetime, timezone


def export_report(conflicts, path="data/conflict_report.json"):
    report = {
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "total_conflicts": len(conflicts),
        "conflicts_by_type": {},
        "conflicts": conflicts,
    }

    for c in conflicts:
        ctype = c["conflict_type"]
        report["conflicts_by_type"][ctype] = report["conflicts_by_type"].get(ctype, 0) + 1

    with open(path, "w") as f:
        json.dump(report, f, indent=2)

    return report


if __name__ == "__main__":
    with open("data/conflict_report.json") as f:
        existing = json.load(f)
    # existing might already be a plain list from engine.py — handle both cases
    conflicts = existing if isinstance(existing, list) else existing.get("conflicts", [])
    report = export_report(conflicts)
    print(f"Report exported: {report['total_conflicts']} conflicts")
    print(f"Breakdown: {report['conflicts_by_type']}")
