"""CI helper: exits non-zero if any high-severity conflicts were found."""
import json
import sys

with open("data/conflict_report.json") as f:
    conflicts = json.load(f)

high_severity = [c for c in conflicts if c.get("severity") == "high"]

print(f"Found {len(conflicts)} total conflicts, {len(high_severity)} high severity")
for c in conflicts:
    print(f"  - [{c.get('conflict_type')}] at fault: {c.get('at_fault_team')}, severity: {c.get('severity')}")

if high_severity:
    print("HIGH SEVERITY CONFLICTS DETECTED - this is expected for the seeded demo policies")
    sys.exit(1)
