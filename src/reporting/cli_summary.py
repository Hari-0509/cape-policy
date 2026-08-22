"""
CAPE-Policy: CLI Summary
Prints a clean, readable summary of detected conflicts to the terminal.
"""

import json

SEVERITY_ICONS = {"high": "🔴", "medium": "🟡", "low": "🟢"}


def print_summary(conflicts):
    print("=" * 60)
    print("  CAPE-POLICY SCAN RESULTS")
    print("=" * 60)
    print(f"\nTotal conflicts found: {len(conflicts)}\n")

    for i, c in enumerate(conflicts, 1):
        icon = SEVERITY_ICONS.get(c.get("severity", "medium"), "⚪")
        print(f"{icon} [{i}] {c['conflict_type'].upper()}")
        print(f"    At fault: {c.get('at_fault_team', 'unknown')}")
        if c.get("formal_attribution"):
            print(f"    Reasoning: {c['formal_attribution']['reasoning']}")
        print(f"    Details: {c.get('explanation', 'N/A')[:120]}...")
        print()

    print("=" * 60)


if __name__ == "__main__":
    with open("data/conflict_report.json") as f:
        data = json.load(f)
    conflicts = data if isinstance(data, list) else data.get("conflicts", [])
    print_summary(conflicts)
