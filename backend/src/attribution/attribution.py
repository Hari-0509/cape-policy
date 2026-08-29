"""
CAPE-Policy: Ownership Attribution Module
Formalizes fault attribution using timestamp comparison (time-drift logic),
now with an explicit confidence score reflecting how certain the attribution
decision is, based on which evidence tier was used to make it.

Confidence tiers:
  0.95 - Clear timestamp difference (>60s apart): unambiguous newer policy
  0.75 - Small timestamp difference (<=60s apart): likely correct, but close
  0.60 - Timestamps tied/unavailable, tie-breaker signal used (e.g. wildcard scope)
  0.30 - No timestamp and no reliable tie-breaker: low-confidence default
"""

from datetime import datetime


def parse_timestamp(ts_string):
    if not ts_string:
        return None
    try:
        return datetime.fromisoformat(ts_string.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def determine_at_fault(policy_a, policy_b, tie_breaker_key=None):
    """
    Given two policies involved in a conflict, determine which one is
    "at fault," along with a confidence score and reasoning string.

    Returns: (at_fault_policy, confidence_score, reasoning_string)
    """
    ts_a = parse_timestamp(policy_a.get("created_at"))
    ts_b = parse_timestamp(policy_b.get("created_at"))

    if ts_a and ts_b and ts_a != ts_b:
        newer, older = (policy_a, policy_b) if ts_a > ts_b else (policy_b, policy_a)
        newer_ts, older_ts = (ts_a, ts_b) if ts_a > ts_b else (ts_b, ts_a)
        gap_seconds = (newer_ts - older_ts).total_seconds()

        confidence = 0.95 if gap_seconds > 60 else 0.75

        reasoning = (
            f"'{newer['owner']}' introduced this policy on {newer_ts.isoformat()}, "
            f"{gap_seconds:.0f}s after '{older['owner']}''s existing policy from "
            f"{older_ts.isoformat()}. The newer change is treated as the source "
            f"of the conflict."
        )
        return newer, confidence, reasoning

    # Timestamps missing or tied — fall back to a declared tie-breaker
    if tie_breaker_key:
        val_a = policy_a.get(tie_breaker_key)
        val_b = policy_b.get(tie_breaker_key)
        if val_a and not val_b:
            reasoning = (
                f"Timestamps are identical or unavailable. Falling back to policy "
                f"scope: '{policy_a['owner']}''s policy is broader "
                f"({tie_breaker_key}=True) and is treated as the more likely source "
                f"of the conflict."
            )
            return policy_a, 0.60, reasoning
        if val_b and not val_a:
            reasoning = (
                f"Timestamps are identical or unavailable. Falling back to policy "
                f"scope: '{policy_b['owner']}''s policy is broader "
                f"({tie_breaker_key}=True) and is treated as the more likely source "
                f"of the conflict."
            )
            return policy_b, 0.60, reasoning

    reasoning = (
        "Timestamps are identical and no reliable tie-breaker is available. "
        "Both teams should review this conflict jointly."
    )
    return None, 0.30, reasoning


def confidence_label(score):
    """Convert a numeric confidence score into a human-readable label
    for display in the dashboard/reports."""
    if score >= 0.9:
        return "High"
    elif score >= 0.7:
        return "Medium-High"
    elif score >= 0.5:
        return "Medium"
    else:
        return "Low"


def enrich_conflict_with_attribution(conflict, policy_a, policy_b, tie_breaker_key=None):
    """
    Take a raw conflict dict (from any detector) and attach a formal,
    confidence-scored attribution decision to it.
    """
    at_fault_policy, confidence, reasoning = determine_at_fault(policy_a, policy_b, tie_breaker_key)

    conflict["formal_attribution"] = {
        "at_fault_owner": at_fault_policy["owner"] if at_fault_policy else "joint-review-needed",
        "confidence_score": confidence,
        "confidence_label": confidence_label(confidence),
        "reasoning": reasoning,
        "policy_a_timestamp": policy_a.get("created_at"),
        "policy_b_timestamp": policy_b.get("created_at"),
    }
    return conflict


if __name__ == "__main__":
    # Test case 1: clear timestamp difference (high confidence)
    policy_a = {"owner": "security-team", "created_at": "2026-08-22T07:00:00+00:00"}
    policy_b = {"owner": "backend-team", "created_at": "2026-08-22T09:00:00+00:00"}
    at_fault, conf, reasoning = determine_at_fault(policy_a, policy_b)
    print(f"Test 1 (clear gap): at_fault={at_fault['owner']}, confidence={conf} ({confidence_label(conf)})")

    # Test case 2: tied timestamps, tie-breaker used (medium confidence)
    policy_a = {"owner": "security-team", "created_at": "2026-08-22T07:26:54+00:00", "is_wildcard_grant": False}
    policy_b = {"owner": "backend-team", "created_at": "2026-08-22T07:26:54+00:00", "is_wildcard_grant": True}
    at_fault, conf, reasoning = determine_at_fault(policy_a, policy_b, tie_breaker_key="is_wildcard_grant")
    print(f"Test 2 (tie-breaker): at_fault={at_fault['owner']}, confidence={conf} ({confidence_label(conf)})")

    # Test case 3: no timestamp, no tie-breaker (low confidence)
    policy_a = {"owner": "security-team"}
    policy_b = {"owner": "backend-team"}
    at_fault, conf, reasoning = determine_at_fault(policy_a, policy_b)
    print(f"Test 3 (no evidence): at_fault={at_fault}, confidence={conf} ({confidence_label(conf)})")
