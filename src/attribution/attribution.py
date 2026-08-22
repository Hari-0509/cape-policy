"""
CAPE-Policy: Ownership Attribution Module
Formalizes fault attribution using timestamp comparison (time-drift logic):
the more recently created/modified policy is treated as the "at-fault"
change, since it's the one that introduced the conflict into a previously
working configuration. Falls back to declared severity/role broadness when
timestamps tie.
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
    "at fault" based on which was introduced more recently (time-drift).

    policy_a, policy_b: dicts with at least 'owner', 'created_at', and
                         optionally a tie_breaker_key like 'is_wildcard_grant'

    Returns: (at_fault_policy, reasoning_string)
    """
    ts_a = parse_timestamp(policy_a.get("created_at"))
    ts_b = parse_timestamp(policy_b.get("created_at"))

    if ts_a and ts_b and ts_a != ts_b:
        if ts_a > ts_b:
            return policy_a, (
                f"'{policy_a['owner']}' introduced this policy on {ts_a.isoformat()}, "
                f"after '{policy_b['owner']}''s existing policy from {ts_b.isoformat()}. "
                f"The newer change is treated as the source of the conflict."
            )
        else:
            return policy_b, (
                f"'{policy_b['owner']}' introduced this policy on {ts_b.isoformat()}, "
                f"after '{policy_a['owner']}''s existing policy from {ts_a.isoformat()}. "
                f"The newer change is treated as the source of the conflict."
            )

    # Timestamps missing or tied — fall back to a declared tie-breaker
    if tie_breaker_key:
        val_a = policy_a.get(tie_breaker_key)
        val_b = policy_b.get(tie_breaker_key)
        if val_a and not val_b:
            return policy_a, (
                f"Timestamps are identical or unavailable. Falling back to policy "
                f"scope: '{policy_a['owner']}''s policy is broader "
                f"({tie_breaker_key}=True) and is treated as the more likely source "
                f"of the conflict."
            )
        if val_b and not val_a:
            return policy_b, (
                f"Timestamps are identical or unavailable. Falling back to policy "
                f"scope: '{policy_b['owner']}''s policy is broader "
                f"({tie_breaker_key}=True) and is treated as the more likely source "
                f"of the conflict."
            )

    return None, (
        "Timestamps are identical and no reliable tie-breaker is available. "
        "Both teams should review this conflict jointly."
    )


def enrich_conflict_with_attribution(conflict, policy_a, policy_b, tie_breaker_key=None):
    """
    Take a raw conflict dict (from any detector) and attach a formal,
    time-drift-aware attribution decision to it.
    """
    at_fault_policy, reasoning = determine_at_fault(policy_a, policy_b, tie_breaker_key)

    conflict["formal_attribution"] = {
        "at_fault_owner": at_fault_policy["owner"] if at_fault_policy else "joint-review-needed",
        "reasoning": reasoning,
        "policy_a_timestamp": policy_a.get("created_at"),
        "policy_b_timestamp": policy_b.get("created_at"),
    }
    return conflict


if __name__ == "__main__":
    # Quick test using your real seeded subsumption conflict data
    policy_a = {
        "owner": "security-team",
        "created_at": "2026-08-22T07:26:54+00:00",
        "is_wildcard_grant": False,
    }
    policy_b = {
        "owner": "backend-team",
        "created_at": "2026-08-22T07:26:54+00:00",
        "is_wildcard_grant": True,
    }

    at_fault, reasoning = determine_at_fault(policy_a, policy_b, tie_breaker_key="is_wildcard_grant")
    print(f"At fault: {at_fault['owner'] if at_fault else 'none determined'}")
    print(f"Reasoning: {reasoning}")
