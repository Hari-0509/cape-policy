"""Ownership attribution with ordinal labels.
High needs corroboration; timestamp-only evidence is capped at Medium."""
from datetime import datetime


def parse_timestamp(ts):
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def determine_at_fault(policy_a, policy_b, tie_breaker_key=None):
    """Returns (at_fault_policy, internal_score, reasoning). The score is internal only."""
    ts_a, ts_b = parse_timestamp(policy_a.get("created_at")), parse_timestamp(policy_b.get("created_at"))
    if ts_a and ts_b and ts_a != ts_b:
        newer, older = (policy_a, policy_b) if ts_a > ts_b else (policy_b, policy_a)
        nts, ots = (ts_a, ts_b) if ts_a > ts_b else (ts_b, ts_a)
        gap = (nts - ots).total_seconds()
        return newer, (0.95 if gap > 60 else 0.75), (
            f"'{newer['owner']}' created this policy {gap:.0f}s after '{older['owner']}''s policy. "
            f"Creation time shows when an object first appeared, not when it was last changed.")
    if tie_breaker_key:
        va, vb = policy_a.get(tie_breaker_key), policy_b.get(tie_breaker_key)
        if va and not vb:
            return policy_a, 0.60, "Creation times are equal or missing; the broader grant is named by rule."
        if vb and not va:
            return policy_b, 0.60, "Creation times are equal or missing; the broader grant is named by rule."
    return None, 0.30, "No usable evidence; both teams should review jointly."


def confidence_label(score, corroborated=False):
    if score >= 0.90:
        return "High" if corroborated else "Medium"
    if score >= 0.50:
        return "Medium"
    return "Low"


def enrich_conflict_with_attribution(conflict, policy_a, policy_b, tie_breaker_key=None, corroborated=False):
    at_fault, score, reasoning = determine_at_fault(policy_a, policy_b, tie_breaker_key)
    conflict["formal_attribution"] = {
        "at_fault_owner": at_fault["owner"] if at_fault else "joint-review-needed",
        "confidence_label": confidence_label(score, corroborated),
        "evidence": "timestamps" if score >= 0.7 else ("fallback rule" if score >= 0.5 else "none"),
        "reasoning": reasoning,
        "internal_score": score,
    }
    return conflict
