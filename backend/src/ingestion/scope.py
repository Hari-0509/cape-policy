"""Namespace scope helpers shared by the detectors."""
import fnmatch


def selector_matches(selector, labels):
    labels = labels or {}
    for k, v in (selector.get("matchLabels") or {}).items():
        if labels.get(k) != v:
            return False
    for e in (selector.get("matchExpressions") or []):
        key, op, vals = e.get("key"), e.get("operator"), e.get("values") or []
        if op == "In" and labels.get(key) not in vals: return False
        if op == "NotIn" and labels.get(key) in vals: return False
        if op == "Exists" and key not in labels: return False
        if op == "DoesNotExist" and key in labels: return False
    return True


def _expand(patterns, names):
    out = set()
    for p in patterns or []:
        if any(ch in p for ch in "*?["):
            out |= {n for n in names if fnmatch.fnmatch(n, p)}
        else:
            out.add(p)
    return out


def effective_namespaces(include, selector, excluded, all_namespaces):
    """all_namespaces: [{'name':..., 'labels': {...}}]. No include list and no
    selector means the policy applies to every namespace."""
    names = [n["name"] for n in all_namespaces]
    if not include and not selector:
        covered = set(names)
    else:
        covered = _expand(include, names)
        if selector:
            covered |= {n["name"] for n in all_namespaces if selector_matches(selector, n.get("labels"))}
    return covered - _expand(excluded, names)
