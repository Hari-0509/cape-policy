"""
CAPE-Policy: Contradiction Detector (causal version)
A pod failure counts as a policy-induced contradiction only when ALL hold:
  1. a Kyverno policy requiring readOnlyRootFilesystem targets the namespace
  2. the container itself sets readOnlyRootFilesystem: true
  3. the container has crashed or restarted
  4. the container's logs contain a 'Read-only file system' error
Unrelated crashes (missing paths, bad commands) are not reported.
"""

import json
from kubernetes import client, config
import sys
sys.path.insert(0, 'src')
from ingestion.scope import effective_namespaces, selector_matches

READONLY_MARKER = "read-only file system"


def _kyverno_scope(block):
    names, selectors, entries = set(), [], []
    if not block:
        return names, selectors
    entries += (block.get("any") or []) + (block.get("all") or [])
    if block.get("resources"):
        entries.append({"resources": block["resources"]})
    for e in entries:
        res = e.get("resources") or {}
        names.update(res.get("namespaces") or [])
        if res.get("namespaceSelector"):
            selectors.append(res["namespaceSelector"])
    return names, selectors


def get_restrictive_fs_policies():
    config.load_kube_config()
    nss = [{"name": n.metadata.name, "labels": n.metadata.labels or {}}
           for n in client.CoreV1Api().list_namespace().items]
    custom_api = client.CustomObjectsApi()
    policies = custom_api.list_cluster_custom_object(group="kyverno.io", version="v1", plural="clusterpolicies")
    restrictive = []
    for item in policies.get("items", []):
        metadata = item.get("metadata", {})
        labels = metadata.get("labels", {})
        for rule in item.get("spec", {}).get("rules", []):
            if "readOnlyRootFilesystem" not in str(rule.get("validate", {}).get("pattern", {})):
                continue
            inc, inc_sel = _kyverno_scope(rule.get("match"))
            exc, exc_sel = _kyverno_scope(rule.get("exclude"))
            covered = effective_namespaces(sorted(inc), inc_sel[0] if inc_sel else None, None, nss)
            excluded = set(exc)
            for sel in exc_sel:
                excluded |= {n["name"] for n in nss if selector_matches(sel, n["labels"])}
            restrictive.append({"policy_name": metadata.get("name"),
                                "owner": labels.get("owner-team", "unknown"),
                                "namespaces": sorted(covered - excluded)})
    return restrictive


def _container_logs(core_api, ns, pod_name, container):
    texts = []
    for previous in (False, True):
        try:
            raw = core_api.read_namespaced_pod_log(
                pod_name, ns, container=container, previous=previous,
                tail_lines=50, _preload_content=False)
            texts.append(raw.data.decode("utf-8", errors="replace"))
        except client.exceptions.ApiException:
            pass
    return "\n".join(texts).lower()


def find_policy_induced_failures(namespaces):
    core_api = client.CoreV1Api()
    findings = []
    for ns in namespaces:
        for pod in core_api.list_namespaced_pod(ns).items:
            for cs in (pod.status.container_statuses or []):
                state = cs.state
                failed = (
                    cs.restart_count > 0
                    or (state.terminated and state.terminated.exit_code not in (0, None))
                    or (state.waiting and state.waiting.reason == "CrashLoopBackOff")
                )
                if not failed:
                    continue
                spec = next((c for c in pod.spec.containers if c.name == cs.name), None)
                sets_ro = bool(spec and spec.security_context
                               and spec.security_context.read_only_root_filesystem)
                if not sets_ro:
                    continue
                logs = _container_logs(core_api, ns, pod.metadata.name, cs.name)
                if READONLY_MARKER in logs:
                    evidence = next((l for l in logs.splitlines() if READONLY_MARKER in l), "")
                    findings.append({
                        "namespace": ns,
                        "pod": pod.metadata.name,
                        "container": cs.name,
                        "owner": (pod.metadata.labels or {}).get("owner-team", "unknown"),
                        "evidence": evidence.strip(),
                    })
    return findings


# Alias so existing runner code keeps working
get_crashing_pods_writing_without_volume = find_policy_induced_failures


def detect_contradiction():
    conflicts = []
    for policy in get_restrictive_fs_policies():
        for fp in find_policy_induced_failures(policy["namespaces"]):
            if fp["owner"] == policy["owner"]:
                continue
            conflicts.append({
                "conflict_type": "policy_induced_failure",
                "finding_status": "confirmed (log evidence)",
                "policy_name": policy["policy_name"],
                "policy_owner": policy["owner"],
                "affected_namespace": fp["namespace"],
                "affected_pod": fp["pod"],
                "workload_owner": fp["owner"],
                "evidence": fp["evidence"],
                "explanation": (
                    f"Team '{policy['owner']}' enforces '{policy['policy_name']}' "
                    f"(readOnlyRootFilesystem) in namespace '{fp['namespace']}'. "
                    f"Pod '{fp['pod']}' from team '{fp['owner']}' sets the flag, so it "
                    f"passes admission, but it then fails with a read-only filesystem "
                    f"error at runtime: \"{fp['evidence']}\"."
                ),
                "at_fault_team": "both: constraint and workload are individually valid but incompatible",
                "severity": "medium",
            })
    return conflicts


if __name__ == "__main__":
    conflicts = detect_contradiction()
    print(f"Contradiction conflicts found: {len(conflicts)}\n")
    for c in conflicts:
        print(f"[{c['finding_status']}] {c['affected_pod']} in {c['affected_namespace']}")
        print(f"  evidence: {c['evidence']}\n")
