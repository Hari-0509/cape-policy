"""
CAPE-Policy: Contradiction/Lockout Detector
Detects when a security policy (e.g., readOnlyRootFilesystem requirement)
combines with a workload's actual runtime needs to make legitimate
deployments fail — even though each policy/spec is individually valid.
"""

import json
from kubernetes import client, config


def get_restrictive_fs_policies():
    """
    Pull Kyverno ClusterPolicies that enforce readOnlyRootFilesystem,
    and which namespaces they target.
    """
    config.load_kube_config()
    custom_api = client.CustomObjectsApi()

    policies = custom_api.list_cluster_custom_object(
        group="kyverno.io", version="v1", plural="clusterpolicies"
    )

    restrictive = []
    for item in policies.get("items", []):
        metadata = item.get("metadata", {})
        labels = metadata.get("labels", {})
        rules = item.get("spec", {}).get("rules", [])

        for rule in rules:
            pattern = str(rule.get("validate", {}).get("pattern", {}))
            if "readOnlyRootFilesystem" in pattern:
                match = rule.get("match", {}).get("any", [{}])[0]
                namespaces = match.get("resources", {}).get("namespaces", [])
                restrictive.append({
                    "policy_name": metadata.get("name"),
                    "owner": labels.get("owner-team", "unknown"),
                    "namespaces": namespaces,
                })
    return restrictive


def get_crashing_pods_writing_without_volume(namespaces):
    """
    Check pods in the given namespaces for CrashLoopBackOff/Error status
    combined with commands that write to a path not covered by a
    declared volumeMount — a strong signal of the lockout pattern.
    """
    core_api = client.CoreV1Api()
    conflicts_found = []

    for ns in namespaces:
        pods = core_api.list_namespaced_pod(ns)
        for pod in pods.items:
            statuses = pod.status.container_statuses or []
            is_failing = any(
                (s.state.waiting and s.state.waiting.reason == "CrashLoopBackOff")
                or (s.state.terminated and s.state.terminated.reason == "Error")
                for s in statuses
            )

            if not is_failing:
                continue

            for container in pod.spec.containers:
                command = " ".join(container.command or []) + " " + " ".join(container.args or [])
                mounted_paths = [vm.mount_path for vm in (container.volume_mounts or [])]

                # crude heuristic: does the command try to write somewhere
                # not covered by any declared mount?
                if "echo" in command or ">" in command or "write" in command.lower():
                    covered = any(path in command for path in mounted_paths)
                    if not covered:
                        conflicts_found.append({
                            "namespace": ns,
                            "pod": pod.metadata.name,
                            "container": container.name,
                            "owner": (pod.metadata.labels or {}).get("owner-team", "unknown"),
                            "command": command.strip(),
                            "declared_mounts": mounted_paths,
                        })
    return conflicts_found


def detect_contradiction():
    restrictive_policies = get_restrictive_fs_policies()
    conflicts = []

    for policy in restrictive_policies:
        failing_pods = get_crashing_pods_writing_without_volume(policy["namespaces"])

        for fp in failing_pods:
            if fp["owner"] == policy["owner"]:
                continue  # same team wrote both, not a cross-team conflict

            conflicts.append({
                "conflict_type": "contradiction",
                "policy_name": policy["policy_name"],
                "policy_owner": policy["owner"],
                "affected_namespace": fp["namespace"],
                "affected_pod": fp["pod"],
                "workload_owner": fp["owner"],
                "explanation": (
                    f"Team '{policy['owner']}' enforces '{policy['policy_name']}' "
                    f"(readOnlyRootFilesystem) in namespace '{fp['namespace']}', but "
                    f"team '{fp['owner']}''s pod '{fp['pod']}' attempts to write to a "
                    f"path with no declared writable volume mount. The pod passes "
                    f"admission control but fails at runtime, and neither team can "
                    f"tell from their own policy alone that the other's requirement "
                    f"is the root cause."
                ),
                "at_fault_team": "both — policy and workload spec are individually "
                                  "valid but incompatible together",
                "severity": "medium",
            })
    return conflicts


if __name__ == "__main__":
    conflicts = detect_contradiction()
    print(f"Contradiction conflicts found: {len(conflicts)}\n")
    for c in conflicts:
        print(f"--- CONFLICT: {c['conflict_type'].upper()} ---")
        print(f"Policy: {c['policy_name']} (owner: {c['policy_owner']})")
        print(f"Affected pod: {c['affected_pod']} in {c['affected_namespace']} (owner: {c['workload_owner']})")
        print(f"At fault: {c['at_fault_team']}")
        print(f"Explanation: {c['explanation']}")
        print()
