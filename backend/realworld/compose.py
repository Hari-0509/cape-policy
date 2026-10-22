"""Render real Helm charts, keep only RBAC and NetworkPolicy objects, assign each chart to a team,
and apply them. Team assignment is ours; the policies are the charts' own."""
import subprocess, yaml, random, json, sys

random.seed(20261018)
CHARTS = [  # (team, release, repo, repo_url, chart): verify each with `helm search repo` and drop broken ones
    ("platform", "ingress-nginx", "ingress-nginx", "https://kubernetes.github.io/ingress-nginx", "ingress-nginx"),
    ("platform", "cert-manager", "jetstack", "https://charts.jetstack.io", "cert-manager"),
    ("platform", "metrics-server", "metrics-server", "https://kubernetes-sigs.github.io/metrics-server/", "metrics-server"),
    ("observability", "kps", "prometheus-community", "https://prometheus-community.github.io/helm-charts", "kube-prometheus-stack"),
    ("observability", "grafana", "grafana", "https://grafana.github.io/helm-charts", "grafana"),
    ("delivery", "argo-cd", "argo", "https://argoproj.github.io/argo-helm", "argo-cd"),
    ("security", "external-secrets", "external-secrets", "https://charts.external-secrets.io", "external-secrets"),
    ("security", "vault", "hashicorp", "https://helm.releases.hashicorp.com", "vault"),
    ("apps", "traefik", "traefik", "https://traefik.github.io/charts", "traefik"),
    ("apps", "dashboard", "kubernetes-dashboard", "https://kubernetes.github.io/dashboard/", "kubernetes-dashboard"),
    ("data", "jaeger", "jaegertracing", "https://jaegertracing.github.io/helm-charts", "jaeger"),
]
KEEP = {"Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding", "NetworkPolicy"}


def sh(cmd, inp=None):
    return subprocess.run(cmd, input=inp, capture_output=True, text=True)


used, log = set(), []
for team, release, repo, url, chart in CHARTS:
    ns = f"rw-{team}"
    sh(["helm", "repo", "add", repo, url]); sh(["helm", "repo", "update", repo])
    r = sh(["helm", "template", release, f"{repo}/{chart}", "--namespace", ns, "--skip-crds"])
    if r.returncode != 0:
        log.append((release, "SKIPPED", r.stderr.strip().splitlines()[-1:] )); print("SKIP", release); continue
    docs = []
    for d in yaml.safe_load_all(r.stdout):
        if not d or d.get("kind") not in KEEP:
            continue
        md = d.setdefault("metadata", {})
        md.setdefault("labels", {})["owner-team"] = team
        if d["kind"] in ("Role", "RoleBinding", "NetworkPolicy"):
            md.setdefault("namespace", ns)
        for s in d.get("subjects", []) or []:
            if s.get("kind") == "ServiceAccount" and not s.get("namespace"):
                s["namespace"] = ns
        docs.append(d)
    used.add(ns)
    sh(["kubectl", "create", "namespace", ns])
    a = sh(["kubectl", "apply", "-f", "-"], yaml.dump_all(docs))
    log.append((release, f"{len(docs)} objects", a.returncode)); print(release, len(docs), "objects, apply rc", a.returncode)
for ns in used:
    sh(["kubectl", "label", "namespace", ns, "cape-policy/class=application", "--overwrite"])
json.dump(log, open("realworld/compose_log.json", "w"), indent=1, default=str)
