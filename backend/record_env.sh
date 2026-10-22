#!/bin/bash
{
echo "# Environment, generated $(date -u +%F)"
echo; echo "## Host"; python src/testgen/hw.py
echo; echo "## Tools"; kubectl version --client 2>&1 | head -2; kind version; helm version --short
echo; echo "## Cluster"; kubectl version 2>&1 | grep -i server; kubectl get nodes -o wide | head -3
echo; echo "## Gatekeeper images"; kubectl get deploy -n gatekeeper-system -o jsonpath='{range .items[*]}{.spec.template.spec.containers[*].image}{"\n"}{end}' 2>/dev/null
echo; echo "## Kyverno"; helm list -n kyverno 2>/dev/null
echo; echo "## Baseline tools"; ~/baseline-venv/bin/checkov --version 2>/dev/null; kube-linter version 2>/dev/null; kube-score version 2>/dev/null; polaris version 2>/dev/null; kubescape version 2>/dev/null | head -1
} > ENVIRONMENT.md
