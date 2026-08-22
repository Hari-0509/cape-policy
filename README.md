# CAPE-Policy

**Ownership-Aware Cross-Policy Conflict Analysis for Multi-Team Kubernetes Clusters**

A tool that detects security policy conflicts between independently-authored
policies from different teams sharing a Kubernetes cluster (RBAC, OPA/Gatekeeper,
Kyverno, NetworkPolicy), and attributes each conflict to the responsible team.

## Status: In Development (Capstone Project)

## Structure
- `test-policies/` — seeded multi-team policy sets, including deliberate conflicts, used for testing
- `src/ingestion/` — Kubernetes API client, pulls policies from the cluster
- `src/graph/` — policy graph builder (NetworkX)
- `src/detection/` — conflict detection engine
- `src/attribution/` — ownership attribution logic
- `src/reporting/` — dashboard, JSON, CLI output
