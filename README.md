# CAPE-Policy
Detects cross-team policy findings in Kubernetes clusters (RBAC, Gatekeeper, Kyverno, NetworkPolicy).

## What it is and is not
A research prototype. Findings are potential anomalies for human review, plus one confirmed category
(policy-induced runtime failure). It is not a production security tool and its attribution is heuristic.

## Requirements
Tested versions: see backend/ENVIRONMENT.md. Python packages: backend/requirements.lock.

## Quick start
1. kind cluster, Gatekeeper, Kyverno (commands in docs/SETUP.md)
2. kubectl label namespace <team-ns> cape-policy/class=application
3. cd backend && python src/ingestion/collector.py > data/latest_scan.json && python src/detection/engine.py

## Reproducing the paper's tables
Run ./reproduce.sh <target> from backend/. Targets are listed by running it with no argument.

## Data
- backend/tests/corpus: 104 generated cases, manifest, results (generator seed 20261018)
- backend/tests/independent: 24 separately written cases and labels.csv
- backend/tests/*.json, backend/realworld: raw results

## Limitations
See Section VII of the paper. The demo dashboard uses a hard-coded login, for demonstration only.

## License and citation
LICENSE (add one; MIT or Apache-2.0 are common). CITATION.cff.  DOI: [TODO after release]
