#!/bin/bash
# Usage (from backend/, venv active): ./reproduce.sh <target>
set -e
case "$1" in
  classification)       python src/testgen/summarize.py ;;
  ablation)             python src/testgen/offline_eval.py generated; python src/testgen/percat_eval.py generated ;;
  independent)          python src/testgen/offline_eval.py independent; python src/testgen/percat_eval.py independent; python src/testgen/independent_misses.py ;;
  attribution)          python src/testgen/attribution_unit.py ;;
  baselines)            for m in independent generated; do python src/testgen/baselines_run.py $m; python src/testgen/baselines_score.py $m; done ;;
  timing-analysis)      python src/testgen/bench_analysis.py ;;
  timing-collect)       python src/testgen/bench_collect.py 30 25,50,100,200 ;;
  timing-contradiction) python src/testgen/bench_contra.py ;;
  rerun-cluster-cases)  python src/testgen/runner.py; python src/testgen/contradiction_runner.py ;;
  *) echo "targets: classification ablation independent attribution baselines timing-analysis timing-collect timing-contradiction rerun-cluster-cases"; exit 1 ;;
esac
