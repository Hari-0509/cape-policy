import sys, math, yaml
sys.path.insert(0, "src"); sys.path.insert(0, ".")
from testgen import offline_eval as oe

NAIVE_TARGET = {"b1_same_subject": "subsumption", "b2_any_explicit_ns": "shadowing",
                "b3_any_cross_ns_grant": "cross_domain_misalignment"}


def wilson(k, n, z=1.96):
    if n == 0: return (0.0, 0.0)
    p = k / n; d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


mode = sys.argv[1] if len(sys.argv) > 1 else "generated"
cases = oe.load_cases(mode)
for T in oe.TYPES:
    subset = [(p, c, e) for p, c, e in cases if mode == "independent" or c == T]
    print(f"\n== {T}: n={len(subset)}, positives={sum(T in e for _, _, e in subset)}")
    for name, fn in oe.CONFIGS.items():
        if name in NAIVE_TARGET and NAIVE_TARGET[name] != T:
            continue
        tp = fp = tn = fneg = 0
        for path, _, exp in subset:
            scan, tns, ans = oe.docs_to_scan([d for d in yaml.safe_load_all(open(path)) if d])
            pred, truth = T in fn(scan, tns, ans), T in exp
            if pred and truth: tp += 1
            elif pred: fp += 1
            elif truth: fneg += 1
            else: tn += 1
        n = len(subset); ok = tp + tn; lo, hi = wilson(ok, n)
        prec = f"{tp/(tp+fp):.2f}" if tp + fp else "n/a"
        rec = f"{tp/(tp+fneg):.2f}" if tp + fneg else "n/a"
        print(f"{name:<26} acc {ok}/{n} [{lo:.2f}-{hi:.2f}]  prec {prec}  rec {rec}  (TP{tp} FP{fp} TN{tn} FN{fneg})")
