import csv, math, collections
def wilson(k, n, z=1.96):
    if n == 0: return (0, 0)
    p = k / n; d = 1 + z * z / n; c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0, c - h), min(1, c + h)
rows = list(csv.DictReader(open("realworld/findings_to_label.csv")))
a = [r["label1"].strip() for r in rows]; b = [r["label2"].strip() for r in rows]; n = len(rows)
cats = sorted(set(a) | set(b))
agree = sum(x == y for x, y in zip(a, b)) / n
pe = sum((a.count(c) / n) * (b.count(c) / n) for c in cats)
print(f"labeled={n} agreement={agree:.2f} kappa={(agree - pe) / (1 - pe) if pe < 1 else 1:.2f}")
by = collections.defaultdict(collections.Counter)
for r in rows: by[r["category"]][(r["final"] or r["label1"]).strip()] += 1
print(f"{'category':<28}{'labeled':>8}{'confirmed':>10}{'intentional':>12}{'unclear':>8}  precision (95% CI)")
for cat, c in by.items():
    t = sum(c.values()); lo, hi = wilson(c["confirmed"], t)
    print(f"{cat:<28}{t:>8}{c['confirmed']:>10}{c['intentional']:>12}{c['unclear']:>8}  {c['confirmed']/t:.2f} [{lo:.2f}-{hi:.2f}]")
