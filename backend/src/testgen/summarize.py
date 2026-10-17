import json, statistics as st
main = [r for r in json.load(open("tests/corpus/results.json"))["results"] if r["correct"] is not None]
con = json.load(open("tests/corpus/contradiction_results.json"))["results"]
rows, by = main + con, {}
for r in rows:
    d = by.setdefault(r["type"], dict(n=0, ok=0, tp=0, fp=0, tn=0, fn=0))
    d["n"] += 1; d["ok"] += bool(r["correct"])
    if r["expected"] and r["detected"]: d["tp"] += 1
    elif not r["expected"] and r["detected"]: d["fp"] += 1
    elif not r["expected"]: d["tn"] += 1
    else: d["fn"] += 1
print(f"{'type':<28}{'acc':>7}{'TP':>4}{'FP':>4}{'TN':>4}{'FN':>4}")
for t, d in by.items():
    print(f"{t:<28}{d['ok']/d['n']*100:>6.1f}%{d['tp']:>4}{d['fp']:>4}{d['tn']:>4}{d['fn']:>4}")
print("overall:", sum(d["ok"] for d in by.values()), "/", sum(d["n"] for d in by.values()))
pos = [r["poll_time_seconds"] for r in con if r["expected"] and r["detected"]]
print("contradiction detected positives:", len(pos), "poll times (s):", sorted(set(pos)))
