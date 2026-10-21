import csv
a = {r["file"].strip(): r["expected"].strip() for r in csv.DictReader(open("tests/independent/labels.csv"))}
b = {r["file"].strip(): r["label"].strip() for r in csv.DictReader(open("tests/independent/second_labeler.csv"))}
files = sorted(set(a) & set(b)); n = len(files)
agree = sum(a[f] == b[f] for f in files) / n
cats = sorted(set(a.values()) | set(b.values()))
pe = sum((sum(a[f] == c for f in files) / n) * (sum(b[f] == c for f in files) / n) for c in cats)
kappa = (agree - pe) / (1 - pe) if pe < 1 else 1.0
print(f"n={n}  agreement={agree:.2f}  kappa={kappa:.2f}")
for f in files:
    if a[f] != b[f]: print("DISAGREE", f, "| writer:", a[f], "| second:", b[f])
