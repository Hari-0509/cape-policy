import re, os, csv
text = open("all_cases.txt", encoding="utf-8").read()
parts = re.split(r'^### (\S+)\s+expected=(\S+)\s*$', text, flags=re.M)
os.makedirs("tests/independent", exist_ok=True)
rows = []
for i in range(1, len(parts), 3):
    name, exp, body = parts[i], parts[i + 1], parts[i + 2]
    body = "\n".join(l for l in body.splitlines() if not l.strip().startswith("```")).strip()
    open(f"tests/independent/{name}", "w", encoding="utf-8").write(body + "\n")
    rows.append((f"tests/independent/{name}", exp))
with open("tests/independent/labels.csv", "w", newline="") as f:
    w = csv.writer(f); w.writerow(["file", "expected"]); w.writerows(rows)
print(len(rows), "cases written")
