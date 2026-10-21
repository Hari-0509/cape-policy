import csv
rows = list(csv.DictReader(open("tests/independent/labels.csv")))
with open("tests/independent/second_labeler.csv", "w", newline="") as f:
    w = csv.writer(f); w.writerow(["file", "label"])
    for r in rows: w.writerow([r["file"], ""])
print("wrote tests/independent/second_labeler.csv with", len(rows), "blank rows")
