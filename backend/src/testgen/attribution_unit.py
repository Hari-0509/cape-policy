import sys
sys.path.insert(0, "src")
from attribution.attribution import determine_at_fault, confidence_label
T = "2026-01-01T00:"
S = [
 ("gap > 60 s", {"owner": "A", "created_at": T+"00:00"}, {"owner": "B", "created_at": T+"05:00"}, None, "B"),
 ("gap > 60 s, reversed", {"owner": "A", "created_at": T+"05:00"}, {"owner": "B", "created_at": T+"00:00"}, None, "A"),
 ("gap <= 60 s", {"owner": "A", "created_at": T+"00:00"}, {"owner": "B", "created_at": T+"00:30"}, None, "B"),
 ("tie, wildcard on A", {"owner": "A", "created_at": T+"00:00", "w": True}, {"owner": "B", "created_at": T+"00:00", "w": False}, "w", "A"),
 ("tie, wildcard on B", {"owner": "A", "created_at": T+"00:00", "w": False}, {"owner": "B", "created_at": T+"00:00", "w": True}, "w", "B"),
 ("no timestamp, no tie-breaker", {"owner": "A"}, {"owner": "B"}, None, None),
 ("missing timestamp, tie-breaker", {"owner": "A", "w": True}, {"owner": "B", "w": False}, "w", "A"),
 ("exactly 60 s", {"owner": "A", "created_at": T+"00:00"}, {"owner": "B", "created_at": T+"01:00"}, None, "B"),
 ("days apart", {"owner": "A", "created_at": "2026-01-01T00:00:00"}, {"owner": "B", "created_at": "2026-01-05T00:00:00"}, None, "B"),
 ("tie, no signal", {"owner": "A", "created_at": T+"00:00", "w": False}, {"owner": "B", "created_at": T+"00:00", "w": False}, "w", None),
]
ok = 0
for name, a, b, key, truth in S:
    p, score, _ = determine_at_fault(a, b, key)
    got = p["owner"] if p else None
    ok += got == truth
    print(f"{name:<32} got={str(got):<5} truth={str(truth):<5} {'OK' if got == truth else 'FAIL'}  label={confidence_label(score)}")
print(f"{ok}/{len(S)} agree")
