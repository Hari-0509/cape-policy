import os, sys, shutil, subprocess
sys.path.insert(0, "src"); sys.path.insert(0, ".")
from testgen import offline_eval as oe

HOME = os.path.expanduser("~")
TOOLS = {
    "checkov":    [f"{HOME}/baseline-venv/bin/checkov", "-f", "{f}", "--framework", "kubernetes", "-o", "json"],
    "kube-linter": ["kube-linter", "lint", "{f}", "--format", "json"],
    "kube-score": ["kube-score", "score", "{f}", "-o", "json"],
    "polaris":    ["polaris", "audit", "--audit-path", "{f}", "--format", "json"],
    "kubescape":  ["kubescape", "scan", "{f}", "--format", "json"],
}
mode = sys.argv[1] if len(sys.argv) > 1 else "independent"
cases = [c[0] for c in oe.load_cases(mode)]
for tool, tmpl in TOOLS.items():
    exe = tmpl[0]
    if not (os.path.exists(exe) or shutil.which(exe)):
        print(f"SKIP {tool}: not installed"); continue
    out_dir = f"tests/baselines/raw/{mode}/{tool}"; os.makedirs(out_dir, exist_ok=True)
    for f in cases:
        cmd = [a.replace("{f}", f) for a in tmpl]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            text = (r.stdout or "") + "\n" + (r.stderr or "")
        except Exception as e:
            text = f"TOOL_ERROR {e}"
        open(os.path.join(out_dir, os.path.basename(f) + ".txt"), "w").write(text)
    print(f"done {tool}: {len(cases)} files")
