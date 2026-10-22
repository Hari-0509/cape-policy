import platform, os, json
def _cpu():
    for l in open("/proc/cpuinfo"):
        if l.startswith("model name"): return l.split(":", 1)[1].strip()
def _ram():
    for l in open("/proc/meminfo"):
        if l.startswith("MemTotal"): return round(int(l.split()[1]) / 1048576, 1)
def info():
    return {"platform": platform.platform(), "cpu": _cpu(), "logical_cpus": os.cpu_count(),
            "ram_gb_visible": _ram(), "python": platform.python_version()}
if __name__ == "__main__": print(json.dumps(info(), indent=1))
