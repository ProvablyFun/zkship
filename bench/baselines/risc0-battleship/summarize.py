#!/usr/bin/env python3
"""Build runs.csv, summary.json, summary.md from an OUTDIR of run_full.sh.
Usage: summarize.py OUTDIR"""
import csv, json, os, statistics, sys
out = sys.argv[1]
rows = [json.loads(l) for l in open(os.path.join(out, "runs.jsonl")) if l.strip()]
cols = ["rep","proof","receipt","history_len","prove_s","verify_first_ms","verify_median_ms",
        "verify_min_ms","verify_max_ms","journal_B","seal_B","wire_json_B","wire_bincode_B",
        "inner_bincode_B","segment_receipts","segments","user_cycles","total_cycles",
        "hit","sunk","defeated","time_maxrss_kB","maxrss_self_kB","maxrss_children_kB",
        "process_wall_s","process_user_s","process_sys_s","rayon_num_threads_env","available_parallelism"]
with open(os.path.join(out, "runs.csv"), "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore"); w.writeheader()
    for r in rows: w.writerow(r)
metrics = ["prove_s","verify_first_ms","verify_median_ms","journal_B","seal_B","wire_json_B",
           "wire_bincode_B","segments","user_cycles","total_cycles","time_maxrss_kB",
           "maxrss_children_kB","process_wall_s","process_user_s"]
groups = {}
for r in rows:
    groups.setdefault((r["proof"], r["receipt"], r["history_len"]), []).append(r)
summ = []
for (p, k, h), rs in groups.items():
    e = {"proof": p, "receipt": k, "history_len": h, "n": len(rs)}
    for m in metrics:
        v = [r[m] for r in rs if r.get(m) is not None]
        if v: e[m] = {"median": statistics.median(v), "min": min(v), "max": max(v)}
    summ.append(e)
up = []
p = os.path.join(out, "upstream_bench.csv")
if os.path.exists(p) and os.path.getsize(p):
    ug = {}
    for r in csv.DictReader(open(p)):
        ug.setdefault((r["proof"], r["receipt_kind"], int(r["history_len"])), []).append(r)
    for (pp, k, h), rs in ug.items():
        e = {"proof": pp, "receipt": k, "history_len": h, "n": len(rs)}
        for m in ["prove_s","verify_ms","journal_B","seal_B","wire_json_B","user_cycles","total_cycles"]:
            v = [float(r[m]) for r in rs]
            e[m] = {"median": statistics.median(v), "min": min(v), "max": max(v)}
        up.append(e)
json.dump({"measure": summ, "upstream_bench": up,
           "meta": json.load(open(os.path.join(out, "meta.json")))},
          open(os.path.join(out, "summary.json"), "w"), indent=2)
kib = lambda b: b / 1024
with open(os.path.join(out, "summary.md"), "w") as f:
    f.write("| proof | receipt | hist | n | prove s med [min,max] | verify ms med (first-call med) | journal B | seal KiB | JSON KiB | bincode KiB | segs | peak RSS MiB med |\n")
    f.write("|---|---|---|---|---|---|---|---|---|---|---|---|\n")
    for e in summ:
        g = lambda m, s="median": e[m][s]
        f.write(f"| {e['proof']} | {e['receipt']} | {'-' if e['proof']=='commit' else e['history_len']} | {e['n']} | "
                f"{g('prove_s'):.2f} [{g('prove_s','min'):.2f}, {g('prove_s','max'):.2f}] | "
                f"{g('verify_median_ms'):.1f} ({g('verify_first_ms'):.1f}) | {g('journal_B'):.0f} | "
                f"{kib(g('seal_B')):.1f} | {kib(g('wire_json_B')):.1f} | {kib(g('wire_bincode_B')):.1f} | "
                f"{g('segments'):.0f} | {g('time_maxrss_kB')/1024:.0f} |\n")
    if up:
        f.write("\nUpstream `zk-battleship-bench` (unmodified), median over runs:\n\n")
        f.write("| proof | receipt | hist | n | prove s | verify ms | journal B | seal KiB | JSON KiB | user cycles |\n|---|---|---|---|---|---|---|---|---|---|\n")
        for e in up:
            g = lambda m: e[m]["median"]
            f.write(f"| {e['proof']} | {e['receipt']} | {e['history_len']} | {e['n']} | {g('prove_s'):.2f} | {g('verify_ms'):.1f} | "
                    f"{g('journal_B'):.0f} | {kib(g('seal_B')):.1f} | {kib(g('wire_json_B')):.1f} | {g('user_cycles'):.0f} |\n")
print(open(os.path.join(out, "summary.md")).read())
