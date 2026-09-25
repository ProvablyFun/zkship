#!/usr/bin/env bash
# Reproducible timing run for the RISC Zero "Ledger-Free Trustless Battleship"
# baseline (hadigghazi/Ledger-Free-Trustless-Battleship).
#
# Usage:  ./run_full.sh [R] [OUTDIR]
#   R       repetitions per configuration (default 5)
#   OUTDIR  output directory (default results/<UTC timestamp>)
#
# Environment knobs (all optional):
#   THREADS=N          export RAYON_NUM_THREADS=N to the host and the r0vm
#                      prover child (default: unset -> rayon uses every CPU in
#                      the affinity mask, i.e. 28 on the i7-14700K)
#   CPUSET=LIST        run every measured process under `taskset -c LIST`
#                      (e.g. CPUSET=0-15 = the 8 P-cores / 16 threads)
#   CONFIGS="..."      space-separated proof:receipt:hist triples
#                      (default: see DEFAULT_CONFIGS below)
#   VERIFY_REPS=K      in-process verification repeats per proof (default 20)
#   UPSTREAM_REPS=U    how many times to also run the UNMODIFIED upstream bench
#                      binary as a cross-check (default 1; 0 disables)
#   SKIP_BUILD=1       do not (re)build
#
# Outputs in OUTDIR:
#   meta.json               versions, commits, env, machine
#   runs.csv                one row per (rep, config) from r0bs-measure
#   runs.jsonl              the raw JSON line of every run
#   time/*.txt              raw `/usr/bin/time -v` output of every process
#   upstream_bench_rN.txt   raw stdout of each upstream bench run
#   upstream_bench.csv      its CSV rows, with a rep column
#   summary.json            median/min/max per config (+ upstream bench)
#   summary.md              the same as a markdown table
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
R="${1:-5}"
OUTDIR="${2:-$HERE/results/$(date -u +%Y%m%dT%H%M%SZ)}"
VERIFY_REPS="${VERIFY_REPS:-20}"
UPSTREAM_REPS="${UPSTREAM_REPS:-1}"
DEFAULT_CONFIGS="commit:composite:0 shot:composite:0 shot:composite:25 shot:composite:50 shot:composite:99 \
commit:succinct:0 shot:succinct:0 shot:succinct:25 shot:succinct:50 shot:succinct:99"
CONFIGS="${CONFIGS:-$DEFAULT_CONFIGS}"

export RISC0_HOME="$HERE/risc0-home"
R0VM="$(ls "$RISC0_HOME"/extensions/v3.0.5-cargo-risczero-*/r0vm)"
export RISC0_SERVER_PATH="$R0VM"
# Never allow mock proving / remote proving to sneak in.
unset RISC0_DEV_MODE RISC0_PROVER RISC0_EXECUTOR BONSAI_API_URL BONSAI_API_KEY
if [[ -n "${THREADS:-}" ]]; then export RAYON_NUM_THREADS="$THREADS"; else unset RAYON_NUM_THREADS; fi

MEASURE="$HERE/measure/target/release/r0bs-measure"
UPBENCH="$HERE/upstream/target/release/zk-battleship-bench"

if [[ "${SKIP_BUILD:-0}" != 1 ]]; then
  (cd "$HERE/upstream" && cargo build --release --locked -p host --bin zk-battleship-bench)
  (cd "$HERE/measure" && cargo build --release --locked)
fi

PIN=()
if [[ -n "${CPUSET:-}" ]]; then PIN=(taskset -c "$CPUSET"); fi

mkdir -p "$OUTDIR/time"
load1="$(cut -d' ' -f1 /proc/loadavg)"
if python3 -c "import sys; sys.exit(0 if float('$load1') > 2.0 else 1)"; then
  echo "WARNING: 1-min load average is $load1 -- other work is running; timings will be inflated." >&2
fi
echo "output: $OUTDIR"

# ---------------------------------------------------------------- meta ----
python3 - "$OUTDIR/meta.json" <<PY
import json, os, subprocess, sys, platform, datetime
def sh(c):
    try: return subprocess.run(c, shell=True, capture_output=True, text=True, cwd="$HERE").stdout.strip()
    except Exception as e: return f"ERR {e}"
meta = {
  "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
  "repetitions": int("$R"),
  "configs": "$CONFIGS".split(),
  "verify_reps": int("$VERIFY_REPS"),
  "upstream_reps": int("$UPSTREAM_REPS"),
  "upstream_commit": sh("git -C upstream rev-parse HEAD"),
  "upstream_dirty": sh("git -C upstream status --porcelain --untracked-files=no"),
  "risc0_zkvm_crate": "3.0.5 (Cargo.lock)",
  "r0vm_version": sh("$R0VM --version"),
  "r0vm_path": "$R0VM",
  "risc0_guest_rustc": sh("$RISC0_HOME/toolchains/*/bin/rustc --version"),
  "host_rustc": sh("cd upstream && rustc --version"),
  "rzup": sh("$RISC0_HOME/bin/rzup --version"),
  "RAYON_NUM_THREADS": os.environ.get("RAYON_NUM_THREADS"),
  "CPUSET": "${CPUSET:-}" or None,
  "cpu_model": sh("lscpu | sed -n 's/^Model name: *//p'"),
  "nproc": sh("nproc"),
  "affinity_nproc": sh("${PIN[*]:-} nproc"),
  "governor": sh("cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"),
  "no_turbo_or_boost": sh("cat /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null || cat /sys/devices/system/cpu/cpufreq/boost 2>/dev/null"),
  "mem_total": sh("grep MemTotal /proc/meminfo"),
  "kernel": platform.release(),
  "loadavg_at_start": open("/proc/loadavg").read().strip(),
  "image_ids_measure": sh("grep -h 'const .*_ID:' measure/target/release/build/methods-*/out/methods.rs"),
  "image_ids_upstream": sh("grep -h 'const .*_ID:' upstream/target/release/build/methods-*/out/methods.rs"),
}
json.dump(meta, open(sys.argv[1], "w"), indent=2)
PY

# --------------------------------------------------- per-config runs ------
# rep-major order: every config is measured once before any is repeated, so
# slow drift (thermal, background load) spreads across configs.
: > "$OUTDIR/runs.jsonl"
for rep in $(seq 1 "$R"); do
  for cfg in $CONFIGS; do
    IFS=: read -r proof receipt hist <<<"$cfg"
    tag="r${rep}_${proof}_${receipt}_h${hist}"
    echo "[$(date -u +%H:%M:%S)] rep $rep/$R  $proof $receipt |H|=$hist"
    line="$(/usr/bin/time -v -o "$OUTDIR/time/$tag.txt" "${PIN[@]}" "$MEASURE" \
            --proof "$proof" --receipt "$receipt" --hist "$hist" --verify-reps "$VERIFY_REPS")"
    python3 - "$OUTDIR/time/$tag.txt" "$rep" "$line" >> "$OUTDIR/runs.jsonl" <<'PY'
import json, re, sys
t = open(sys.argv[1]).read()
d = json.loads(sys.argv[3])
d["rep"] = int(sys.argv[2])
m = re.search(r"Maximum resident set size \(kbytes\): (\d+)", t); d["time_maxrss_kB"] = int(m.group(1))
m = re.search(r"Elapsed \(wall clock\) time.*: (.+)", t)
parts = [float(x) for x in m.group(1).strip().split(":")]
d["process_wall_s"] = sum(p * 60 ** i for i, p in enumerate(reversed(parts)))
d["process_user_s"] = float(re.search(r"User time \(seconds\): ([\d.]+)", t).group(1))
d["process_sys_s"] = float(re.search(r"System time \(seconds\): ([\d.]+)", t).group(1))
print(json.dumps(d))
PY
  done
done

# ------------------------------------------- upstream bench (cross-check) --
: > "$OUTDIR/upstream_bench.csv"
for rep in $(seq 1 "$UPSTREAM_REPS"); do
  echo "[$(date -u +%H:%M:%S)] upstream zk-battleship-bench run $rep/$UPSTREAM_REPS"
  /usr/bin/time -v -o "$OUTDIR/time/upstream_bench_r$rep.txt" "${PIN[@]}" "$UPBENCH" \
    > "$OUTDIR/upstream_bench_r$rep.txt"
  hdr="$(grep '^proof,' "$OUTDIR/upstream_bench_r$rep.txt")"
  [[ -s "$OUTDIR/upstream_bench.csv" ]] || echo "rep,$hdr" > "$OUTDIR/upstream_bench.csv"
  grep -E '^(commit|shot),' "$OUTDIR/upstream_bench_r$rep.txt" | sed "s/^/$rep,/" >> "$OUTDIR/upstream_bench.csv"
done

# ------------------------------------------------------------- summary -----
python3 "$HERE/summarize.py" "$OUTDIR"
echo "done: $OUTDIR"
