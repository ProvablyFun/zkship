#!/usr/bin/env bash
# P0 benchmarks of the zkship implementation: environment, cold start, peak
# memory, per-operation timings, sizes, complete games, and networked games.
# Usage: bench/run_p0.sh [OUT_DIR]   (from anywhere; keep the machine idle)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WS="$ROOT/zkship"
OUT="${1:-$ROOT/bench/results/p0-$(date -u +%Y%m%dT%H%M%SZ)}"
BIN="$WS/target/release/zkb-bench"
# One P-core for single-threaded runs; distinct physical P-cores for the
# networked games (two players plus four proxy threads).
PIN1="${PIN1:-taskset -c 4}"
PINN="${PINN:-taskset -c 0,2,4,6,8,10}"
SETUP_ITERS="${SETUP_ITERS:-200}"
ANSWER_ITERS="${ANSWER_ITERS:-1000}"
GAMES="${GAMES:-30}"
NET_GAMES="${NET_GAMES:-5}"
COLD_RUNS="${COLD_RUNS:-20}"

mkdir -p "$OUT"
(cd "$WS" && cargo build --release --locked -p zkb-bench >/dev/null)

load=$(cut -d' ' -f1 /proc/loadavg)
if awk "BEGIN{exit !($load > 1.0)}"; then
  echo "warning: load average $load; results will be noisy" >&2
fi

{
  echo "{"
  echo "  \"date_utc\": \"$(date -u +%FT%TZ)\","
  echo "  \"commit\": \"$(git -C "$ROOT" rev-parse HEAD)\","
  echo "  \"dirty\": $(git -C "$ROOT" diff --quiet -- zkship && echo false || echo true),"
  echo "  \"rustc\": \"$(rustc -V)\","
  echo "  \"cpu\": \"$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs)\","
  echo "  \"logical_cpus\": $(nproc),"
  echo "  \"avx2\": $(grep -qw avx2 /proc/cpuinfo && echo true || echo false),"
  echo "  \"avx512ifma\": $(grep -qw avx512ifma /proc/cpuinfo && echo true || echo false),"
  echo "  \"governor\": \"$(cat /sys/devices/system/cpu/cpu4/cpufreq/scaling_governor 2>/dev/null || echo unknown)\","
  echo "  \"kernel\": \"$(uname -sr)\","
  echo "  \"mem_total_kb\": $(awk '/MemTotal/{print $2}' /proc/meminfo),"
  echo "  \"load_at_start\": \"$(cat /proc/loadavg)\","
  echo "  \"pin_single\": \"$PIN1\","
  echo "  \"pin_net\": \"$PINN\","
  echo "  \"setup_iters\": $SETUP_ITERS, \"answer_iters\": $ANSWER_ITERS, \"games\": $GAMES, \"net_games\": $NET_GAMES,"
  echo "  \"binary\": $("$BIN" env)"
  echo "}"
} > "$OUT/env.json"

echo "== cold start ($COLD_RUNS fresh processes)"
echo "phase,rules,ms" > "$OUT/cold_init.csv"
for _ in $(seq "$COLD_RUNS"); do $PIN1 "$BIN" cold-init >> "$OUT/cold_init.csv"; done

echo "== peak RSS"
echo "rules,max_rss_kb" > "$OUT/rss.csv"
for rules in standard no-touch; do
  kb=$(/usr/bin/time -v $PIN1 "$BIN" setup-once --rules "$rules" 2>&1 >/dev/null \
    | awk -F: '/Maximum resident/{gsub(/ /,"",$2); print $2}')
  echo "$rules,$kb" >> "$OUT/rss.csv"
done

echo "== sizes"
$PIN1 "$BIN" sizes --out "$OUT"

echo "== per-operation timings"
$PIN1 "$BIN" ops --out "$OUT" --setup-iters "$SETUP_ITERS" --answer-iters "$ANSWER_ITERS" --warmup 20 --fleets 20

echo "== complete games (in-process)"
for rules in standard no-touch; do
  for strategy in hunt-target random sweep; do
    $PIN1 "$BIN" games --out "$OUT" --rules "$rules" --strategy "$strategy" --games "$GAMES" --seed 1000 2>/dev/null
  done
done

echo "== networked games"
for rtt in 0 50 150; do
  $PINN "$BIN" net --out "$OUT" --rtt-ms "$rtt" --games "$NET_GAMES" --strategy hunt-target --seed 2000
done
# A constrained link: 10 Mbit/s, 50 ms RTT.
$PINN "$BIN" net --out "$OUT" --rtt-ms 50 --mbps 10 --games "$NET_GAMES" --strategy hunt-target --seed 2000

echo "load_at_end: $(cat /proc/loadavg)" >> "$OUT/notes.txt"
python3 "$ROOT/bench/summarize_p0.py" "$OUT" > "$OUT/summary.md"
echo "wrote $OUT"
