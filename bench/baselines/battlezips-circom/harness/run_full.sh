#!/usr/bin/env bash
# Full (or smoke) benchmark run for the BattleZips-Circom baseline.
#
# usage: harness/run_full.sh [PROVE_ITERS=20] [VERIFY_ITERS=100] [GAS_GAMES=3] [CLI_ITERS=5] [OUT_DIR]
#   PROVE_ITERS  iterations per case for wtns/prove/fullProve (in-process) and rapidsnark
#   VERIFY_ITERS iterations per case for snarkjs groth16.verify
#   GAS_GAMES    number of complete scripted games replayed on the Hardhat network
#   CLI_ITERS    fresh-process `snarkjs groth16 prove` runs per case (peak-RSS rows); fullprove uses min(3, CLI_ITERS)
#   OUT_DIR      default harness/results/<UTC timestamp>
# env: WARMUP (default 1) warm-up iterations per in-process op, recorded but excluded from summary
#      PIN      optional CPU pinning prefix, e.g. PIN="taskset -c 0-15" (P-cores on the i7-14700K)
#
# Requires harness/setup.sh to have been run (keys under upstream/zk, verifiers regenerated).
# Outputs: timings.csv, gas.csv, gas_game_totals.csv, static.csv, env.json, summary.json, summary.txt
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$HERE/env.sh"

PROVE_ITERS="${1:-20}"
VERIFY_ITERS="${2:-100}"
GAS_GAMES="${3:-3}"
CLI_ITERS="${4:-5}"
OUT="${5:-$HERE/results/$(date -u +%Y%m%dT%H%M%SZ)}"
WARMUP="${WARMUP:-1}"
PIN="${PIN:-}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

for f in zk/zkey/board_final.zkey zk/zkey/shot_final.zkey zk/board_js/board.wasm zk/shot_js/shot.wasm zk/board_verification_key.json zk/shot_verification_key.json; do
  [ -f "$UP_DIR/$f" ] || { echo "missing $UP_DIR/$f: run harness/setup.sh first" >&2; exit 1; }
done

# ---- environment record
python3 - "$OUT/env.json" <<EOF
import json, subprocess, sys, platform, os
def sh(c):
    try: return subprocess.run(c, shell=True, capture_output=True, text=True).stdout.strip()
    except Exception as e: return str(e)
env = {
  "argv": {"prove_iters": $PROVE_ITERS, "verify_iters": $VERIFY_ITERS, "gas_games": $GAS_GAMES, "cli_iters": $CLI_ITERS, "warmup": $WARMUP, "pin": "$PIN"},
  "date_utc": sh("date -u +%FT%TZ"),
  "host": platform.node(), "kernel": platform.release(),
  "cpu": sh("lscpu | sed -n 's/^Model name: *//p'"), "nproc": os.cpu_count(),
  "governor": sh("cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"),
  "loadavg_at_start": sh("cat /proc/loadavg"),
  "node": sh("node -v"),
  "circom": sh("$CIRCOM --version"),
  "snarkjs": sh("node -p \"require('$UP_DIR/node_modules/snarkjs/package.json').version\""),
  "hardhat": sh("node -p \"require('$UP_DIR/node_modules/hardhat/package.json').version\""),
  "upstream_commit": sh("git -C $UP_DIR rev-parse HEAD"),
  "upstream_dirty_files": sh("git -C $UP_DIR status --porcelain"),
  "rapidsnark_commit": sh("git -C $BASE_DIR/tools/rapidsnark rev-parse HEAD"),
  "rapidsnark_binary": "$RAPIDSNARK",
  "artifact_sha256": sh("cd $UP_DIR && sha256sum zk/zkey/board_final.zkey zk/zkey/shot_final.zkey zk/board.r1cs zk/shot.r1cs zk/board_js/board.wasm zk/shot_js/shot.wasm").splitlines(),
}
json.dump(env, open(sys.argv[1], "w"), indent=2)
EOF
[ -f "$HARNESS_DIR/setup_out/setup_times.csv" ] && cp "$HARNESS_DIR/setup_out/setup_times.csv" "$OUT/setup_times.csv"

T0=$(date +%s)
echo "== bench_prove (prove=$PROVE_ITERS verify=$VERIFY_ITERS cli=$CLI_ITERS warmup=$WARMUP) -> $OUT"
$PIN node "$HARNESS_DIR/bench_prove.js" --out "$OUT" --prove-iters "$PROVE_ITERS" --verify-iters "$VERIFY_ITERS" \
  --cli-iters "$CLI_ITERS" --warmup "$WARMUP" 2>&1 | tee "$OUT/bench_prove.log"
echo "== static metrics"
node "$HARNESS_DIR/static_metrics.js" --out "$OUT" > "$OUT/static.log" 2>&1
echo "== gas ($GAS_GAMES game(s))"
( cd "$UP_DIR" && GAS_OUT="$OUT" GAS_GAMES="$GAS_GAMES" $PIN npx hardhat run "$HARNESS_DIR/gas.js" ) 2>&1 | tee "$OUT/gas.log"
echo "== summary"
node "$HARNESS_DIR/summarize.js" "$OUT"
echo "total harness wall: $(( $(date +%s) - T0 )) s   (results in $OUT)"
