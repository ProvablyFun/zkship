#!/usr/bin/env bash
# One-time BUILD-TIME setup for the BattleZips-Circom baseline, timed per step.
#
# This is a step-by-step transcription of upstream scripts/ptau.sh + scripts/circuits.sh
# (same commands, same order, same parameters), with each step wrapped in /usr/bin/time so
# we get wall-clock + peak RSS per step. Differences from upstream:
#   * snarkjs is invoked as `node node_modules/snarkjs/build/cli.cjs` instead of `yarn snarkjs`
#     (avoids yarn's own ~0.3 s startup being charged to every step);
#   * circom is invoked via $CIRCOM (pinned binary) instead of whatever `circom` is on PATH.
#
# Usage: harness/setup.sh [ceremony|hermez]
#   ceremony (default): run upstream's local pot15 powers-of-tau ceremony (ptau.sh).
#   hermez            : download the Hermez/Polygon perpetual ptau (2^15) instead, and only time
#                       the download + verify.
# Output: harness/setup_out/setup_times.csv (+ logs), keys under upstream/zk/.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$HERE/env.sh"
UP="$UP_DIR"
PTAU_MODE="${1:-ceremony}"
OUT="$HERE/setup_out"
mkdir -p "$OUT"
CSV="$OUT/setup_times.csv"
LOG="$OUT/setup.log"
: > "$LOG"
echo "phase,step,wall_s,user_s,sys_s,max_rss_kb" > "$CSV"

cd "$UP"
SNARKJS=(node "$SNARKJS_CLI")
{ echo "node $(node -v)"; "$CIRCOM" --version; echo "snarkjs $(node -p "require('$UP/node_modules/snarkjs/package.json').version")"; } | tee -a "$LOG"

step() { # step <phase> <name> <cmd...>
  local phase="$1" name="$2"; shift 2
  local tf; tf="$(mktemp)"
  echo "==> [$phase] $name: $*" | tee -a "$LOG"
  /usr/bin/time -f '%e,%U,%S,%M' -o "$tf" "$@" >>"$LOG" 2>&1
  echo "$phase,$name,$(cat "$tf")" | tee -a "$CSV"
  rm -f "$tf"
}
ent() { head -n 4096 /dev/urandom | openssl sha1; }

# ---------------------------------------------------------------- Phase 1 (ptau.sh)
mkdir -p zk/ptau
if [ "$PTAU_MODE" = "ceremony" ]; then
  step ptau new            "${SNARKJS[@]}" powersoftau new bn128 15 zk/ptau/pot15_0000.ptau -v
  step ptau contribute1    "${SNARKJS[@]}" powersoftau contribute zk/ptau/pot15_0000.ptau zk/ptau/pot15_0001.ptau --name="First contribution" -v -e="$(ent)"
  step ptau contribute2    "${SNARKJS[@]}" powersoftau contribute zk/ptau/pot15_0001.ptau zk/ptau/pot15_0002.ptau --name="Second contribution" -v -e="$(ent)"
  step ptau contribute3    "${SNARKJS[@]}" powersoftau contribute zk/ptau/pot15_0002.ptau zk/ptau/pot15_0003.ptau --name="Third contribution" -v -e="$(ent)"
  step ptau verify_0003    "${SNARKJS[@]}" powersoftau verify zk/ptau/pot15_0003.ptau
  step ptau beacon         "${SNARKJS[@]}" powersoftau beacon zk/ptau/pot15_0003.ptau zk/ptau/pot15_beacon.ptau 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 10 -n="Final Beacon"
  step ptau prepare_phase2 "${SNARKJS[@]}" powersoftau prepare phase2 zk/ptau/pot15_beacon.ptau zk/ptau/pot15_final.ptau -v
  step ptau verify_final   "${SNARKJS[@]}" powersoftau verify zk/ptau/pot15_final.ptau
elif [ "$PTAU_MODE" = "hermez" ]; then
  step ptau download_hermez curl -fsSL -o zk/ptau/pot15_final.ptau https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_15.ptau
  step ptau verify_final    "${SNARKJS[@]}" powersoftau verify zk/ptau/pot15_final.ptau
else
  echo "unknown ptau mode $PTAU_MODE" >&2; exit 2
fi

# ---------------------------------------------------------------- Phase 2 (circuits.sh)
mkdir -p zk/zkey
step compile board_circom "$CIRCOM" zk/circuits/board.circom -o zk/ --r1cs --wasm --sym
step compile shot_circom  "$CIRCOM" zk/circuits/shot.circom  -o zk/ --r1cs --wasm --sym

# upstream first runs a plain `groth16 setup` into *_final.zkey (later overwritten by the beacon step)
step zkey board_groth16_setup "${SNARKJS[@]}" groth16 setup zk/board.r1cs zk/ptau/pot15_final.ptau zk/zkey/board_final.zkey
step zkey shot_groth16_setup  "${SNARKJS[@]}" groth16 setup zk/shot.r1cs  zk/ptau/pot15_final.ptau zk/zkey/shot_final.zkey
step zkey board_new "${SNARKJS[@]}" zkey new zk/board.r1cs zk/ptau/pot15_final.ptau zk/zkey/board_0000.zkey
step zkey shot_new  "${SNARKJS[@]}" zkey new zk/shot.r1cs  zk/ptau/pot15_final.ptau zk/zkey/shot_0000.zkey
step zkey board_contribute1 "${SNARKJS[@]}" zkey contribute zk/zkey/board_0000.zkey zk/zkey/board_0001.zkey --name="First board contribution" -v -e="$(ent)"
step zkey shot_contribute1  "${SNARKJS[@]}" zkey contribute zk/zkey/shot_0000.zkey zk/zkey/shot_0001.zkey --name="First shot contribution" -v -e="$(ent)"
step zkey board_contribute2 "${SNARKJS[@]}" zkey contribute zk/zkey/board_0001.zkey zk/zkey/board_0002.zkey --name="Second board contribution" -v -e="$(ent)"
step zkey shot_contribute2  "${SNARKJS[@]}" zkey contribute zk/zkey/shot_0001.zkey zk/zkey/shot_0002.zkey --name="Second shot contribution" -v -e="$(ent)"
step zkey board_contribute3 "${SNARKJS[@]}" zkey contribute zk/zkey/board_0002.zkey zk/zkey/board_0003.zkey --name="Third board contribution" -v -e="$(ent)"
step zkey shot_contribute3  "${SNARKJS[@]}" zkey contribute zk/zkey/shot_0002.zkey zk/zkey/shot_0003.zkey --name="Third shot contribution" -v -e="$(ent)"
step zkey board_verify_0003 "${SNARKJS[@]}" zkey verify zk/board.r1cs zk/ptau/pot15_final.ptau zk/zkey/board_0003.zkey
step zkey shot_verify_0003  "${SNARKJS[@]}" zkey verify zk/shot.r1cs  zk/ptau/pot15_final.ptau zk/zkey/shot_0003.zkey
step zkey board_beacon "${SNARKJS[@]}" zkey beacon zk/zkey/board_0003.zkey zk/zkey/board_final.zkey 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 10 -n="Board FinalBeacon phase2"
step zkey shot_beacon  "${SNARKJS[@]}" zkey beacon zk/zkey/shot_0003.zkey zk/zkey/shot_final.zkey 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 10 -n="Shot Final Beacon phase2"
step zkey board_verify_final "${SNARKJS[@]}" zkey verify zk/board.r1cs zk/ptau/pot15_final.ptau zk/zkey/board_final.zkey
step zkey shot_verify_final  "${SNARKJS[@]}" zkey verify zk/shot.r1cs  zk/ptau/pot15_final.ptau zk/zkey/shot_final.zkey
step export board_vkey "${SNARKJS[@]}" zkey export verificationkey zk/zkey/board_final.zkey zk/board_verification_key.json
step export shot_vkey  "${SNARKJS[@]}" zkey export verificationkey zk/zkey/shot_final.zkey  zk/shot_verification_key.json
step export board_sol  "${SNARKJS[@]}" zkey export solidityverifier zk/zkey/board_final.zkey contracts/BoardVerifier.sol
sed -i 's/contract Verifier/contract BoardVerifier/g' contracts/BoardVerifier.sol
step export shot_sol   "${SNARKJS[@]}" zkey export solidityverifier zk/zkey/shot_final.zkey contracts/ShotVerifier.sol
sed -i 's/contract Verifier/contract ShotVerifier/g' contracts/ShotVerifier.sol

# hardhat compile (solc download on first run is network-bound; time it anyway)
step hardhat compile npx hardhat compile --force

sha256sum zk/ptau/pot15_final.ptau zk/zkey/board_final.zkey zk/zkey/shot_final.zkey \
  zk/board.r1cs zk/shot.r1cs zk/board_js/board.wasm zk/shot_js/shot.wasm \
  zk/board_verification_key.json zk/shot_verification_key.json \
  contracts/BoardVerifier.sol contracts/ShotVerifier.sol | tee "$OUT/artifact_sha256.txt"
echo "setup done; timings in $CSV"
