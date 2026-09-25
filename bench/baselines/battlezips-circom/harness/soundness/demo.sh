#!/usr/bin/env bash
# Compile the *_evil circuits (witness-generator-only changes), check their R1CS is byte-identical to
# upstream's, then forge proofs against the upstream zkeys and verify them with snarkjs and with the
# generated Solidity verifiers on the Hardhat network. Result: harness/soundness/result.json
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$HERE/../env.sh"
mkdir -p "$HERE/build"
"$CIRCOM" "$HERE/circuits/board_evil.circom" -o "$HERE/build" --r1cs --wasm > "$HERE/build/compile.log" 2>&1
"$CIRCOM" "$HERE/circuits/shot_evil.circom"  -o "$HERE/build" --r1cs --wasm >> "$HERE/build/compile.log" 2>&1
for c in board shot; do
  a=$(sha256sum < "$UP_DIR/zk/$c.r1cs" | cut -d' ' -f1)
  b=$(sha256sum < "$HERE/build/${c}_evil.r1cs" | cut -d' ' -f1)
  if [ "$a" = "$b" ]; then echo "$c: R1CS identical ($a)"; else echo "$c: R1CS DIFFERS ($a vs $b)"; exit 1; fi
done | tee "$HERE/r1cs_identity.txt"
cd "$UP_DIR" && npx hardhat run "$HERE/demo.js"
