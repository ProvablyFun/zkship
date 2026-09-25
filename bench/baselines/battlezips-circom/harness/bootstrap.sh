#!/usr/bin/env bash
# From-scratch bootstrap of the BattleZips-Circom baseline (no sudo needed).
# Idempotent: skips steps whose outputs already exist. Then run harness/setup.sh and harness/run_full.sh.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE="$(dirname "$HERE")"
UPSTREAM_COMMIT=d6f6b0ed0a5876cc0a5d374291be49627e32ae07
CIRCOM_SHA256=85342c7ff332d948df7c0c50ecf201e6129349aef550ce873f3c811b79fe53a3

# 1. upstream repo at the pinned commit
[ -d "$BASE/upstream/.git" ] || git clone https://github.com/BattleZips/BattleZips-Circom "$BASE/upstream"
git -C "$BASE/upstream" checkout -q "$UPSTREAM_COMMIT"

# 2. Node 16.17.1 (upstream README's version) + yarn v1 frozen-lockfile install
export NVM_DIR="${NVM_DIR:-$HOME/.nvm}"
# shellcheck disable=SC1091
source "$NVM_DIR/nvm.sh" >/dev/null
nvm install 16.17.1 >/dev/null
nvm use 16.17.1 >/dev/null
[ -d "$BASE/upstream/node_modules/snarkjs" ] || (cd "$BASE/upstream" && npx -y yarn@1.22.22 install --frozen-lockfile)

# 3. hardhat accounts: hardhat.config.js derives accounts from $MNEMONIC; use the standard test mnemonic
[ -f "$BASE/upstream/.env" ] || echo 'MNEMONIC=test test test test test test test test test test test junk' > "$BASE/upstream/.env"

# 4. circom 2.2.3 prebuilt release binary
mkdir -p "$BASE/tools/bin"
if [ ! -x "$BASE/tools/bin/circom-2.2.3" ]; then
  curl -fsSL -o "$BASE/tools/bin/circom-2.2.3" https://github.com/iden3/circom/releases/download/v2.2.3/circom-linux-amd64
  chmod +x "$BASE/tools/bin/circom-2.2.3"
fi
echo "$CIRCOM_SHA256  $BASE/tools/bin/circom-2.2.3" | sha256sum -c

# 5. rapidsnark (native prover)
[ -x "$BASE/tools/bin/rapidsnark-prover" ] || bash "$BASE/tools/build_rapidsnark.sh"
echo "bootstrap done. next: harness/setup.sh  then  harness/run_full.sh"
