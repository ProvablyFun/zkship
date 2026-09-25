# Common environment for all harness scripts (sourced).
# Node 16.17.1 is the version upstream's README says it was last built with; snarkjs 0.4.27's CLI
# also crashes on Node >= 20 (process.exit() called with a Uint8Array), so we pin it.
HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(dirname "$HARNESS_DIR")"
UP_DIR="$BASE_DIR/upstream"
NODE_VERSION="${NODE_VERSION:-16.17.1}"
export NVM_DIR="${NVM_DIR:-$HOME/.nvm}"
# shellcheck disable=SC1091
source "$NVM_DIR/nvm.sh" >/dev/null
nvm use "$NODE_VERSION" >/dev/null || { echo "nvm install $NODE_VERSION first" >&2; exit 1; }
CIRCOM="${CIRCOM:-$BASE_DIR/tools/bin/circom-2.2.3}"
RAPIDSNARK="${RAPIDSNARK:-$BASE_DIR/tools/bin/rapidsnark-prover}"
SNARKJS_CLI="$UP_DIR/node_modules/snarkjs/build/cli.cjs"
export HARNESS_DIR BASE_DIR UP_DIR CIRCOM RAPIDSNARK SNARKJS_CLI
