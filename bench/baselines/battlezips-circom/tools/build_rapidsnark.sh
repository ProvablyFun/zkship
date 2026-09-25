#!/usr/bin/env bash
# Build rapidsnark (native Groth16 prover) without sudo:
#   * nasm 2.16.03 built from source into tools/local (rapidsnark needs it for the ffiasm x86_64 field code)
#   * GMP 6.3.0 built by rapidsnark's own build_gmp.sh into tools/rapidsnark/depends/gmp/package
#   * libsodium-dev and OpenMP (libgomp) come from the host system
# Result: tools/bin/rapidsnark-prover (-> tools/rapidsnark/package/bin/prover)
set -euo pipefail
T="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RAPIDSNARK_COMMIT="${RAPIDSNARK_COMMIT:-81eddf1a536d26497b237c0b8a04fe90baf7e439}"
mkdir -p "$T/src" "$T/local" "$T/bin"

if [ ! -x "$T/local/bin/nasm" ]; then
  cd "$T/src"
  [ -f nasm-2.16.03.tar.xz ] || curl -fsSLO https://www.nasm.us/pub/nasm/releasebuilds/2.16.03/nasm-2.16.03.tar.xz
  echo "1412a1c760bbd05db026b6c0d1657affd6631cd0a63cddb6f73cc6d4aa616148  nasm-2.16.03.tar.xz" | sha256sum -c
  rm -rf nasm-2.16.03 && tar xf nasm-2.16.03.tar.xz && cd nasm-2.16.03
  ./configure --prefix="$T/local" >/dev/null && make -j"$(nproc)" >/dev/null && make install >/dev/null
fi
export PATH="$T/local/bin:$PATH"
nasm -v

[ -d "$T/rapidsnark" ] || git clone https://github.com/iden3/rapidsnark "$T/rapidsnark"
cd "$T/rapidsnark"
git checkout -q "$RAPIDSNARK_COMMIT"
git submodule update --init --recursive -q
[ -f depends/gmp/package/lib/libgmp.a ] || ./build_gmp.sh host
make host
ln -sf "$T/rapidsnark/package/bin/prover" "$T/bin/rapidsnark-prover"
"$T/bin/rapidsnark-prover" 2>&1 | head -3 || true
