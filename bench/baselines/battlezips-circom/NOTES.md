# BattleZips-Circom SNARK baseline: build, harness, findings

This is the reproducible baseline for comparing against our Pedersen + Bulletproofs zero-knowledge
Battleship (no chain). The baseline is BattleZips-Circom: circom 2 circuits, snarkjs Groth16 on
BN254, MiMCSponge board commitment, generated Solidity verifiers and a `BattleshipGame` contract,
all run through Hardhat.

Everything lives under `/home/user/src/provablyfun/baselines/battlezips-circom/`:

```
upstream/                 git clone of BattleZips-Circom, pinned commit (keys + build outputs land in upstream/zk/)
tools/bin/circom-2.2.3    circom prebuilt release binary
tools/rapidsnark/         rapidsnark source at pinned commit; tools/bin/rapidsnark-prover -> package/bin/prover
tools/local/bin/nasm      nasm 2.16.03 built from source (needed by rapidsnark, no sudo)
tools/build_rapidsnark.sh builds nasm + GMP + rapidsnark
harness/env.sh            pins Node 16.17.1 and tool paths (sourced by every script)
harness/bootstrap.sh      from-scratch clone/install/build (idempotent)
harness/setup.sh          one-time ptau + zkey setup, timed per step (BUILD TIME, not per game)
harness/bench_prove.js    witness / prove / fullProve / verify timings, snarkjs lib + CLI + rapidsnark
harness/static_metrics.js R1CS shape + artifact sizes
harness/gas.js            full scripted game on the Hardhat network; gas per tx
harness/summarize.js      CSV -> summary.json (median / p95 / mean / min / max / n) + summary.txt
harness/run_full.sh       runs all of the above for one results directory
harness/soundness/        forged-proof demonstration (see section 5)
harness/setup_out/        timings and logs from the one-time setup that was run
harness/smoke/            smoke-run output (2 prove iters, 3 verify iters, 1 game)
patches/                  diff of the upstream working tree after setup
```

## 1. Versions and commits

| component | version / commit | notes |
|---|---|---|
| BattleZips-Circom | `d6f6b0ed0a5876cc0a5d374291be49627e32ae07` (2024-07-02, "add benchmark") | HEAD of default branch on 2026-09-25 |
| circom | 2.2.3 (release binary `circom-linux-amd64`, sha256 `85342c7f…79fe53a3`) | default `--O1`; upstream pins nothing beyond `pragma circom 2.0.3` |
| circomlib | 2.0.5 | from yarn.lock |
| snarkjs | 0.4.27 | yarn.lock resolves `^0.4.13` to 0.4.27; it bundles ffjavascript 0.2.55 |
| hardhat | 2.11.2, default hardfork `arrowGlacier` (London gas schedule) | from yarn.lock |
| ethers | 5.7.1; circomlibjs 0.1.7 | from yarn.lock |
| solc | 0.6.11 (verifiers), 0.8.11 (game), optimizer on, 200 runs | upstream hardhat.config.js |
| Node | v16.17.1 via nvm | the version upstream's README names; see the deviations section for why not 24 |
| yarn | 1.22.22 (`npx yarn@1.22.22 install --frozen-lockfile`) | |
| rapidsnark | `81eddf1a536d26497b237c0b8a04fe90baf7e439` (`v0.0.8-2-g81eddf1`, 2026-04-16) | built natively, x86_64 asm, OpenMP on, GMP 6.3.0 built by its own `build_gmp.sh host` |
| rapidsnark submodules | ffiasm `aa90166d`, circom_runtime `83978507`, json `350ff4f7`, pistache `ae0da38c` | |
| nasm | 2.16.03 from source (sha256 `1412a1c7…aa616148`) | |
| machine | i7-14700K (8P+12E cores, 28 threads), 125 GB RAM, kernel 7.0.0-31, governor `powersave` | |

Artifact hashes from the setup that was run (keys come from a fresh random ceremony, so another setup run gives different
zkeys and verifiers; R1CS and wasm are deterministic for a given circom version):

```
c3bc0dc3d56b690e31fc19443ad3086a596ec7585fce58fbb3ba64fdd416ee71  zk/ptau/pot15_final.ptau
168c9fe75524f40e625c7f41006edd2fb4c0d23e0c622d4422a4004e1ec44c0d  zk/zkey/board_final.zkey
c598da857fc0188e7b985513d68814ebb0dbea14458c226983fea05920325863  zk/zkey/shot_final.zkey
3e8f6bebf93737f808b4cc46c3e6b098139fd5c2caeffa9d9ae26123bbe2f126  zk/board.r1cs
d42f2925e4c9ae648d3bd47423a19987bf1b36b500a9b93c494ac3f26faf7b1b  zk/shot.r1cs
cb3b3ea23bff1a610c033e5f4dcf990831f40b8dcaf00e4b7da6219b453aa9a8  zk/board_js/board.wasm
68d951c670b7e7af642cd6c3ea3ecaa2a5b264c29d60246f1be4eb048f6f1a50  zk/shot_js/shot.wasm
086178e753265fad69061d72691206967642a84c43d2aa9a3c6524507102c3b6  zk/board_verification_key.json
df731bd69ed9cd04c1e9d0754033a33627e19d34e39100c29e27df1561ab51b8  zk/shot_verification_key.json
4990e0997fc8ad73c5829dd5c4559b28681a3418868fcfb5c8ccfdad296396bf  contracts/BoardVerifier.sol
a68932875eb0f556f5255fdb718777413d9e67555b180c0568a4fbc2e65b3471  contracts/ShotVerifier.sol
```

## 2. Reproduce from scratch

```bash
cd /home/user/src/provablyfun/baselines/battlezips-circom
harness/bootstrap.sh        # clone+checkout upstream, nvm install 16.17.1, yarn frozen install, .env,
                            # circom 2.2.3 download (sha256-checked), nasm+GMP+rapidsnark build (~2 min)
harness/setup.sh ceremony   # one-time ptau (local pot15 ceremony) + zkeys + vkeys + Solidity verifiers + hardhat compile
                            #   use `harness/setup.sh hermez` to download the Hermez pot15 ptau instead of running the ceremony
harness/run_full.sh 20 100 3 5          # full timing run, see section 6
harness/soundness/demo.sh               # optional: forged-proof demonstration (section 5)
```

Here is what `bootstrap.sh` does, command by command:

```bash
git clone https://github.com/BattleZips/BattleZips-Circom upstream && git -C upstream checkout d6f6b0ed0a5876cc0a5d374291be49627e32ae07
source ~/.nvm/nvm.sh && nvm install 16.17.1 && nvm use 16.17.1
(cd upstream && npx -y yarn@1.22.22 install --frozen-lockfile)
echo 'MNEMONIC=test test test test test test test test test test test junk' > upstream/.env
curl -fsSL -o tools/bin/circom-2.2.3 https://github.com/iden3/circom/releases/download/v2.2.3/circom-linux-amd64 && chmod +x tools/bin/circom-2.2.3
tools/build_rapidsnark.sh   # nasm 2.16.03 ./configure --prefix=tools/local; git clone --recursive rapidsnark;
                            # checkout 81eddf1a; ./build_gmp.sh host; make host
```

`setup.sh` runs the commands of upstream `scripts/ptau.sh` and `scripts/circuits.sh` one at a time, with the
same arguments and in the same order. It changes only how the tools are invoked: `node node_modules/snarkjs/build/cli.cjs`
replaces `yarn snarkjs`, and the pinned `$CIRCOM` replaces whatever `circom` is on PATH. It also adds `--sym` to
the circom calls and runs `npx hardhat compile --force` at the end. Each step runs under `/usr/bin/time`.

## 3. Build-time setup: one-time ceremony and key generation (not per game)

Upstream ships no ptau or zkeys (both are gitignored). It does ship `contracts/{Board,Shot}Verifier.sol`,
generated from the authors' own keys. `setup.sh` regenerates those files, which it must do because the keys are new.
The local pot15 ceremony takes under two minutes on this machine, so no downloaded ptau was needed.
The Hermez option exists but was not used.

Recorded once, in `harness/setup_out/setup_times.csv`. Wall-clock seconds (peak RSS):

| phase | steps | wall (s) |
|---|---|---|
| ptau (phase 1, 2^15) | new 0.68, 3 contributions 4.24 / 4.06 / 3.83, verify 0.88, beacon 3.91, **prepare phase2 90.64**, verify final 4.26 (1.48 GB RSS) | **112.5** |
| circom compile | board 0.22, shot 0.16 | 0.38 |
| zkey (phase 2) | groth16 setup 10.31 / 11.07 (upstream runs this and then overwrites its output), zkey new 11.35 / 11.07, 3 contributions per circuit 2.2–4.0 each, verify 0003 13.2 / 13.1, beacon 2.0 / 3.3, verify final 12.0 / 11.7 | **117.2** |
| export | 2 vkeys + 2 Solidity verifiers, about 0.7 each | 2.8 |
| hardhat compile | first run, includes the solc 0.6.11 and 0.8.11 downloads | 4.35 |
| **total** | | **237 s (about 4 min)** |

About 70 s of the zkey phase is optional verification (`zkey verify` ×4) and upstream's redundant `groth16 setup` (×2).
The smallest honest key generation is `zkey new` + one contribution + `beacon` + vkey export:
about 11 + 3 + 3 + 0.7 ≈ 18 s per circuit.

## 4. Metrics: what each one means

Raw rows are written per iteration. `summarize.js` drops warm-up rows and reports median, p95 (nearest rank), mean, min, max and n.

**Benchmark cases.** Boards and shots are copied verbatim from upstream `test/utils/index.js`, so they are fixed and deterministic:
- `board`: Alice's board proof, with ships at (0,0..4, horizontal).
- `shot_hit`: Bob's board, Alice's shot [2,4], hit=1. This is the same input as upstream `test/benchmark.js`.
- `shot_miss`: Alice's board, Bob's shot [9,9], hit=0.

**`timings.csv`** (`bench_prove.js`):

| impl | op | measures |
|---|---|---|
| snarkjs-lib | wtns_calculate | `snarkjs.wtns.calculate(input, wasm, {type:'mem'})`: witness generation in WASM, in-process, including WASM instantiation |
| snarkjs-lib | groth16_prove | `snarkjs.groth16.prove(zkey, wtns)`: prover only. Witness precomputed, zkey read from file (page cache) each call |
| snarkjs-lib | fullprove | `snarkjs.groth16.fullProve(input, wasm, zkey)`: witness + prove. This is what upstream's tests and front end call |
| snarkjs-lib | groth16_verify | `snarkjs.groth16.verify(vkey, public, proof)`: off-chain verification (4-pairing check in WASM plus JSON parsing) |
| snarkjs-cli | groth16_prove / fullprove | a fresh `node cli.cjs groth16 prove\|fullprove …` process under `/usr/bin/time`. Wall includes Node startup and zkey load; `max_rss_kb` is **peak RSS** |
| rapidsnark | groth16_prove | native `prover zkey wtns proof.json public.json` under `/usr/bin/time`. Wall includes process start, zkey load and JSON write; `max_rss_kb` is peak RSS. Witness comes from snarkjs and is not included. Proofs are checked with `snarkjs.groth16.verify` on the first and last iteration (`ok` column) |

- The first `WARMUP` iterations (default 1) of each in-process op are written with `warmup=1` and excluded from the summary. They include curve and worker-thread initialisation.
- snarkjs uses worker threads (one per logical CPU, 28 here). rapidsnark uses OpenMP (default 28 threads).
- `user_s` / `sys_s` are CPU seconds for the CLI rows.

**`static.csv`** (`static_metrics.js`):
- Constraints, wires, public/private inputs, outputs and labels, as `snarkjs r1cs info` reports them. The raw CLI text is saved to `r1cs_info_*.txt`.
- Sizes in bytes of `.r1cs`, `.wasm`, final `.zkey`, `verification_key.json` and the verifier `.sol`, plus `proof.json`, `public.json` and `.wtns` as written by the snarkjs CLI.
- `proof_bytes_uncompressed` = 256. That is A (G1, 64 B) + B (G2, 128 B) + C (G1, 64 B), which equals the 8 × uint256 the verifier takes (`a[2], b[2][2], c[2]`).
- `proof_bytes_compressed_theoretical` = 128. Point compression is **not** accepted by the contract; this is for reference only.
- **What the contract actually takes in calldata** (ABI, static types):
  - `newGame` 292 B (selector + boardHash + 8 proof words)
  - `joinGame` 324 B (+ gameId)
  - `turn` 388 B (selector + gameId + bool hit + next shot[2] + 8 proof words). The board hash and the previous shot are read from storage, not from calldata.
  - `firstTurn` 100 B, with no proof.

  `gas.js` checks these numbers against real transaction data.

**`gas.csv` / `gas_game_totals.csv`** (`gas.js`, Hardhat in-process network, `arrowGlacier`):
- One row per transaction: `gas_used` from the receipt, and `calldata_bytes` / `calldata_gas` (EIP-2028: 16 per non-zero byte, 4 per zero byte).
- `exec_gas` = gas_used − 21000 − calldata_gas, with an extra − 32000 for contract creation.
- The game replays upstream `test/game.js` exactly:
  - deploy ShotVerifier, BoardVerifier, Forwarder (ERC-2771) and BattleshipGame
  - `newGame` (Alice's board proof), then `joinGame` (Bob's board proof), then `firstTurn([1,0])` with no proof
  - 16 × (Bob `turn` hit=1 proof, then Alice `turn` hit=0 proof), then a final Bob `turn` hit=1
  - Alice reaches 17 hits and wins.
- **Counts per game:** 2 board proofs, 33 shot proofs (**17 hit reports, 16 miss reports**), 36 gameplay transactions and 4 deployments. `gas.js` asserts that the winner is Alice with 17 hits.
- `bare_*Verifier.verifyProof` rows are an extra transaction sent straight to each verifier with a real proof. They isolate the cost of the Groth16 check and are **not** counted in the game total.
- `play_gas` = sum over the 36 gameplay transactions. `deploy_gas` = the 4 deployments.
- Gas varies by a few hundred between runs, because proof bytes are random and zero calldata bytes are cheaper, and between turns, because of zero→non-zero SSTOREs. Hence `GAS_GAMES` > 1.

**Fork sensitivity.** Groth16 verification cost is ecAdd/ecMul/ecPairing (EIP-1108) plus calldata; neither has changed since Istanbul. Two later forks matter:
- Shanghai's EIP-3860 would add about 2 gas per 32-byte word of initcode to the deployments (a few hundred gas).
- Prague's EIP-7623 calldata floor does not bind for these execution-heavy transactions.

## 5. What the circuits and contract actually enforce (read and tested)

### What they claim
The README says board.circom proves the placement is "within 10x10 range, does not collide with other ships,
mimcSponge integrity check". It says shot.circom proves "a given shot in the game hits or misses".

### Board circuit (`zk/circuits/board.circom`)
- Hash binding. This is sound:
  ```
  40    component hasher = MiMCSponge(15, 220, 1);
  42        hasher.ins[i] <== ships[i \ 3][i % 3];
  44    hash === hasher.outs[0];
  ```
- **Bounds.** `templates/shipRange.circom` does range-check, but with `LessThan(4)`:
  ```
  19    lt[0] = LessThan(4); // 4 bit number since max is 10
  20    lt[0].in[0] <== ship[0] + (n - 1);
  41    ship[2] * (ship[2] - 1) === 0;      // z binary: sound
  47    muxOk.out === 1;
  ```
  circomlib's `LessThan(4)` is `Num2Bits(5)` of `in[0] + 16 - in[1]`, with no range check on its inputs.
  With `in[1] = 10` it accepts any field element in [−6, 9], not just [0, 9].
  So coordinates p−6…p−1 ("negative") pass, and ships may start off-board. This follows from reading the code; it was not exercised.
- **Non-overlap is NOT enforced.** In `templates/placeShip.circom` every value that feeds the collision check is
  assigned with `<--`. That is a witness-only assignment, which creates no constraint:
  ```
  39        hCollision.in[i] <-- cellVal * (cellVal - 1) == 0;
  45        vCollision.in[i] <-- cellVal * (cellVal - 1) == 0;
  51    collisionMux.out === expectedCollision.out;
  57        toNumH.in[i] <-- boardH[i \ 10][i % 10];
  58        toNumV.in[i] <-- boardV[i \ 10][i % 10];
  ```
  `hCollision` / `vCollision` are `Bits2Num`, which does not constrain its inputs to be bits. A prover can simply set
  every `*Collision.in[i] = 1`. circom 2.2.3 `--inspect` flags these signals: "CA02 … hCollision.in … do not appear in any constraint of the father component".

### Shot circuit (`zk/circuits/shot.circom`)
- Shot range (the same `LessThan(4)` caveat applies) and hash binding:
  ```
  24-30  ltX/ltY = LessThan(4) … ltX.out * ltY.out === 1;
  36     hash === hasher.outs[0];
  63     hit === ors[3].out;
  ```
- **The hit/miss result is NOT constrained.** In `templates/hitShip.circom` the per-ship hit flags are
  computed in `var`s and moved into the mux with `<--`:
  ```
  34    mux.c[0] <-- hHit;
  35    mux.c[1] <-- vHit;
  37    hit <== mux.out;
  ```
  - `HitShip.shot[0..1]` appear in no constraint at all. circom `--inspect`: "CA01 … local signals shot … do not appear in any constraint".
  - circomlib's `OR()` is `out <== a + b - a*b`, with no booleanity check.
  - So a prover can make `hit` any value, for any shot, against any committed board.

### Demonstration (`harness/soundness/`)
`circuits/*_evil.circom` are copies of the upstream circuits. The only changes are to the `<--` lines, meaning
witness-generator code; the diff is below. They compile to an **R1CS byte-identical** to upstream's (sha256 checked, see
`r1cs_identity.txt`), so the honest `*_final.zkey`, vkey and Solidity verifiers apply unchanged. `demo.sh` output (`result.json`):

- **False miss.** Alice's shot [2,4] hits Bob's ship at (1,4) horizontal, but the forged proof reports it with public `hit=0`.
  - The honest wasm refuses the input: "Assert Failed … shot line 63".
  - The forged proof is accepted: `snarkjs_verify: true`, `solidity_verifyProof: true` (deployed ShotVerifier).
- **Overlapping board.** All 5 ships are placed at (0,0) horizontal, stacked on top of each other: 5 occupied cells instead of 17.
  - The honest wasm refuses: "Assert Failed … PlaceShip line 51".
  - The forged proof is accepted: `snarkjs_verify: true`, `solidity_verifyProof: true` (deployed BoardVerifier).

So the baseline's proofs **do not** give board validity (non-overlap) or shot soundness. Only the hash binding,
`z ∈ {0,1}` and the loose coordinate range are enforced. Fixing it would need `<==`-constrained hit and collision logic,
for example IsEqual-based cell matching, which would change constraint counts. Our timing numbers describe the circuits as shipped.

```diff
--- upstream/zk/circuits/templates/hitShip.circom
+++ harness/soundness/circuits/templates/hitShip.circom
-    mux.c[0] <-- hHit;
-    mux.c[1] <-- vHit;
+    // EVIL witness generator: report "no hit" regardless of the board (constraints unchanged)
+    mux.c[0] <-- 0;
+    mux.c[1] <-- 0;
--- upstream/zk/circuits/templates/placeShip.circom
+++ harness/soundness/circuits/templates/placeShip.circom
-        hCollision.in[i] <-- cellVal * (cellVal - 1) == 0;
+        hCollision.in[i] <-- 1; // EVIL: claim no collision (constraints unchanged)
-        vCollision.in[i] <-- cellVal * (cellVal - 1) == 0;
+        vCollision.in[i] <-- 1; // EVIL: claim no collision (constraints unchanged)
```
The copies also rewrite include paths to point at `upstream/node_modules`.

### Contract (`contracts/BattleshipGame.sol`, `IBattleshipGame.sol`)
- **No sinking proofs.** The game ends when a hit counter reaches 17. There is no per-ship "sunk" announcement or proof:
  ```
  IBattleshipGame.sol:28  uint256 public constant HIT_MAX = 17; // number of hits before all ships are sunk
  BattleshipGame.sol:146  if (_hit) game.hitNonce[(game.nonce - 1) % 2]++;
  BattleshipGame.sol:149  if (game.hitNonce[(game.nonce - 1) % 2] >= HIT_MAX) gameOver(_game);
  ```
- Each `turn` verifies one shot proof against the stored board hash, the stored previous shot and the claimed `_hit`:
  ```
  136  sv.verifyProof(a, [b_0, b_1], c, [boardHash, shot[0], shot[1], hitInt])
  ```
- **Repeated shots are accepted.** Shots are stored with no uniqueness or range check (lines 112, 152: `game.shots[game.nonce] = _next;`).
  A player could fire at one known hit cell 17 times and win, and an honest opponent would have to keep proving "hit".
  This comes from reading the code; it was not exercised.
- There is no timeout or forfeit, so a losing player can stall forever. Out-of-range shots are rejected only because the
  honest prover cannot build a witness for them, which also stalls the game.

## 6. Deviations from upstream

- **No source patches to upstream.** `git -C upstream status` after setup shows only:
  - `M contracts/BoardVerifier.sol`, `M contracts/ShotVerifier.sol`: regenerated by the setup, exactly as upstream
    `scripts/circuits.sh` does. Only the verifying-key constants change, 34 lines. The full diff is in
    `patches/upstream-worktree-after-setup.diff`; the stat is `2 files changed, 34 insertions(+), 34 deletions(-)`.
  - `upstream/.env` (gitignored) with `MNEMONIC=test test … junk`. `hardhat.config.js` derives the hardhat accounts
    from `MNEMONIC`; this is the standard Hardhat test mnemonic.
  - Build outputs that upstream gitignores: `zk/ptau`, `zk/zkey`, `zk/*.r1cs`, `*_js/`, vkeys, `artifacts/`, `cache/`.
- **Node 16.17.1 instead of 24.** The yarn install works on Node 24. But the snarkjs 0.4.27 CLI crashes on Node ≥ 20:
  `process.exit()` is called with a `Uint8Array` (`ERR_INVALID_ARG_TYPE` after `powersoftau contribute`).
  16.17.1 is also the version upstream's README says it was built with. The library API (prove/verify) does work on Node 24.
  If a Node 24 comparison is wanted, run `NODE_VERSION=24.12.0 harness/run_full.sh …`, but the snarkjs-cli rows may fail.
- **circom 2.2.3** (latest release) instead of "master as of 2022". It compiles the circuits unchanged, with the default `--O1`.
  Other circom versions may give slightly different constraint counts.
- The harness calls snarkjs as `node cli.cjs`, not `yarn snarkjs`. It never modifies upstream files.
- The upstream `test/game.js` suite also passes unchanged on this setup (`npx hardhat test test/game.js`: 5 passing, 38 s).
  See `harness/smoke/upstream_game_test.log`.

## 7. Smoke results (NOT the final numbers)

`harness/run_full.sh 2 3 1 2 harness/smoke`: 2 prove iterations after 1 warm-up, 3 verify iterations, 1 game, 2 CLI runs.
Another workload was active at the time (loadavg 4 / 13 / 16), so treat these as sanity values only.

| case | circuit (constraints / wires) | wtns | snarkjs prove | fullProve | snarkjs verify | snarkjs CLI prove (peak RSS) | rapidsnark prove (peak RSS) |
|---|---|---|---|---|---|---|---|
| board | 10 644 / 11 654, 1 public | 17 ms | 462 ms | 487 ms | 228 ms | 823 ms (798 MiB) | 110 ms (15 MiB) |
| shot_hit | 9 940 / 9 965, 4 public | 12 ms | 472 ms | 504 ms | 223 ms | 866 ms (749 MiB) | 121 ms (11 MiB) |
| shot_miss | same | 12 ms | 480 ms | 482 ms | 223 ms | 871 ms (747 MiB) | 121 ms (12 MiB) |

- Sizes:
  - zkey: board 6 166 080 B, shot 5 545 429 B
  - r1cs: board 1 898 996 B, shot 1 745 420 B
  - wasm: board 142 740 B, shot 112 517 B
  - vkey JSON: board 2 927 B, shot 3 476 B
  - proof.json ≈ 806 B; public.json 84 B (board), ≈ 101 B (shot)
  - binary proof 256 B
- Gas (1 game):

  | tx | gas_used | calldata |
  |---|---|---|
  | deploy ShotVerifier | 935 835 | |
  | deploy BoardVerifier | 861 867 | |
  | deploy Forwarder | 658 010 | |
  | deploy BattleshipGame | 1 335 228 | |
  | newGame | 327 568 | 292 B |
  | joinGame | 309 674 | 324 B |
  | firstTurn | 78 049 | |
  | turn (hit), n=17 | median 356 157 (range 331 087–373 269) | |
  | turn (miss), n=16 | median 332 863 (range 312 939–332 875) | |
  | bare BoardVerifier.verifyProof | 228 206 (exec 202 594) | |
  | bare ShotVerifier.verifyProof | 252 071 (exec 225 991) | |

  **One full game = 11 988 250 gas** in 36 transactions. Adding the deployments (3 790 940) gives **15 779 190**.
  There were 17 hits and 16 misses.

## 8. Full timing run

```bash
cd /home/user/src/provablyfun/baselines/battlezips-circom
harness/run_full.sh 20 100 3 5
#  args: PROVE_ITERS VERIFY_ITERS GAS_GAMES CLI_ITERS [OUT_DIR]   (defaults 20 100 3 5, OUT_DIR=harness/results/<UTC>)
#  env:  WARMUP=1   PIN="taskset -c 0-15"   (optional: P-core pinning on the hybrid i7-14700K)
```

- **Outputs** in `OUT_DIR`:
  - raw CSVs: `timings.csv`, `static.csv`, `gas.csv`, `gas_game_totals.csv`
  - `summary.json`: median / p95 / mean / min / max / n per (case, impl, op), gas per transaction kind, and game totals. It also includes `env.json` (versions, commits, artifact hashes, governor, loadavg) and the build-time `setup_times.csv` rows.
  - `summary.txt`, plus logs and proof artifacts
- **Estimated wall time: about 5 minutes on an idle machine.**
  - Per case, about 50 s:
    - 21 × (wtns 15 ms + prove 0.5 s + fullProve 0.5 s)
    - 101 × verify 0.22 s
    - 5 + 3 CLI runs × 0.85 s
    - 20 × rapidsnark 0.12 s
  - Three cases: about 2.7 min.
  - 3 games × about 40 s of proving plus Hardhat startup: about 2.2 min.
  - The setup is not rerun. Re-running `harness/setup.sh` adds about 4 min but creates new keys.

**Caveats for the paper**
- snarkjs and rapidsnark use every logical CPU by default. The governor is `powersave` and the CPU is hybrid, so report the thread count and pinning used.
- rapidsnark wall time on circuits this small is dominated by fixed overhead: process start, zkey load and OpenMP start-up with 28 threads (about 1.4 s of CPU for 0.11 s of wall).
