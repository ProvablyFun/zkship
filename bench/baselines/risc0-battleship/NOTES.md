# Baseline: RISC Zero "Ledger-Free Trustless Battleship" (Ghazi, 2026)

Set up on 2026-09-25 on i7-14700K / 125 GB, CPU proving only. This directory
holds only the builds and **one** smoke run (R=1). Final timings still need to
be taken on a quiet machine with `run_full.sh`.

## 1. What is where

```
upstream/        git clone, UNMODIFIED (git status clean)
risc0-home/      private RISC0_HOME (rzup + r0vm/cargo-risczero 3.0.5 + guest rust 1.97.0).
                 Nothing was installed into ~/.risc0, ~/.cargo/bin or shell rc files.
measure/         r0bs-measure: small separate crate (one proof per process) that
                 path-depends on the unmodified upstream crates
run_full.sh      timing wrapper (R reps, CSV + JSON, /usr/bin/time -v)
summarize.py     rebuilds runs.csv / summary.{json,md} from an output dir
smoke/           the one smoke run (raw output; run_full.log = console)
build.log        upstream release build log
```

## 2. Versions and pins

| item | value |
|---|---|
| upstream repo | https://github.com/hadigghazi/Ledger-Free-Trustless-Battleship |
| upstream commit | `a8fdd56323d60821325fd5f8a393b1f3ba89ce45` (HEAD of default branch, 2026-07-07, "paper: revise prose for clarity and readability") |
| release tag | `v1.0.0` = `db2411991b5c55d4dc4cd03c0fd3f9c68b6319a7`; `git diff v1.0.0 HEAD` touches only README, CITATION.cff and docs/paper. **The code is identical to v1.0.0** (Zenodo DOI 10.5281/zenodo.21207531) |
| `risc0-zkvm` crate | 3.0.5 (Cargo.lock; manifests say `"3.0"`); `risc0-build` 3.0.5, `risc0-groth16` 3.0.4 |
| r0vm (the actual prover) | `risc0-r0vm 3.0.5` (from rzup component `cargo-risczero` 3.0.5) |
| rzup | 0.5.0 (binary from `risc0-artifacts.s3.us-west-2.amazonaws.com/rzup/prod/Linux-X64/rzup`, sha256 `7cdc1dd5…c6c1ca`) |
| guest toolchain | rzup `rust` 1.97.0 (`rustc 1.97.0-dev (e638c6cfe 2026-07-15)`). This is the newest rzup rust; the paper does not say which guest toolchain it used |
| host toolchain | `rust-toolchain.toml` says `channel = "stable"`, which here is rustc 1.95.0 (paper: "rustc 1.96") |
| guest image IDs | COMMIT_BOARD_ID `9dc11682cc496634553acc96e9a75a79305b04e6a241fce0efd09caa2772ec94`, PROVE_SHOT_ID `7ab8d54536acc468153dda8f70cbc5f00d00b8ded5c67c8523980177c19c3381`. The upstream and measure builds produce byte-identical guest ELFs |
| Cargo features (host) | `risc0-zkvm = { version = "3.0", features = ["disable-dev-mode"] }`. There is **no `prove` feature**, so `default_prover()` is the **ExternalProver**: every proof starts a fresh `r0vm` subprocess and talks to it over a local socket |

## 3. Reproduction

```bash
cd /home/user/src/provablyfun/baselines/risc0-battleship
export RISC0_HOME=$PWD/risc0-home          # run_full.sh sets this itself

# (re)install toolchain, if ever needed (CARGO_HOME only redirects rzup's symlinks):
CARGO_HOME=$PWD/risc0-home/cargo-shim risc0-home/bin/rzup install cargo-risczero 3.0.5
CARGO_HOME=$PWD/risc0-home/cargo-shim risc0-home/bin/rzup install rust 1.97.0

# build (run_full.sh does this unless SKIP_BUILD=1)
(cd upstream && cargo build --release --locked -p host --bin zk-battleship-bench)
(cd measure  && cargo build --release --locked)

# full timing run: R=5, all 28 threads (default)
./run_full.sh 5 results/r5-t28
# variants
THREADS=16 CPUSET=0-15 ./run_full.sh 5 results/r5-pcores   # 8 P-cores / 16 HT threads
UPSTREAM_REPS=5 ./run_full.sh 5                             # also repeat the upstream bench 5x
```

`run_full.sh` does four things:

1. Writes `meta.json`: commits, r0vm/rustc versions, image IDs, CPU, governor, load average, thread settings.
2. For rep in 1..R and each config (rep-major order), runs `r0bs-measure` once under `/usr/bin/time -v` (optionally under `taskset`). Each run appends one JSON line to `runs.jsonl`. The raw `time -v` output goes to `time/`.
3. Runs the **unmodified** `zk-battleship-bench` `UPSTREAM_REPS` times (default 1) as a cross-check. Its raw stdout goes to `upstream_bench_rN.txt` and its rows to `upstream_bench.csv`.
4. Calls `summarize.py`, which writes `runs.csv`, `summary.json` (median/min/max per config, for both sources) and `summary.md`.

Default configs are `{commit, shot|H|=0,25,50,99} x {composite, succinct}`, the upstream bench's own grid. Set `CONFIGS="shot:composite:99 ..."` to narrow it.

Threads: set `THREADS=N` to export `RAYON_NUM_THREADS=N`. The r0vm child inherits it, and the r0vm binary links rayon (`RAYON_NUM_THREADS` appears in its strings). If unset, rayon uses every CPU in the affinity mask, which is 28 here. `CPUSET` adds `taskset -c`. Both values go into `meta.json`. The smoke run used the default: unset, 28.

The script refuses mock proving: it unsets `RISC0_DEV_MODE`, `RISC0_PROVER`, `RISC0_EXECUTOR` and `BONSAI_*`, and the binary also bails if `RISC0_DEV_MODE` is set. Upstream compiles with `disable-dev-mode` in any case. The script also warns if the 1-minute load average is above 2.

## 4. What the upstream bench measures (`host/src/bin/bench.rs`)

The bench takes no flags or arguments. It prints CSV to stdout, one single run per row:
`proof,receipt_kind,history_len,prove_s,verify_ms,journal_B,seal_B,wire_json_B,user_cycles,total_cycles`

* Board: `random_fleet(StdRng::seed_from_u64(42))` plus a random salt. The shot is always (9,9). The history is `history_of_len(n)`, i.e. cells 0..n-1 in row-major order. For |H| ∈ {0,25,50,99}, under `ProverOpts::default()` (composite) and then `ProverOpts::succinct()`.
* `prove_s`: wall time around `default_prover().prove_with_opts(env, ELF, opts)`. The `ExecutorEnv` is built before the timer starts. Because the prover is external, the time **includes spawning r0vm, IPC, execution, proving, the receipt transfer, and the client's `verify_integrity`** of the returned receipt.
* `verify_ms`: a single call to the upstream `verify_commit` / `verify_shot`. These are `receipt.verify(IMAGE_ID)`, a journal decode, and the commitment / shot / history equality checks.
* `seal_B`: composite gives the sum over segment receipts of `get_seal_bytes().len()`; succinct gives the succinct seal bytes. Assumption receipts and claims are excluded.
* `wire_json_B`: `serde_json::to_vec(&receipt).len()`. This is what their relay sends. JSON encodes the `u32` seal words as decimal text, so it is about 2.6x the raw seal.
* It ends with a witness-independence check: executor user cycles for `prove_shot` on 20 random boards (|H|=30).

What it does **not** give you, and so `r0bs-measure` adds:
* repetitions and summary statistics;
* a separate process per proof, so peak RSS is per operation;
* a compact binary size (`bincode::serialize(&receipt)`, the standard risc0 serde binary encoding, round-trip verified);
* repeated verification (K=20, median/min/max, plus the first call separately to match upstream);
* segment count and paging/reserved cycles;
* hit/sunk/defeated as a sanity check;
* `getrusage` self versus children RSS.

`r0bs-measure` uses **the same timing boundaries, fleet, shot and histories** as the upstream bench, and the upstream `verify_*` functions.

Metric definitions in `runs.csv`:
- `prove_s`: as upstream. It includes the r0vm spawn, which is part of the real per-move latency of their system.
- `verify_first_ms`: the first verify call (= upstream `verify_ms`). `verify_median_ms`, `verify_min_ms` and `verify_max_ms` cover the next K calls on a warm process.
- `journal_B`, `seal_B`, `wire_json_B`: as upstream. `wire_bincode_B` is the bincode of the full `Receipt`. `inner_bincode_B` is the bincode of `InnerReceipt`, i.e. without the journal.
- `time_maxrss_kB`: from `/usr/bin/time -v`. It is the max RSS over the measured process and its reaped descendants, which in practice is the r0vm child; it is not a sum. `maxrss_self_kB` is the host process only (about 8 MB). `maxrss_children_kB` is the r0vm child.
- `process_wall_s` and `process_user_s` cover the whole process (prove + 21 verifies + serialization). user/wall gives the effective parallelism.

## 5. The comparator's paper: what it reports (verbatim)

File: `upstream/docs/paper/zk-battleship.tex` (and `.pdf`, which matches). Title: "Ledger-Free Trustless Battleship: Self-Contained Zero-Knowledge Shot Proofs with Public-History Binding", Hadi Ghazi, July 2026.

**Hardware / setup (Sec. "Evaluation", verbatim):**
> "All measurements are CPU-only on a consumer laptop: Intel Core Ultra~7 155H (22 hardware threads), 15\,GB RAM available to the measurement environment (WSL2, Ubuntu 22.04), \code{rustc} 1.96, \code{risc0-zkvm} 3.0.5, default composite receipts and \code{ProverOpts::succinct()} where indicated. Wire size is the JSON-serialized receipt as actually sent through the relay."

**Table 1 (verbatim values):**

| Proof | Receipt | \|H\| | Prove (s) | Verify (ms) | Journal (B) | Seal (KiB) | Wire (KiB) |
|---|---|---|---|---|---|---|---|
| commit | composite | -- | 21.0 | 34.5 | 128 | 215.7 | 554.1 |
| shot | composite | 0 | 30.0 | 34.3 | 152 | 215.7 | 554.1 |
| shot | composite | 25 | 47.2 | 27.1 | 352 | 238.2 | 613.6 |
| shot | composite | 50 | 41.1 | 28.2 | 552 | 238.2 | 614.4 |
| shot | composite | 99 | 42.3 | 32.8 | 944 | 238.2 | 616.1 |
| commit | succinct | -- | 54.3 | 31.1 | 128 | 217.4 | 569.5 |
| shot | succinct | 0 | 54.8 | 29.0 | 152 | 217.4 | 569.5 |
| shot | succinct | 99 | 76.8 | 27.1 | 944 | 217.4 | 572.8 |

Caption (verbatim):
> "Proving and verification cost (single runs; proving uses all 22 threads). $|\mathcal{H}|$ is the length of the bound shot history. Wire size is the JSON-serialized receipt as sent through the relay; Seal is the raw STARK seal within it."

So all numbers come from **single runs**, with no repetitions, variance or RSS reported. There are no succinct rows for |H|=25/50.

**Other quotable sentences:**
- Abstract: "On a commodity laptop CPU a shot proof takes between 30 and 47\,s to generate and about 30\,ms to verify, which is fast enough for turn-based play without special hardware."
- "Setup requires one commit proof per player, about 21\,s and produced concurrently on the two machines, plus a coin flip that takes under a millisecond. Each subsequent turn requires one shot proof, between 30 and 47\,s, along with verification of about 30\,ms and the relay round-trips."
- "Guest execution grows linearly in the bound history, from 20.3k user cycles at $|\mathcal{H}| = 0$ to 101.8k at $|\mathcal{H}| = 99$, but the prover pads execution into segments of a power-of-two length, so the cost of proving changes only when a segment boundary is crossed: an empty history occupies one segment of $2^{16}$ cycles, and every longer history in a full game fits within two."
- "its journal overhead stays under 1\,KB against a receipt of about 600\,KiB even at $|\mathcal{H}| = 99$"
- "A complete match of roughly 60 to 90 shots spends between 30 and 60 minutes proving, [...] and no single wait exceeds a minute on this hardware."
- "Succinct receipts compress an entire execution into a seal of constant size, 217.4\,KiB regardless of the history, at between 1.4 and 1.8 times the proving cost. At this circuit size a composite receipt spans only one or two segments, so succinctness saves nothing on the wire, and we use composite receipts by default."
- Witness independence: "Running the \textsf{shot} guest on a fixed shot and a 30-shot history across 20 random boards gives execution lengths between 45{,}147 and 45{,}173 cycles, a spread of 26 cycles, below 0.06\%"
- Protocol cost: "Each shot costs one proof, one verification, and a journal holding $O(|\mathcal{H}|)$ shot entries at two bytes each before serialization."
- Artifact: "All reported numbers are reproducible via \code{cargo run --release -p host --bin zk-battleship-bench} and the \code{--ignored} integration test suite."
- README: "a shot proof takes roughly half a minute on a modern laptop CPU".

**What the proofs establish** (paper Sec. "The protocol", checked against the guest code in `methods/guest/src/bin/*.rs`):
- **Board legality: yes.** The commit proof (`commit_board`) asserts `fleet.is_valid()`, meaning one of each of the 5 ships (17 cells), in bounds, with no overlap, and outputs `C = SHA-256(encode(B) || salt)` with a 256-bit salt. Paper: "runs the \textsf{commit} guest, which \emph{asserts} $\mathsf{legal}(B_P)$ (composition, bounds, non-overlap)". The shot proofs do **not** re-check legality. They re-derive C and assert equality, and legality then follows from the setup receipt plus SHA-256 collision resistance (paper Claim "Response soundness").
- **Hit/miss: yes.** `hit = occ(B, x)`.
- **Sinking announcements: yes, including which ship.** `sunk = sunkship(B, x, H)` gives `Option<ShipKind>`.
- **Defeat / game end: yes.** `defeated = allsunk(B, H ∪ {x})` is computed in-guest.
- **History binding: yes. This is the paper's main contribution.** The journal is `(C, x, hit, sunk, def, H)` with the full explicit history list, not a hash chain. The verifier checks `J.H == F_V` (its own fired list) by sequence equality, along with `J.C == C_P` and `J.x == x`. The journal therefore grows by 8 B per prior shot (152 B at |H|=0 → 944 B at |H|=99) because of risc0 serde u32-word encoding, where the paper counts "two bytes each before serialization".
- Also in scope: Blum coin flip for first move (outside the zkVM), and fixed-shape guest code for witness-independent cycle counts. The paper treats aborts as out of scope. Distinct shots are enforced by the agent, not the proof.
- Proof system: RISC Zero STARK (poseidon2), with composite receipts by default. It is transparent (no trusted setup). Groth16 is not used.

## 6. Smoke run (R=1, 2026-09-25 ~17:16 UTC): `smoke/`

**Caveat: the machine was busy.** The 1-minute load average was 19.0 at start and about 26 during the run, from the BattleZips-Circom baseline being built at the same time (`node` at ~1400 % CPU). These timings are therefore **inflated and noisy**. They serve only to check the pipeline and are not results. Settings: `RAYON_NUM_THREADS` unset, i.e. 28 threads, governor `powersave` (intel_pstate), turbo on.

r0bs-measure (one process per proof):

| proof | receipt | hist | prove s | verify ms (median of 20 / first) | journal B | seal KiB | JSON KiB | bincode KiB | total cycles (po2) | user cycles | peak RSS MiB |
|---|---|---|---|---|---|---|---|---|---|---|---|
| commit | composite | - | 4.52 | 11.0 / 14.8 | 128 | 215.7 | 554.1 | 216.3 | 65536 (2^16) | 14033 | 602 |
| shot | composite | 0 | 5.01 | 17.8 / 18.3 | 152 | 215.7 | 554.1 | 216.3 | 65536 (2^16) | 20062 | 604 |
| shot | composite | 25 | 8.03 | 12.7 / 11.1 | 352 | 238.2 | 613.7 | 239.2 | 131072 (2^17) | 40049 | 1186 |
| shot | composite | 50 | 8.86 | 18.9 / 18.9 | 552 | 238.2 | 614.4 | 239.6 | 131072 (2^17) | 59803 | 1186 |
| shot | composite | 99 | 8.42 | 10.2 / 10.3 | 944 | 238.2 | 616.3 | 240.4 | 131072 (2^17) | 98593 | 1190 |
| commit | succinct | - | 11.57 | 12.9 / 20.6 | 128 | 217.4 | 569.6 | 218.2 | 65536 | 14033 | 1427 |
| shot | succinct | 0 | 7.96 | 9.3 / 9.7 | 152 | 217.4 | 569.7 | 218.3 | 65536 | 20062 | 1427 |
| shot | succinct | 25 | 10.74 | 9.6 / 9.7 | 352 | 217.4 | 570.1 | 218.7 | 131072 | 40049 | 1427 |
| shot | succinct | 50 | 11.48 | 9.6 / 9.8 | 552 | 217.4 | 571.2 | 219.1 | 131072 | 59803 | 1427 |
| shot | succinct | 99 | 10.89 | 9.5 / 10.1 | 944 | 217.4 | 572.9 | 219.8 | 131072 | 98593 | 1427 |

Unmodified upstream `zk-battleship-bench`, single run straight afterwards (`smoke/upstream_bench_r1.txt`):

| proof | receipt | hist | prove s | verify ms | journal B | seal B | wire JSON B |
|---|---|---|---|---|---|---|---|
| commit | composite | 0 | 3.01 | 9.9 | 128 | 220904 | 567396 |
| shot | composite | 0 | 3.42 | 10.0 | 152 | 220904 | 567638 |
| shot | composite | 25 | 6.73 | 11.1 | 352 | 243944 | 628352 |
| shot | composite | 50 | 6.63 | 10.3 | 552 | 243944 | 629262 |
| shot | composite | 99 | 6.34 | 9.9 | 944 | 243944 | 630882 |
| commit | succinct | 0 | 8.12 | 10.2 | 128 | 222668 | 583197 |
| shot | succinct | 0 | 8.02 | 9.5 | 152 | 222668 | 583191 |
| shot | succinct | 25 | 11.75 | 9.5 | 352 | 222668 | 584459 |
| shot | succinct | 50 | 11.10 | 10.1 | 552 | 222668 | 584967 |
| shot | succinct | 99 | 11.12 | 10.2 | 944 | 222668 | 586570 |

Witness-independence line: `cycles: min=44055 max=44079 spread=24` (paper: 45,147–45,173, spread 26). Peak RSS of the whole upstream bench process is 1.43 GB.

Observations from the smoke run:
- **Sizes reproduce the paper exactly.** Journal 128/152/352/552/944 B. Seal 215.7 / 238.2 / 217.4 KiB. JSON wire 554.1 / 613.6–616.1 / 569.5–572.8 KiB. JSON size moves by a few bytes from run to run because seal words are printed as decimals.
- Compact binary encoding (bincode) is about 216–240 KiB, roughly 2.56x smaller than their JSON wire format. The honest minimum-size figure to cite is seal ≈ 216–238 KiB (composite) or 217 KiB (succinct).
- Cycle counts differ slightly from the paper. We get 20,062 user cycles at |H|=0 against their "20.3k", and 98,593 at |H|=99 against "101.8k". The likely cause is a different guest rustc: we use rzup rust 1.97.0, and theirs is unstated. The padded segment size is the same (2^16 → 2^17), so proving cost is unaffected.
- The paper's wording is imprecise on one point. Every proof here, composite included, has **exactly 1 segment receipt**. |H| ≥ 25 is a single 2^17-cycle segment, not two 2^16 segments, because the default segment limit is po2 20. The paper's "fits within two" means two 2^16 units of padding. The seal sizes match the paper, so their run had the same structure.
- Shot (9,9) is a miss for the seed-42 fleet, and at |H|=99 `defeated=true`. Because of the fixed-shape guest, neither affects cost.
- Proving on the i7-14700K is about 4–7x faster than the paper's laptop: 3.4–8.9 s against 30–47 s for composite shots. The two smoke sources differ by 1–2 s per composite proof (upstream bench 3.0–6.7 s, r0bs-measure 4.5–8.9 s), even though the code path and boundaries are the same. The background load is the most likely cause, which is exactly why R ≥ 5 on a quiet machine is needed. Check in the real run whether the gap persists (e.g. a page-cache cold r0vm start per process). If it does, report the upstream-bench numbers (`UPSTREAM_REPS=R`) as the primary figures.
- Effective parallelism: `process_user_s / process_wall_s` is about 14–16 cores for composite and 14–22 for succinct, out of 28 threads.

## 7. Estimated wall time for the final run

The smoke run took about 90 s for the 10 r0bs-measure configs and 77 s for one upstream bench run, both on a loaded machine.

| command | estimate (loaded) | estimate (quiet) |
|---|---|---|
| `./run_full.sh 5` (5x10 measure + 1 upstream) | ≈ 9 min | ≈ 6–7 min |
| `UPSTREAM_REPS=5 ./run_full.sh 5` | ≈ 14 min | ≈ 10 min |
| `THREADS=16 CPUSET=0-15 ...` | somewhat longer, maybe 1.2–1.5x | |

Budget ≤ 15 min for the recommended `UPSTREAM_REPS=5 ./run_full.sh 5`. Disk use is small: about 100 KB per run.

## 8. Caveats for the paper

1. **Dev mode is impossible**: `disable-dev-mode` is compiled in, and `RISC0_DEV_MODE` is unset and checked. All receipts are real STARKs, verified by `receipt.verify(image_id)` in the host.
2. **Composite vs succinct.** Their default, and the protocol they deploy, uses **composite** receipts (1 segment each here). Succinct costs about 1.3–2.7x the proving time in the smoke run (paper: 1.4–1.8x) and saves nothing in size at this scale. Compare our protocol against composite as the headline, and list succinct separately. Neither is Groth16. The seal is a transparent STARK of about 216–238 KiB, against our Bulletproofs sizes.
3. **prove_s includes r0vm process spawn + IPC + `verify_integrity`.** This is how their agent actually proves, because the host lacks the `prove` feature. The spawn overhead is a fraction of a second. An in-process `LocalProver` would be slightly faster, but that is not what they ship or measure.
4. **Verify time** is host-side `Receipt::verify` plus journal checks, about 10 ms here against about 30 ms on their laptop. The first call is a little slower than the warm calls.
5. **Wire size**: their relay uses JSON, which is inflated about 2.6x. For a fair size comparison, cite the raw seal (or bincode) next to their JSON "wire" figure, and say so.
6. **Threads/CPU**: the i7-14700K is hybrid (8 P-cores with HT plus 12 E-cores, 28 threads). The default uses all 28, and the paper used all 22 of the 155H. The governor is `powersave` (intel_pstate) with turbo on. For stable numbers, keep the machine otherwise idle. Optionally use `CPUSET=0-15` for P-cores only, and report the setting from `meta.json`.
7. **Single runs in the paper.** Their table has n=1 per cell, with no variance, so the 47.2 s vs 41.1 s non-monotonicity across |H| is noise. Say "single runs" when quoting their numbers.
8. The guest toolchain differs from the paper's (unstated) one, so image IDs and cycle counts will not match theirs bit for bit. The circuit logic and the padded trace size are identical.
9. Nothing in upstream was modified, so no diff to record. `measure/` is a separate crate. Its `Cargo.lock` was seeded from upstream's, and every shared package has the same version.
