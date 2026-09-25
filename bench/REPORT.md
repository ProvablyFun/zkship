# ZK Battleship: implementation and benchmarks for the BBCON 2026 extended abstract

Prepared for Freeman Slaughter, 25 September 2026.

Historical. Current figures: `../docs/zk-battleship.pdf`, Section 9.

## 1. Bottom line

- **The Rust code now implements exactly the construction in the abstract.** That means one indicator vector per ship, the moment equations for straightness with the squaring protocol, one aggregated Bulletproof for the 605 bit checks, openings of B_i to answer shots, not-sunk range proofs after hits, and the 28-element no-touch proof. The earlier code implemented a different construction (a placement-vector protocol from an earlier long paper).
- **Every size claimed in the abstract is confirmed byte for byte by the implementation:**
  - setup: 559 group elements and 50 scalars = **19,488 B**
  - miss: **32 B**
  - hit: **576 B** (512 B or 448 B once only two or one ships remain)
  - no-touch rule: **28 elements + 5 scalars**
- **Measured speed, one CPU core, median:**
  - legality proof: **77 ms** to generate, **15 ms** to receive and verify
  - hit: **1.5 ms** to answer, **0.4 ms** to check
  - miss: answered in under a microsecond, checked in 18 µs
  - complete game: about **0.12 s of computation per player**
  - over a 50 ms round-trip connection: a turn takes **51 ms** and a whole game about **3 s**
- **The abstract's new figures need correcting.** The revised text says "setup ~200 ms, legality proof ~130 ms, verification ~60 ms", and says these were obtained "even without implementing the Bulletproofs aggregation". Those figures were a rough early measurement of the *old* construction. Bulletproofs aggregation is now implemented, and the measured values are the ones above. Suggested replacement text is in §2.
- **Against the two comparable systems, measured on the same machine:**
  - **BattleZips-Circom (Groth16 + contract):**
    - proving: 0.45–0.49 s per proof with snarkjs, 0.10–0.12 s with rapidsnark, both on 28 threads
    - verifying: 0.22 s per proof
    - gas: about 330,000–356,000 per turn. Its own scripted test game, the shortest possible (33 shot proofs, one side hitting on every turn), costs **12.0 M**. A game of the length we observed (≈ 105 turns) would cost **≈ 35–37 M** (estimated from the per-turn gas). Deploying the contracts costs 3.8 M more
    - plus block confirmation on every turn
    - **Its circuits are unsound as shipped.** We produced a false-miss proof and an overlapping-fleet proof, and both are accepted by its own verification keys and on-chain verifiers.
  - **Ghazi 2026, "Ledger-Free Trustless Battleship" (RISC Zero zkVM, also no blockchain):**
    - 3.3 s per board proof and 3.4–7.3 s per shot proof, on 28 threads
    - 216–238 KiB receipts
    - up to 1.2 GB of memory
  - **Per hit, our proof is about 300× faster to generate than snarkjs (65× faster than rapidsnark) and 2,000–5,000× faster than the zkVM, while using one core instead of 28.** For the one-time board proof, the gap is about 6× over snarkjs and 43× over the zkVM.

## 2. Changes needed in the revised abstract (in priority order)

1. **Abstract, last sentence (numbers from the old code).** Replace "with average board setup in ~200ms, while proving legality takes only ~130ms and verification in ~60ms" with:
   > "On one CPU core, the legality proof takes 77 ms to generate and 15 ms to verify, a hit is answered in 1.5 ms and checked in 0.4 ms, and a complete game costs each player about 0.12 s of computation and under 60 KB of traffic."

2. **Abstract, privacy claim.** "statistical privacy without leakage" overclaims: the opponent learns hits, misses and sunk ships, which the game reveals by design. The previous wording was right. Suggest:
   > "statistical privacy, leaking nothing beyond the game's own outcomes"

3. **Results & Discussion, first paragraph.** Replace "and takes about 200ms on average to generate. Even without implementing the Bulletproofs aggregation, our proof of concept code records that a proof of piece legality takes about 130ms, with verification in 60ms." with:
   > "and our implementation proves it in 77 ms and verifies it in 15 ms on one core; on a local connection both players are ready to fire 0.19 s after starting. A hit is answered in 1.5 ms and checked in 0.4 ms, and a miss in microseconds, so over a 50 ms round trip a turn takes 51 ms and a whole game about 3 s. By comparison, a BattleZips Groth16 shot proof takes 0.46 s to generate and 0.22 s to verify with snarkjs on 28 threads, and each turn costs about 350,000 gas (at least 12 million for even the shortest game) before the block that confirms it."

4. **Table 1, "Setup artifacts" row.** "Two group generators" is incomplete: the Bulletproofs also need 2 × 1,024 vector generators (2 × 4,096 with the no-touch rule). These are hashed from a public string, so there is still no trusted setup. Suggest:
   > "Two group generators and Bulletproofs generators hashed from a public string; no trusted setup"

5. **Sinking sentence.** "sinking is verified on the correct turn without revealing which ship was hit" is true for hits that do not sink a ship. A sink announcement necessarily opens the sunk ship's cells. Suggest:
   > "…without revealing which ship a non-sinking hit struck"

6. **Privacy caveat, no text change required.** A sink announcement opens the sunk ship's commitments, so it reveals the ship's index. For the two length-3 ships, that is which of the two sank. This matches the standard rules, where the sunk ship is named. But "leakage equal to the game's own information" assumes the game names the ship. If the rules only announce length, the implementation leaks one bit more.

7. **Optional but recommended: related work.**
   - Ghazi (2026), "Ledger-Free Trustless Battleship" (zkVM, Zenodo DOI 10.5281/zenodo.21207531), also removes the blockchain. A reviewer may cite it against the novelty of "we remove the blockchain referee".
   - One sentence positions it: *"Ghazi (2026) also removes the chain, using a general-purpose zkVM; on the same machine its shot proofs take 3–7 s and 216–238 KiB, against our 1.5 ms and 576 B."*
   - The phrase "which alone is not sufficient" about BattleZips can be backed by fact: its board and shot circuits leave the collision and hit logic unconstrained. We forged accepted proofs of a false miss and of an overlapping fleet. If this is stated in the paper, consider notifying the BattleZips maintainers first.

Everything else in the revision (sizes, 605 bits / 24 elements, 576 B hit, 28-element no-touch proof, "hit under 600 bytes") matches the implementation.

## 3. Proposed measured table (fits under Table 1)

Medians on an Intel i7-14700K. Ours runs on one core; BattleZips and the zkVM use all 28 hardware threads, their default.

| | This work | BattleZips-Circom (Groth16) | Ghazi 2026 (RISC Zero zkVM) |
|---|---|---|---|
| One-time setup | none (hashed generators) | trusted setup ceremony + keys, ≈ 4 min; 6.2 MB + 5.5 MB proving keys | none |
| Board proof: generate / verify | 77 ms / 15 ms | 0.45 s (rapidsnark 0.12 s) / 0.22 s | 3.3 s / 10 ms |
| Board message | 19,488 B | 256 B proof + hash; 327,616 gas | 216 KiB seal (554 KiB as sent, JSON) |
| Hit: generate / verify | 1.5 ms / 0.41 ms | 0.46 s (rapidsnark 0.10 s) / 0.22 s | 3.4–7.3 s / 10 ms |
| Hit message | 576 B | 256 B proof; 356,157 gas | 216–238 KiB seal |
| Miss: generate / verify | < 1 µs / 18 µs | same as hit; 332,863 gas | same as hit |
| Sinking | proved on the turn it happens | not proved; game ends at 17 hits | proved |
| Whole game | ≈ 0.12 s computation, 43–56 KB per player; no gas | 12.0 M gas for the shortest game, ≈ 35–37 M at a typical length (est.), + 3.8 M deployment; one transaction per turn | several minutes of proving per player (≈ 50–90 shot proofs of 3–7 s) |
| Peak memory | 6 MB | 0.75–0.8 GB (snarkjs) / 12–14 MB (rapidsnark) | 0.6–1.2 GB |
| Soundness as shipped | security proofs in the paper; implementation rejects every cheating fleet and answer in our tests; not audited | forged false-miss and overlapping-board proofs accepted (reproduced twice) | claimed by its paper; checked only by reading its guest code |

## 4. Our measurements in detail

Intel i7-14700K, Linux, Rust 1.89, release build, one P-core. Load average about 1.4 at the start. Medians with p95 in parentheses; n = 200 for setup operations, 1,000 for answers.

**Setup (sent once per player)**

| | standard | no-touch rule |
|---|---|---|
| size | 19,488 B | 20,544 B |
| prove | 76.8 ms (79.7) | 351 ms (372) |
| receive: decode + verify | 15.0 ms (15.3) | 46.0 ms (49.1) |
| first use of the parameters (hashing the generators) | 12.8 ms | 46.8 ms |
| peak memory, prove + verify | 6.0 MiB | 15.7 MiB |

**Answers**

| answer | cryptographic bytes | defender | shooter verifies |
|---|---|---|---|
| miss | 32 | < 1 µs | 18 µs |
| hit, 3–5 ships afloat | 576 | 1.49 ms (1.6) | 0.36–0.41 ms |
| hit, 2 ships afloat | 512 | 0.84 ms | 0.25 ms |
| hit, 1 ship afloat | 448 | 0.50 ms | 0.18 ms |
| sink announcement (ship of length 5 / 2) | 192 / 96 | < 1 µs | 0.11 / 0.05 ms |

On the wire, each message adds a 1-byte tag. The session layer adds a 78-byte header and a 64-byte Ed25519 signature per message.

**Forged messages** never cost the receiver more than verifying an honest one:
- a forged setup is rejected in 1.6 ms (early check) to 14.2 ms (last check)
- a forged answer is rejected in 0.02–0.39 ms

**Complete games** (30 games per setting, real session layer with signatures, random fleets)

| rules | shooter | winner's shots | bytes sent per player | CPU per player (of which setup) |
|---|---|---|---|---|
| standard | hunt-and-target | 53 | 43 KB (max 49 KB) | 120 ms (96 ms) |
| standard | random | 93 | 56 KB | 123 ms (92 ms) |
| no-touch | hunt-and-target | 57 | 46 KB | 426 ms (401 ms) |

**Networked games** (TCP with injected delay; time from firing to having verified the answer)

| round trip | setup until first shot | turn (median / p95) | whole game |
|---|---|---|---|
| local (0 ms) | 0.19 s | 0.3 / 2.4 ms | 0.24 s |
| 50 ms | 0.40 s | 51 / 57 ms | 2.9 s |
| 150 ms | 0.56 s | 151 / 160 ms | 7.9 s |
| 50 ms, 10 Mbit/s link | 0.36 s | 52 / 61 ms | 2.9 s |

The turn time is the network's round trip; computation adds about 1 ms.

## 5. Comparators

**BattleZips-Circom** (github.com/BattleZips/BattleZips-Circom, commit d6f6b0e):
- **Stack:** circom 2.2.3, snarkjs 0.4.27, rapidsnark, Hardhat.
- **Measurement:** n = 20 proofs, 100 verifications and 3 complete on-chain games per case, all 28 threads.
- **Circuits:** 10,644 constraints (board), 9,940 (shot).
- **Proving:** snarkjs 450–468 ms (the witness adds 12–18 ms); rapidsnark 99–123 ms.
- **Verification:** 219–221 ms, off-chain.
- **Gas:**
  - Verifying one Groth16 proof alone costs 228,254 (board) and 252,071 (shot).
  - Upstream's scripted game (2 board proofs, 33 shot proofs, 36 transactions; the shortest possible game) costs 11,988,250 gas, plus 3,790,940 to deploy the contracts. At ≈ 0.33–0.36 M gas per turn, a ≈ 105-turn game would cost ≈ 35–37 M (estimate, not measured).
- **Latency (modeled, not measured):** on Ethereum each turn also waits at least one 12-second block. A typical game of 50–90 shots per player therefore spends 20–36 minutes waiting for blocks alone.
- **Soundness:** hit/miss and non-overlap are not enforced, because the circuits compute them without constraining them. Our forged proofs verify under its own keys and contracts. The contract also accepts repeated shots.

**Ghazi 2026, "Ledger-Free Trustless Battleship"** (RISC Zero 3.0.5, commit a8fdd56, code identical to v1.0.0):
- **Measurement:** n = 5 per case, all 28 threads, rerun on our machine. Another job kept the load average near 5 during this run, so treat these figures as upper bounds.
- **Proving (composite receipts, their default):** board 3.3 s; shots 3.4 s with no history and 6.5–7.3 s with 25–99 prior shots.
- **Verification:** about 10 ms.
- **Size:** seal 216–238 KiB; 554–616 KiB as JSON on the wire.
- **Peak memory:** 0.6–1.2 GB.
- **What their own paper reports** (laptop Core Ultra 7 155H, single runs): 21 s per board proof, 30–47 s per shot proof, about 30 ms to verify.

## 6. What changed in the code (for the record)

The code is on `main`.

- **Construction:**
  - Bulletproofs built from scratch: inner-product argument, and aggregated range proofs with any bit width, padded to a power of two.
  - The squaring protocol.
  - The setup proof, with the optional no-touch proof.
  - Shot answers: miss, hit with a not-sunk proof, and sink announcement.
  - The game, network session and command-line demo moved to this construction.
- **Tests:**
  - Cheating provers are rejected for bent, gapped, diagonal, short, long, split, overlapping and touching fleets, and for non-bit orientations.
  - False misses, delayed sink announcements, premature or wrong sink announcements, and proofs replayed across turns or sessions are rejected.
  - A privacy coupling test is included.
  - Fuzz targets for every network decoder, and pinned test vectors.
- **Benchmark harness** for our code and both comparators; every raw sample is kept.
- **Not independently audited.** Two implementation notes relevant to the claims:
  - Prover randomness is derived from the witness plus fresh entropy, so the zero-knowledge of the implementation is computational in practice.
  - The Bulletproofs generators are hashed to the group, as noted in §2, item 4.
