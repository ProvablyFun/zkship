# Benchmarks

Measurements for the paper (`../docs/zk-battleship.pdf`, Section 9) and the
BBCON 2026 extended abstract
(`../docs/BBCON2026_ZK_Battleship_Extended_Abstract.pdf`), of the Rust
implementation in `../zkship/` against two other Battleship systems.

| Part | What | How |
| --- | --- | --- |
| P0 | Our protocol: per-operation costs, exact sizes, cold start, peak memory, forged-message rejection, complete games (in-process), networked games (TCP, injected RTT and bandwidth) | `run_p0.sh` → `results/p0-*/`, `summary.md` |
| P1 | BattleZips-Circom (Groth16 via snarkjs and rapidsnark, Solidity verifiers): constraints, key/proof sizes, witness/prove/verify times, gas for a complete game | `baselines/battlezips-circom/` |
| P2 | Ghazi's ledger-free RISC Zero Battleship: proving/verification time and receipt sizes as history grows; soundness review of BattleZips | `baselines/risc0-battleship/`, `baselines/battlezips-circom/harness/soundness/` |

## Method

- Release build (`overflow-checks = true`, as shipped), single-threaded code,
  pinned to one P-core (`taskset -c 4`) on a hybrid i7-14700K; the networked
  runs use one thread per player and two per proxy direction, restricted to
  six distinct P-cores (`taskset -c 0,2,4,6,8,10`). The governor is `powersave` (intel_pstate, turbo on) and
  cannot be changed without root, so `run_p0.sh` warns when the 1-minute load
  average exceeds 1.0 and records the load at start and end.
- Every sample is written to CSV. Summaries report nearest-rank median and p95.
- Inputs vary: 20 random fleets per rule set for the setup, four fleets for
  answers, fresh seeded fleets and shooters for every game. Setup encode,
  decode and verify, and each answer's produce, decode and verify, are
  interleaved per iteration; setup proving runs in its own loop.
- Timing boundaries: `setup_prove` is commitments plus proof from a fixed
  witness; `setup_decode+verify` is what a receiver does with the bytes;
  `answer_produce` includes encoding; `answer_verify` excludes decoding (listed
  separately). In games, `produce` of an answer is the defender's whole
  handling of the shot frame, signatures included.
- Sizes are read from the real encoders at three boundaries: cryptographic
  payload (what the abstract counts), message with its tag byte, and signed
  frame (78-byte header, 64-byte signature).
- Baselines run with their own defaults (all 28 hardware threads); our code
  is single-threaded. Comparisons state this.

## Reproduce

```text
bench/run_p0.sh                     # about 10 minutes on an idle machine
cd bench/baselines/battlezips-circom && harness/bootstrap.sh && harness/setup.sh ceremony && harness/run_full.sh 20 100 3 5
cd bench/baselines/risc0-battleship && (toolchain per NOTES.md) && UPSTREAM_REPS=5 ./run_full.sh 5
```
