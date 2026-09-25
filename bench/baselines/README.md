# Baselines

Harnesses for the two comparators, as run for the paper. Only our scripts
and notes are tracked; each harness fetches and builds its upstream into its
own directory (`upstream/`, `tools/`, `risc0-home/`, `node_modules/`,
`target/`), which `.gitignore` excludes.

| Directory | Comparator | Entry points |
| --- | --- | --- |
| `battlezips-circom/` | BattleZips-Circom (circom 2 + snarkjs Groth16 on BN254, Solidity verifiers, Hardhat) | `harness/bootstrap.sh`, `harness/setup.sh ceremony`, `harness/run_full.sh 20 100 3 5`, `harness/soundness/demo.sh` |
| `risc0-battleship/` | Ghazi, *Ledger-Free Trustless Battleship* (RISC Zero zkVM 3.0.5, CPU proving) | toolchain install and build per `NOTES.md` §3, then `UPSTREAM_REPS=5 ./run_full.sh 5` |

Each `NOTES.md` pins versions and commits, defines every metric, records
deviations from upstream (none in source for either), and quotes what the
comparator's own paper or README reports. The notes were written where the
harnesses were first set up (`~/src/provablyfun/baselines/<name>/`); the
scripts locate everything relative to themselves, so any writable copy works.

Final results: `../results/`.
