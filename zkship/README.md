# zkship: Zero-Knowledge Battleship reference implementation (Rust)

Authority: `../docs/zk-battleship.tex`. Wire formats, domain strings, and
transcript order are specified by the code and pinned by `vectors/`.

Not independently audited. Do not use for meaningful stakes.

- `zkb-core/`: parameters and geometry, Pedersen, bit and Schnorr Sigma protocols, Π_wf, openings, game state machine. No I/O.
- `zkb-session/`: codec, Ed25519 identity and peer-auth policy hook, Hello/roles/sid, signed frame chain, coin flip, session driver.
- `zkb-cli/`: two-process TCP demo (native only).
- `fuzz/`: cargo-fuzz targets (nightly, outside the workspace).
- `vectors/`: pinned commitment/proof and game-transcript vectors.

```text
cargo build --workspace --locked
cargo test --workspace --release --locked   # debug is minutes; proofs are slow
cargo +nightly fuzz run <target>            # from fuzz/
cargo build -p zkb-core -p zkb-session --target wasm32-unknown-unknown
zkb-cli listen  --addr 127.0.0.1:7878 --name alice
zkb-cli connect --addr 127.0.0.1:7878 --name bob
```

Rust 1.85+. `ZKB_CLI_AUTO=1` auto-confirms fingerprints and fires scripted shots (test aid only).

Not provided: peer authentication (the CLI fingerprint prompt is a hook, not
MITM protection), transport confidentiality (transcripts are public),
attributable timeouts, abort fairness, UC or concurrent security,
post-quantum soundness. Π_wf privacy is computational (Merlin
witness-rekeyed nonces), not the paper's perfect WI; commitments and
play-phase openings stay information-theoretically hiding.

Security-relevant changes (need review plus new vectors): G/H derivation,
point/scalar decoding, canonical parameter bytes, placement enumeration,
Fiat-Shamir fields/order, challenge reduction, proof algebra, RNG rekeying,
secret-side variable-time calls, game functional construction, sid
derivation, frame encoding, role/sequence rules, crypto dependency majors.
