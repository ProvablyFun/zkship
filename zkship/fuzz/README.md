# Fuzz targets

`cargo-fuzz` crate outside the workspace (nightly, sanitizers).

| Target | Exercises |
| --- | --- |
| `wf_proof_decode` | `WfProof::decode` (exact 82,752-byte gate, canonical scalars) |
| `board_commitment_decode` | `UnverifiedBoardCommitment::from_bytes` (exact 24,320-byte gate, canonical points) |
| `answer_decode` | `ShotAnswer::decode` (`b`-implied 33/165-byte lengths) |
| `frame_decode` | `SignedFrame::decode` (size bounds, header/actual length consistency, per-type payload rules) |
| `hello_decode` | `Hello::decode` and `check_hello` with attacker-shaped key/nonce/signature bytes |
| `session_replay` | a live `Session::accept` fed arbitrary bytes: structural decode, chain gate, class-B rejections |

- Decoder targets apply up to 256 sparse writes to exact-length fixtures: each 4-byte instruction is a 24-bit LE offset plus one byte, so small inputs reach late fields.
- The frame decoder's unit tests pin the wasm32 case: the declared payload length is never added to header+signature sizes (usize overflow on 32-bit).

## Running

```text
cargo +nightly fuzz build
cargo +nightly fuzz run frame_decode -- -max_total_time=60
```

If symbolization stalls: `ASAN_OPTIONS=symbolize=0` and `-print_funcs=0`.

`corpus/<target>/` is tracked; add seeds deliberately (reviewed input or fixed crash). `target/` and `artifacts/` are ignored. For a crash: reproduce with `cargo +nightly fuzz run <target> artifacts/<target>/<file>`, fix with a regression unit test, then promote the input to the corpus.
