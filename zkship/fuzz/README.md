# Fuzz targets

`cargo-fuzz` crate outside the workspace (nightly, sanitizers).

| Target | Exercises |
| --- | --- |
| `setup_message_decode` | `SetupMessage::decode`, both rule sets (exact 19,488/20,544-byte gate, canonical points and scalars), re-encode equality |
| `answer_decode` | `ShotAnswer::decode`, every tag/length/unsunk shape (33; 449/513/577; 100-199), re-encode equality |
| `frame_decode` | `SignedFrame::decode` (size bounds, header/actual length consistency, per-type payload rules; both commit lengths, every answer length) |
| `hello_decode` | `Hello::decode` and `check_hello` with attacker-shaped key/nonce/signature bytes, both profiles |
| `session_replay` | two real sessions through commit/coin/play; replay, signed invalid state events and answer mutations (changed answers rejected); unchanged state on class-B input |

- Decoder targets apply up to 256 sparse writes to exact-length fixtures: each 4-byte instruction is a 24-bit LE offset plus one byte, so small inputs reach late fields. Byte 0 selects the fixture (rules, answer shape, frame type or profile; see each target's header).
- `session_replay`: byte 0 = valid setup frames (0 to 5), byte 1 = honest exchanges (0 to 199), then 3-byte adversarial instructions (at most 16).
- Under `cfg(fuzzing)` verified setup/play prefixes are cached via `Clone`; mutated frames still pass ordinary signature/proof verification.
- The frame decoder's unit tests pin the wasm32 case: the declared payload length is never added to header+signature sizes (usize overflow on 32-bit).

## Running

```text
cargo +nightly fuzz build
cargo +nightly fuzz run frame_decode -- -max_total_time=60
```

If symbolization stalls: `ASAN_OPTIONS=symbolize=0` and `-print_funcs=0`.

`corpus/<target>/` is tracked; add seeds deliberately (reviewed input or fixed crash). `target/` and `artifacts/` are ignored. For a crash: reproduce with `cargo +nightly fuzz run <target> artifacts/<target>/<file>`, fix with a regression unit test, then promote the input to the corpus.
