# Interoperability vectors (standard v1)

Format: `key = value` per line, `#` comments, lowercase hex, decimal integers;
multi-byte integers inside protocol encodings are little-endian.

## commitment_proof_v1.txt

- `profile`, `params_id`; `prover_id`, `sid` (proof context).
- `placement_positions`: five global position indices, block order (5,4,3,3,2).
- `blinders_rng`, `proof_finalize_rng`: seeded RNGs for `s` and Fiat-Shamir finalization.
- `entry_commitments_len` (24,320), `proof_len` (82,752); SHA-512/256 of `E`, proof, and `E || proof`.
- `entry_commitments_hex`, `proof_hex`: canonical bytes.

Regenerate: `cargo run -p zkb-core --example generate_commitment_vector` (checks the digest pinned in `wf.rs`).
Conformance: `zkb-session/tests/conformance.rs::commitment_proof_vector_decodes`.

## game_transcript_v1.txt

- `key_seed_role_a/b`, `hello_role_a/b` (162 bytes each); `placement_role_a/b`.
- `blinders_seed_*`, `proof_finalize_rng_*`, `coin_rng_*`: seeded RNGs.
- `sid`, `genesis_hash`, `first_mover`, `winner`, `winner_hits`, `winner_sunk_total`, `loser_hits`.
- `frame_count`, `frame[0000]`..: every signed frame in chain order (sequence 1..).

Regenerate: `cargo run -p zkb-session --example generate_game_transcript` (byte-for-byte).
Conformance: `zkb-session/tests/conformance.rs::game_transcript_vector_replays_byte_for_byte`.
