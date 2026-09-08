//! Privacy coupling test (paper Lemma 2.3) with trapdoored test-only
//! generators. Relation is G = xi * H (xi = log_H G, the paper's xi = log_h g),
//! NOT H = xi * G. Proof bytes are deliberately not compared: the prover RNG
//! is rekeyed with the witness, so WI is only distributional.

use crate::game::BoardShots;
use crate::openings::{self, ShotAnswer};
use crate::params::{CellIndex, Parameters, DISTINCT_LENGTHS, N, P};
use crate::pedersen;
use crate::wf::{self, VerifiedBoardCommitment};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_COMPRESSED;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::Sha512;

fn placement_e0() -> Vec<u8> {
    let mut e = vec![0u8; P];
    e[0] = 1;
    e[134] = 1;
    e[292] = 1;
    e[460] = 1;
    e[643] = 1;
    e
}

/// `e0` with the length-2 ship moved from cells [70-71] to [73-74].
fn placement_e1() -> Vec<u8> {
    let mut e = placement_e0();
    e[643] = 0;
    e[646] = 1; // row 7, col 3: cells 73-74
    e
}

fn semantics(answer: &ShotAnswer) -> (bool, [u8; 4]) {
    match answer {
        ShotAnswer::Miss { .. } => (false, [0; 4]),
        ShotAnswer::Hit { sunk, .. } => (true, std::array::from_fn(|i| sunk[i].tau)),
    }
}

#[test]
fn privacy_coupling() {
    // xi stays a local variable; never stored in Parameters.
    let xi = Scalar::from_bytes_mod_order([0x42; 32]);
    assert_ne!(xi, Scalar::ZERO);
    let h = RistrettoPoint::hash_from_bytes::<Sha512>(b"zkbattleship/test-only/coupling-H");
    let g = xi * h;
    let params = Parameters::from_test_generators(g, h);
    let geometry = params.geometry();

    let e0 = placement_e0();
    let e1 = placement_e1();
    assert!(geometry.is_legal_placement(&e0));
    assert!(geometry.is_legal_placement(&e1));
    assert_ne!(e0, e1);

    let mut rng = ChaCha20Rng::from_seed([0xC0; 32]);
    let s0: Vec<Scalar> = (0..P).map(|_| Scalar::random(&mut rng)).collect();
    // s1 = s0 + xi * (e0 - e1).
    let s1: Vec<Scalar> = (0..P)
        .map(|p| {
            let d = i64::from(e0[p]) - i64::from(e1[p]);
            let d_scalar = if d >= 0 {
                Scalar::from(d as u64)
            } else {
                -Scalar::from((-d) as u64)
            };
            s0[p] + xi * d_scalar
        })
        .collect();

    let entry0 = pedersen::commit_vector(&params, &e0, &s0);
    let entry1 = pedersen::commit_vector(&params, &e1, &s1);
    let point_bytes = |points: &[RistrettoPoint]| {
        points
            .iter()
            .flat_map(|p| p.compress().to_bytes())
            .collect::<Vec<u8>>()
    };
    assert_eq!(point_bytes(&entry0), point_bytes(&entry1));
    assert_ne!(params.g().compress(), RISTRETTO_BASEPOINT_COMPRESSED);

    // Both proofs verify against the same E; bytes intentionally not compared.
    let prover_id = [0xC1; 32];
    let sid = [0xC2; 32];
    let (board0, pi0) = wf::prove_with_rng(
        &params,
        &prover_id,
        &sid,
        &e0,
        &s0,
        ChaCha20Rng::from_seed([0xC3; 32]),
    )
    .unwrap();
    let (board1, pi1) = wf::prove_with_rng(
        &params,
        &prover_id,
        &sid,
        &e1,
        &s1,
        ChaCha20Rng::from_seed([0xC4; 32]),
    )
    .unwrap();
    assert_eq!(board0.to_bytes(), board1.to_bytes());
    wf::verify(&params, &prover_id, &sid, &board0, &pi0).unwrap();
    wf::verify(&params, &prover_id, &sid, &board0, &pi1).unwrap();

    let verified_board = VerifiedBoardCommitment::from_parts_for_test(
        entry0.clone(),
        pedersen::cell_commitments(&params, &entry0),
    );
    let mut tracker = BoardShots::new_verifier(&params);
    let mut is_shot = [false; N];
    let mut accepted_counts = [0u8; 4];
    let mut verified_hits = 0u8;

    let answer = |e: &[u8], s: &[Scalar], cell: CellIndex, is_shot: &[bool; N]| {
        let mut counts = [0u8; 4];
        let mut blinders = [Scalar::ZERO; 4];
        for (idx, &length) in DISTINCT_LENGTHS.iter().enumerate() {
            for p in openings::sunk_positions(geometry, length, is_shot) {
                counts[idx] += e[p];
                blinders[idx] += s[p];
            }
        }
        openings::answer_shot(&params, cell, e, s, &counts, &blinders)
    };

    // Final cell 70 is a hit for e0 but a miss for e1.
    let shots: [u8; 15] = [10, 60, 40, 41, 42, 0, 1, 2, 3, 4, 20, 21, 22, 23, 70];
    let mut agreeing = 0usize;
    let mut skipped = 0usize;
    for &i in &shots {
        let cell = CellIndex::from_index(i).unwrap();
        tracker.register_shot(geometry, &entry0, cell).unwrap();
        is_shot[i as usize] = true;

        let a0 = answer(&e0, &s0, cell, &is_shot);
        let a1 = answer(&e1, &s1, cell, &is_shot);
        let (b0, taus0) = semantics(&a0);
        let (b1, taus1) = semantics(&a1);

        if b0 == b1 && (!b0 || taus0 == taus1) {
            // All authorized functionals agree, so the encoded answers must match.
            assert_eq!(a0.encode(), a1.encode(), "shot at cell {i}");
            let outcome = openings::verify_answer(
                &params,
                &verified_board.cell_commitments()[i as usize],
                tracker.sunk_commitments(),
                &accepted_counts,
                verified_hits,
                &a0,
            )
            .unwrap();
            accepted_counts = outcome.sunk_counts;
            verified_hits += u8::from(outcome.hit);
            agreeing += 1;
        } else {
            assert_ne!(a0.encode(), a1.encode(), "shot at cell {i}");
            skipped += 1;
        }
    }
    assert_eq!(agreeing, 14);
    assert_eq!(skipped, 1);
    assert_eq!(verified_hits, 12);
    assert_eq!(accepted_counts, [1, 1, 1, 0]);
}
