//! Privacy coupling (paper Theorem 8.6; abstract, Results: "a change of
//! variables on the commitment randomness") with trapdoored test-only
//! generators `G = xi H`. For two legal fleets the opponent has not told
//! apart, shifting the cell blinders `rho` by `xi (s - s')` makes every cell
//! commitment `C_{j,i}`, every length opening and every answer opening
//! equal. `O_j`, `Q_{j,d}` and `delta_{j,d}` would also need `omega` and
//! `theta` shifted, which the prover draws from its own RNG, so they are not
//! compared. Range proofs and Σ-protocol transcripts are not compared either:
//! they are zero-knowledge, and the prover RNG is rekeyed with the witness.

use crate::answers::{self, AnswerContext, BoardShots, ResponderSecrets, ShotAnswer};
use crate::fleet::tests::{fleet_a, ship};
use crate::fleet::{Fleet, SHIP_BITS};
use crate::params::{CellIndex, Parameters, Rules};
use crate::setup;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::Sha512;

/// `fleet_a` with the length-2 ship moved from cells 80-81 to 85-86.
fn fleet_a_moved() -> Fleet {
    let mut ships = *fleet_a().ships();
    ships[4] = ship(8, 5, false);
    Fleet::new(ships, Rules::NoTouch).unwrap()
}

enum View {
    Miss(Scalar),
    Hit(Scalar),
    Sunk(Scalar, u8, Vec<(CellIndex, Scalar)>),
}

fn view(answer: &ShotAnswer) -> View {
    match answer {
        ShotAnswer::Miss { rho } => View::Miss(*rho),
        ShotAnswer::Hit { rho, .. } => View::Hit(*rho),
        ShotAnswer::Sunk {
            rho,
            ship,
            openings,
        } => View::Sunk(*rho, *ship, openings.clone()),
    }
}

#[test]
fn privacy_coupling() {
    // xi stays a local variable; never stored in Parameters.
    let xi = Scalar::from_bytes_mod_order([0x42; 32]);
    let h = RistrettoPoint::hash_from_bytes::<Sha512>(b"zkbattleship/test-only/coupling-H");
    let g = xi * h;
    let params = Parameters::from_test_generators(g, h, Rules::Standard);

    let fleets = [fleet_a(), fleet_a_moved()];
    let bits = [fleets[0].ship_bits(), fleets[1].ship_bits()];
    let mut rng = ChaCha20Rng::from_seed([0xC0; 32]);
    let rho0: Vec<Scalar> = (0..SHIP_BITS).map(|_| Scalar::random(&mut rng)).collect();
    let rho1: Vec<Scalar> = (0..SHIP_BITS)
        .map(|k| {
            rho0[k]
                + xi * (Scalar::from(u64::from(bits[0][k])) - Scalar::from(u64::from(bits[1][k])))
        })
        .collect();
    let rho = [rho0, rho1];

    let id = [0xD1; 32];
    let sid = [0x5D; 32];
    let msgs: Vec<setup::SetupMessage> = (0..2)
        .map(|k| {
            setup::prove_with_rng(
                &params,
                &id,
                &sid,
                &fleets[k],
                &rho[k],
                ChaCha20Rng::from_seed([k as u8; 32]),
            )
            .unwrap()
        })
        .collect();
    for msg in &msgs {
        setup::verify(&params, &id, &sid, msg).unwrap();
    }
    assert_eq!(msgs[0].ship_cells, msgs[1].ship_cells);
    assert_eq!(msgs[0].length_openings, msgs[1].length_openings);

    // Shots that never touch cells 80-81 or 85-86: sink ship 0, hit ship 1,
    // miss elsewhere.
    let shots: [u8; 12] = [10, 0, 1, 2, 99, 3, 4, 20, 21, 55, 70, 88];
    let ctx = AnswerContext {
        defender_id: &id,
        sid: &sid,
    };
    let mut boards = [BoardShots::default(), BoardShots::default()];
    let mut secrets = [
        ResponderSecrets::new(&fleets[0], rho[0].clone()),
        ResponderSecrets::new(&fleets[1], rho[1].clone()),
    ];
    let mut sunk = 0;
    for &c in &shots {
        let cell = CellIndex::from_index(c).unwrap();
        let mut views = Vec::new();
        for k in 0..2 {
            boards[k].register(msgs[k].ship_cells(), cell);
            secrets[k].register(cell);
            let answer = answers::answer_shot(
                &params,
                &ctx,
                &boards[k],
                &secrets[k],
                cell,
                &mut ChaCha20Rng::from_seed([7; 32]),
            );
            if let ShotAnswer::Sunk { ship, .. } = &answer {
                boards[k].mark_sunk(*ship);
            }
            views.push(view(&answer));
        }
        match (&views[0], &views[1]) {
            (View::Miss(a), View::Miss(b)) | (View::Hit(a), View::Hit(b)) => assert_eq!(a, b),
            (View::Sunk(a, s, o), View::Sunk(b, t, p)) => {
                assert_eq!((a, s, o), (b, t, p));
                sunk += 1;
            }
            _ => panic!("coupled fleets answered cell {c} differently"),
        }
    }
    assert_eq!(sunk, 1);
    assert!(boards[0].sunk()[0] && boards[0].sunk().iter().filter(|&&s| s).count() == 1);
}
