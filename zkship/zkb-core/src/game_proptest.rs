//! State-machine properties. Boards use zero blinders and E_p = e_p * G so
//! the real `accept_answer` verification runs without any proof work.

use crate::game::{Game, GameError, Role, ShotOutcome, State};
use crate::params::{CellIndex, Parameters, DISTINCT_LENGTHS, K, N, P, T};
use crate::pedersen;
use crate::wf::VerifiedBoardCommitment;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use proptest::prelude::*;

fn role_index(role: Role) -> usize {
    match role {
        Role::A => 0,
        Role::B => 1,
    }
}

fn occupied(geometry: &crate::params::Geometry, e: &[u8]) -> Vec<CellIndex> {
    let mut cells = Vec::new();
    for (p, &bit) in e.iter().enumerate() {
        if bit == 1 {
            cells.extend_from_slice(geometry.cells_of_position(p));
        }
    }
    cells
}

fn zero_blinder_board(
    params: &Parameters,
    e: &[u8],
) -> (Vec<RistrettoPoint>, VerifiedBoardCommitment) {
    let g = *params.g();
    let entry: Vec<RistrettoPoint> = e
        .iter()
        .map(|&b| if b == 1 { g } else { RistrettoPoint::default() })
        .collect();
    let cells = pedersen::cell_commitments(params, &entry);
    (
        entry.clone(),
        VerifiedBoardCommitment::from_parts_for_test(entry, cells),
    )
}

fn arb_placement() -> impl Strategy<Value = Vec<u8>> {
    (
        0..120usize,
        0..140usize,
        0..160usize,
        0..160usize,
        0..180usize,
    )
        .prop_map(|(a, b, c, d, f)| {
            let mut e = vec![0u8; P];
            e[a] = 1;
            e[120 + b] = 1;
            e[260 + c] = 1;
            e[420 + d] = 1;
            e[580 + f] = 1;
            e
        })
        .prop_filter("placement must be legal", |e| {
            Parameters::standard_v1().geometry().is_legal_placement(e)
        })
}

fn arb_shot_order() -> impl Strategy<Value = Vec<u8>> {
    Just((0..N as u8).collect::<Vec<_>>()).prop_shuffle()
}

proptest! {
    #![proptest_config(ProptestConfig {
        // Each case plays a full game (~1-2s in debug).
        cases: 32,
        .. ProptestConfig::default()
    })]

    #[test]
    fn honest_random_games_never_abort(
        e_a in arb_placement(),
        e_b in arb_placement(),
        shots_a in arb_shot_order(),
        shots_b in arb_shot_order(),
        first_is_a in any::<bool>(),
    ) {
        let params = Parameters::standard_v1();
        let geometry = params.geometry();
        let first_mover = if first_is_a { Role::A } else { Role::B };
        let (entry_a, verified_a) = zero_blinder_board(params, &e_a);
        let (entry_b, verified_b) = zero_blinder_board(params, &e_b);
        let zeros = || vec![Scalar::ZERO; P];
        let mut game_a = Game::new(
            params,
            Role::A,
            first_mover,
            entry_a,
            e_a.clone(),
            zeros(),
            verified_b,
        )
        .unwrap();
        let mut game_b = Game::new(
            params,
            Role::B,
            first_mover,
            entry_b,
            e_b.clone(),
            zeros(),
            verified_a,
        )
        .unwrap();

        let placements = [e_a, e_b];
        let shot_orders = [shots_a, shots_b];
        let mut cursors = [0usize; 2];
        let mut last_fired: [Option<CellIndex>; 2] = [None, None];
        let mut prev_hits = [0u8; 2];
        let mut prev_sunk = [[0u8; 4]; 2];

        let mut current = first_mover;
        let winner = loop {
            let defender = current.other();
            let (attacker, attacked) = match current {
                Role::A => (&mut game_a, &mut game_b),
                Role::B => (&mut game_b, &mut game_a),
            };
            let ai = role_index(current);
            let di = role_index(defender);

            if let Some(prev) = last_fired[ai] {
                let rejected = matches!(
                    attacker.fire_shot(prev),
                    Err(GameError::RepeatedShot { .. })
                );
                prop_assert!(rejected);
            }

            let cell = loop {
                let index = shot_orders[ai][cursors[ai]];
                cursors[ai] += 1;
                let cell = CellIndex::from_index(index).unwrap();
                if !attacker.shots_on_board(defender).is_shot(cell) {
                    break cell;
                }
            };

            let byte = attacker.fire_shot(cell).unwrap();
            last_fired[ai] = Some(cell);
            attacked.receive_shot(byte).unwrap();
            let answer = attacked.answer_shot().unwrap();
            let outcome = attacker.accept_answer(&answer).unwrap();

            let hits = attacker.verified_hits();
            prop_assert!(hits >= prev_hits[ai]);
            prop_assert!(hits <= T as u8);
            prev_hits[ai] = hits;

            let counts = attacker.accepted_sunk_counts();
            for (i, &length) in DISTINCT_LENGTHS.iter().enumerate() {
                prop_assert!(counts[i] >= prev_sunk[ai][i]);
                prop_assert!(counts[i] <= geometry.ship_count_of_length(length));
            }
            prev_sunk[ai] = counts;

            if outcome == ShotOutcome::Win {
                break current;
            }
            let benign = matches!(outcome, ShotOutcome::Miss | ShotOutcome::Hit { .. });
            prop_assert!(benign);
            let loser_cells = occupied(geometry, &placements[di]);
            let shots_on_loser = attacker.shots_on_board(defender);
            prop_assert!(loser_cells.iter().any(|&c| !shots_on_loser.is_shot(c)));
            current = defender;
        };

        let li = role_index(winner.other());
        let (winner_game, loser_game) = match winner {
            Role::A => (&game_a, &game_b),
            Role::B => (&game_b, &game_a),
        };
        prop_assert_eq!(winner_game.state(), State::Finished { winner });
        prop_assert_eq!(winner_game.verified_hits(), T as u8);
        prop_assert_eq!(
            winner_game.accepted_sunk_counts().iter().sum::<u8>(),
            K as u8
        );
        let loser_cells = occupied(geometry, &placements[li]);
        let shots_on_loser = winner_game.shots_on_board(winner.other());
        prop_assert!(loser_cells.iter().all(|&c| shots_on_loser.is_shot(c)));
        // Loser finished at the same chain position by conceding T hits.
        prop_assert!(loser_game.verified_hits() < T as u8);
        prop_assert_eq!(loser_game.state(), State::Finished { winner });
        prop_assert_eq!(loser_game.hits_conceded(), T as u8);
        prop_assert_eq!(winner_game.hits_conceded(), loser_game.verified_hits());
    }
}
