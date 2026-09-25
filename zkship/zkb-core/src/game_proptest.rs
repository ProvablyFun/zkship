//! State-machine properties over random fleets and shot orders. Setups skip
//! the proof (commitments are honest, so every answer check still runs).

use crate::fleet::{Fleet, SHIP_BITS};
use crate::game::{Game, GameContext, GameError, Role, ShotOutcome, State};
use crate::params::{CellIndex, Parameters, Rules, K, N, T};
use crate::setup::VerifiedSetup;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use proptest::prelude::*;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn role_index(role: Role) -> usize {
    match role {
        Role::A => 0,
        Role::B => 1,
    }
}

fn board(params: &Parameters, fleet: &Fleet, seed: u64) -> (Vec<Scalar>, Vec<RistrettoPoint>) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let rho: Vec<Scalar> = (0..SHIP_BITS).map(|_| Scalar::random(&mut rng)).collect();
    let bits = fleet.ship_bits();
    let cells = (0..SHIP_BITS)
        .map(|k| Scalar::from(u64::from(bits[k])) * params.g() + rho[k] * params.h())
        .collect();
    (rho, cells)
}

fn arb_shot_order() -> impl Strategy<Value = Vec<u8>> {
    Just((0..N as u8).collect::<Vec<_>>()).prop_shuffle()
}

proptest! {
    #![proptest_config(ProptestConfig {
        // Each case plays a full game with real not-sunk proofs.
        cases: 16,
        .. ProptestConfig::default()
    })]

    #[test]
    fn honest_random_games_never_abort(
        no_touch in any::<bool>(),
        seeds in any::<(u64, u64)>(),
        shots_a in arb_shot_order(),
        shots_b in arb_shot_order(),
        first_is_a in any::<bool>(),
    ) {
        let rules = if no_touch { Rules::NoTouch } else { Rules::Standard };
        let params = Parameters::for_rules(rules);
        let fleets = [
            Fleet::random(&mut ChaCha20Rng::seed_from_u64(seeds.0), rules),
            Fleet::random(&mut ChaCha20Rng::seed_from_u64(seeds.1), rules),
        ];
        let first_mover = if first_is_a { Role::A } else { Role::B };
        let (rho_a, cells_a) = board(params, &fleets[0], seeds.0);
        let (rho_b, cells_b) = board(params, &fleets[1], seeds.1);
        let ctx = |own: u8, peer: u8| GameContext { own_id: [own; 32], peer_id: [peer; 32], sid: [9; 32] };
        let mut game_a = Game::new(
            params, Role::A, first_mover, ctx(1, 2), cells_a.clone(), &fleets[0], rho_a, &[1; 32],
            VerifiedSetup::from_ship_cells_for_test(cells_b.clone()),
        ).unwrap();
        let mut game_b = Game::new(
            params, Role::B, first_mover, ctx(2, 1), cells_b, &fleets[1], rho_b, &[2; 32],
            VerifiedSetup::from_ship_cells_for_test(cells_a),
        ).unwrap();

        let shot_orders = [shots_a, shots_b];
        let mut cursors = [0usize; 2];
        let mut last_fired: [Option<CellIndex>; 2] = [None, None];
        let mut prev_hits = [0u8; 2];
        let mut sinks = [0usize; 2];

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
                let rejected = matches!(attacker.fire_shot(prev), Err(GameError::RepeatedShot { .. }));
                prop_assert!(rejected);
            }
            let cell = loop {
                let cell = CellIndex::from_index(shot_orders[ai][cursors[ai]]).unwrap();
                cursors[ai] += 1;
                if !attacker.shots_on_board(defender).is_shot(cell) {
                    break cell;
                }
            };
            let byte = attacker.fire_shot(cell).unwrap();
            last_fired[ai] = Some(cell);
            attacked.receive_shot(byte).unwrap();
            let answer = attacked.answer_shot().unwrap();
            prop_assert_eq!(answer.is_hit(), fleets[di].occupied()[cell.index() as usize]);
            let decoded = attacker.decode_answer(&answer.encode()).unwrap();
            let outcome = attacker.accept_answer(&decoded).unwrap();

            let hits = attacker.verified_hits();
            prop_assert!(hits >= prev_hits[ai] && hits <= T as u8);
            prev_hits[ai] = hits;
            if let ShotOutcome::Sunk { ship } = outcome {
                sinks[ai] += 1;
                let cells = fleets[di].cells(ship as usize);
                prop_assert!(cells.contains(&cell));
                prop_assert!(cells.iter().all(|c| attacker.shots_on_board(defender).is_shot(*c)));
            }
            if outcome == ShotOutcome::Win {
                break current;
            }
            // No ship is fully shot without having been announced.
            for j in 0..K {
                let all_shot = fleets[di]
                    .cells(j)
                    .iter()
                    .all(|c| attacker.shots_on_board(defender).is_shot(*c));
                prop_assert_eq!(all_shot, attacker.peer_sunk()[j]);
            }
            current = defender;
        };

        let (winner_game, loser_game) = match winner {
            Role::A => (&game_a, &game_b),
            Role::B => (&game_b, &game_a),
        };
        prop_assert_eq!(sinks[role_index(winner)], K - 1);
        prop_assert_eq!(winner_game.state(), State::Finished { winner });
        prop_assert_eq!(winner_game.verified_hits(), T as u8);
        prop_assert_eq!(winner_game.peer_sunk(), [true; K]);
        prop_assert!(loser_game.verified_hits() < T as u8);
        prop_assert_eq!(loser_game.state(), State::Finished { winner });
        prop_assert_eq!(loser_game.hits_conceded(), T as u8);
        prop_assert_eq!(winner_game.hits_conceded(), loser_game.verified_hits());
    }
}
