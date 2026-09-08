//! Pure deterministic game state (paper Construction 4.2); no I/O.
//!
//! Not in the paper: the game ends on BOTH sides at the same chain position.
//! The shooter finishes on accepting its T-th verified hit; the defender
//! finishes when it answers the shot conceding its T-th hit. After that no
//! sender is expected, so both peers agree on the linear transcript.

use crate::openings::{self, AnswerRejection, ShotAnswer, SUNK_REPORT_SIZE};
use crate::params::{CellIndex, Geometry, Parameters, PlacementError, K, N, P, T};
use crate::wf::VerifiedBoardCommitment;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Fixed by the session bootstrap: lower identity key is A and commits first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    A,
    B,
}

impl Role {
    pub fn other(self) -> Role {
        match self {
            Role::A => Role::B,
            Role::B => Role::A,
        }
    }
}

/// At every nonterminal position exactly one sender is expected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    AwaitingShot { shooter: Role },
    AwaitingAnswer { shooter: Role, cell: CellIndex },
    Finished { winner: Role },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShotOutcome {
    Miss,
    Hit { newly_sunk: u8 },
    Win,
}

/// Deliberately no "peer cheated" variant: opening failures are
/// `AnswerRejected`; `InternalInvariantFailure` is a local incident.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GameError {
    WrongState,
    OutOfRangeShot {
        cell: u8,
    },
    RepeatedShot {
        cell: u8,
    },
    IllegalPlacement(PlacementError),
    WrongWitnessLength {
        expected: usize,
        actual: usize,
    },
    WrongCommitmentCount {
        expected: usize,
        actual: usize,
    },
    AnswerRejected(AnswerRejection),
    /// Class D: fail closed; an implementation incident, never proof of
    /// peer cheating.
    InternalInvariantFailure(&'static str),
}

impl fmt::Display for GameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GameError::WrongState => write!(f, "message does not match the current game state"),
            GameError::OutOfRangeShot { cell } => write!(f, "shot cell {cell} is out of range"),
            GameError::RepeatedShot { cell } => write!(f, "cell {cell} has already been shot"),
            GameError::IllegalPlacement(e) => write!(f, "illegal local placement: {e}"),
            GameError::WrongWitnessLength { expected, actual } => {
                write!(f, "blinder vector has length {actual}, expected {expected}")
            }
            GameError::WrongCommitmentCount { expected, actual } => {
                write!(f, "got {actual} entry commitments, expected {expected}")
            }
            GameError::AnswerRejected(e) => write!(f, "answer rejected: {e}"),
            GameError::InternalInvariantFailure(what) => {
                write!(f, "internal invariant failure: {what}")
            }
        }
    }
}

impl std::error::Error for GameError {}

#[derive(Zeroize, ZeroizeOnDrop)]
#[cfg_attr(fuzzing, derive(Clone))]
struct ResponderSecrets {
    e: Vec<u8>,
    s: Vec<Scalar>,
    sunk_counts: [u8; SUNK_REPORT_SIZE],
    sunk_blinders: [Scalar; SUNK_REPORT_SIZE],
}

/// Public shot tracking with incremental sunk supports. `remaining_unshot_cells[p]`
/// starts at the position's length; when it first reaches zero the position
/// has entered W_{l,S}: E_p joins the public sum, and on the responder side
/// (e_p, s_p) join the running (tau, theta). Update decisions are public;
/// only the added scalars are secret.
#[cfg_attr(fuzzing, derive(Clone))]
pub struct BoardShots {
    shot: [bool; N],
    remaining_unshot_cells: Box<[u8]>,
    fully_covered: Box<[bool]>,
    sunk_commitments: [RistrettoPoint; SUNK_REPORT_SIZE],
    secrets: Option<ResponderSecrets>,
}

fn length_index(geometry: &Geometry, length: u8) -> usize {
    geometry
        .distinct_lengths()
        .iter()
        .position(|&l| l == length)
        .expect("position length is a distinct fleet length")
}

impl BoardShots {
    fn new(params: &Parameters, secrets: Option<ResponderSecrets>) -> BoardShots {
        let geometry = params.geometry();
        let remaining_unshot_cells: Vec<u8> = (0..geometry.p())
            .map(|p| geometry.cells_of_position(p).len() as u8)
            .collect();
        BoardShots {
            shot: [false; N],
            remaining_unshot_cells: remaining_unshot_cells.into_boxed_slice(),
            fully_covered: vec![false; geometry.p()].into_boxed_slice(),
            sunk_commitments: [RistrettoPoint::default(); SUNK_REPORT_SIZE],
            secrets,
        }
    }

    pub fn new_verifier(params: &Parameters) -> BoardShots {
        Self::new(params, None)
    }

    pub fn new_responder(
        params: &Parameters,
        e: Vec<u8>,
        s: Vec<Scalar>,
    ) -> Result<BoardShots, GameError> {
        // Wrap secrets in the zeroizing container before any fallible check.
        let secrets = ResponderSecrets {
            e,
            s,
            sunk_counts: [0; SUNK_REPORT_SIZE],
            sunk_blinders: [Scalar::ZERO; SUNK_REPORT_SIZE],
        };
        if secrets.s.len() != P {
            return Err(GameError::WrongWitnessLength {
                expected: P,
                actual: secrets.s.len(),
            });
        }
        params
            .geometry()
            .validate_placement(&secrets.e)
            .map_err(GameError::IllegalPlacement)?;
        Ok(Self::new(params, Some(secrets)))
    }

    fn clear_secrets(&mut self) {
        self.secrets = None;
    }

    pub fn is_shot(&self, cell: CellIndex) -> bool {
        self.shot[cell.index() as usize]
    }

    pub fn sunk_commitments(&self) -> &[RistrettoPoint; SUNK_REPORT_SIZE] {
        &self.sunk_commitments
    }

    /// The cell joins the public shot set before the answer is computed.
    /// Rejection leaves shot history and running sums unchanged.
    pub fn register_shot(
        &mut self,
        geometry: &Geometry,
        entry_commitments: &[RistrettoPoint],
        cell: CellIndex,
    ) -> Result<(), GameError> {
        if entry_commitments.len() != P {
            return Err(GameError::WrongCommitmentCount {
                expected: P,
                actual: entry_commitments.len(),
            });
        }
        if self.is_shot(cell) {
            return Err(GameError::RepeatedShot { cell: cell.index() });
        }
        self.shot[cell.index() as usize] = true;
        for &p in geometry.support_of_cell(cell) {
            let remaining = &mut self.remaining_unshot_cells[p];
            *remaining = remaining
                .checked_sub(1)
                .expect("a counter decrements at most once per covering cell");
            if *remaining == 0 && !self.fully_covered[p] {
                self.fully_covered[p] = true;
                let index = length_index(geometry, geometry.cells_of_position(p).len() as u8);
                self.sunk_commitments[index] += entry_commitments[p];
                if let Some(secrets) = &mut self.secrets {
                    secrets.sunk_counts[index] += secrets.e[p];
                    secrets.sunk_blinders[index] += secrets.s[p];
                }
            }
        }
        Ok(())
    }

    #[allow(clippy::type_complexity)]
    fn responder_material(
        &self,
    ) -> Option<(
        &[u8],
        &[Scalar],
        &[u8; SUNK_REPORT_SIZE],
        &[Scalar; SUNK_REPORT_SIZE],
    )> {
        self.secrets.as_ref().map(|secrets| {
            (
                secrets.e.as_slice(),
                secrets.s.as_slice(),
                &secrets.sunk_counts,
                &secrets.sunk_blinders,
            )
        })
    }
}

#[cfg_attr(fuzzing, derive(Clone))]
pub struct Game<'a> {
    params: &'a Parameters,
    local_role: Role,
    state: State,
    own_board: BoardShots,
    own_entry_commitments: Vec<RistrettoPoint>,
    peer_board: BoardShots,
    peer_verified: VerifiedBoardCommitment,
    accepted_sunk_counts: [u8; SUNK_REPORT_SIZE],
    verified_hits: u8,
    hits_conceded: u8,
}

impl<'a> Game<'a> {
    pub fn new(
        params: &'a Parameters,
        local_role: Role,
        first_mover: Role,
        own_entry_commitments: Vec<RistrettoPoint>,
        e: Vec<u8>,
        s: Vec<Scalar>,
        peer_verified: VerifiedBoardCommitment,
    ) -> Result<Game<'a>, GameError> {
        let own_board = BoardShots::new_responder(params, e, s)?;
        if own_entry_commitments.len() != P {
            return Err(GameError::WrongCommitmentCount {
                expected: P,
                actual: own_entry_commitments.len(),
            });
        }
        Ok(Game {
            params,
            local_role,
            state: State::AwaitingShot {
                shooter: first_mover,
            },
            own_board,
            own_entry_commitments,
            peer_board: BoardShots::new_verifier(params),
            peer_verified,
            accepted_sunk_counts: [0; SUNK_REPORT_SIZE],
            verified_hits: 0,
            hits_conceded: 0,
        })
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn local_role(&self) -> Role {
        self.local_role
    }

    /// Incremented only after a valid hit opening.
    pub fn verified_hits(&self) -> u8 {
        self.verified_hits
    }

    pub fn accepted_sunk_counts(&self) -> [u8; SUNK_REPORT_SIZE] {
        self.accepted_sunk_counts
    }

    /// Honest `b = 1` answers on the own board; T of them finish the game.
    pub fn hits_conceded(&self) -> u8 {
        self.hits_conceded
    }

    pub fn shots_on_board(&self, role: Role) -> &BoardShots {
        if role == self.local_role {
            &self.own_board
        } else {
            &self.peer_board
        }
    }

    pub fn fire_shot(&mut self, cell: CellIndex) -> Result<u8, GameError> {
        let State::AwaitingShot { shooter } = self.state else {
            return Err(GameError::WrongState);
        };
        if shooter != self.local_role {
            return Err(GameError::WrongState);
        }
        self.peer_board.register_shot(
            self.params.geometry(),
            self.peer_verified.entry_commitments(),
            cell,
        )?;
        self.state = State::AwaitingAnswer {
            shooter: self.local_role,
            cell,
        };
        Ok(cell.index())
    }

    /// The cell joins the own board's public shot set before the answer.
    pub fn receive_shot(&mut self, cell: u8) -> Result<(), GameError> {
        let State::AwaitingShot { shooter } = self.state else {
            return Err(GameError::WrongState);
        };
        if shooter == self.local_role {
            return Err(GameError::WrongState);
        }
        let cell = CellIndex::from_index(cell).ok_or(GameError::OutOfRangeShot { cell })?;
        self.own_board
            .register_shot(self.params.geometry(), &self.own_entry_commitments, cell)?;
        self.state = State::AwaitingAnswer {
            shooter: self.local_role.other(),
            cell,
        };
        Ok(())
    }

    /// Conceding the T-th hit finishes the game with the peer as winner; the
    /// returned answer is still sent as the final frame.
    pub fn answer_shot(&mut self) -> Result<ShotAnswer, GameError> {
        let State::AwaitingAnswer { shooter, cell } = self.state else {
            return Err(GameError::WrongState);
        };
        if shooter == self.local_role {
            return Err(GameError::WrongState);
        }
        let (e, s, counts, blinders) =
            self.own_board
                .responder_material()
                .ok_or(GameError::InternalInvariantFailure(
                    "answer owed but the own-board secrets are gone",
                ))?;
        let answer = openings::answer_shot(self.params, cell, e, s, counts, blinders);
        // `b` is public (it is being sent).
        if answer.is_hit() {
            self.hits_conceded += 1;
        }
        if self.hits_conceded == T as u8 {
            self.finish(self.local_role.other());
        } else {
            self.state = State::AwaitingShot {
                shooter: self.local_role,
            };
        }
        Ok(answer)
    }

    /// Session-layer forfeit; erases secrets, keeps public tallies.
    pub fn finish_by_forfeit(&mut self, winner: Role) -> Result<(), GameError> {
        if matches!(self.state, State::Finished { .. }) {
            return Err(GameError::WrongState);
        }
        self.finish(winner);
        Ok(())
    }

    fn finish(&mut self, winner: Role) {
        self.state = State::Finished { winner };
        self.own_board.clear_secrets();
    }

    /// Uses the cached C_i and the public running sunk sums. At T hits the
    /// sunk counts must sum to K, else class-D internal failure.
    pub fn accept_answer(&mut self, answer: &ShotAnswer) -> Result<ShotOutcome, GameError> {
        let State::AwaitingAnswer { shooter, cell } = self.state else {
            return Err(GameError::WrongState);
        };
        if shooter != self.local_role {
            return Err(GameError::WrongState);
        }
        let outcome = openings::verify_answer(
            self.params,
            &self.peer_verified.cell_commitments()[cell.index() as usize],
            self.peer_board.sunk_commitments(),
            &self.accepted_sunk_counts,
            self.verified_hits,
            answer,
        )
        .map_err(GameError::AnswerRejected)?;

        if !outcome.hit {
            self.state = State::AwaitingShot {
                shooter: self.local_role.other(),
            };
            return Ok(ShotOutcome::Miss);
        }

        let newly_sunk: u8 =
            outcome.sunk_counts.iter().sum::<u8>() - self.accepted_sunk_counts.iter().sum::<u8>();
        self.accepted_sunk_counts = outcome.sunk_counts;
        self.verified_hits += 1;
        if self.verified_hits == T as u8 {
            if self.accepted_sunk_counts.iter().sum::<u8>() != K as u8 {
                return Err(GameError::InternalInvariantFailure(
                    "hit count reached T but cumulative sunk counts do not sum to K",
                ));
            }
            self.finish(self.local_role);
            return Ok(ShotOutcome::Win);
        }
        self.state = State::AwaitingShot {
            shooter: self.local_role.other(),
        };
        Ok(ShotOutcome::Hit { newly_sunk })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pedersen;
    use crate::wf::{self};
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use sha2::Sha512;

    fn test_params() -> Parameters {
        let h = RistrettoPoint::hash_from_bytes::<Sha512>(b"zkbattleship/test-only/game-H");
        Parameters::from_test_generators(RISTRETTO_BASEPOINT_POINT, h)
    }

    fn placement_a() -> Vec<u8> {
        let mut e = vec![0u8; P];
        e[0] = 1; // cells 0-4
        e[134] = 1; // cells 20-23
        e[292] = 1; // cells 40-42
        e[460] = 1; // cells 50-52
        e[643] = 1; // cells 70-71
        e
    }

    fn placement_b() -> Vec<u8> {
        let mut e = vec![0u8; P];
        e[5] = 1; // cells 5-9
        e[127] = 1; // cells 10-13
        e[272] = 1; // cells 14-16
        e[444] = 1; // cells 30-32
        e[625] = 1; // cells 50-51
        e
    }

    fn rng(seed: u8) -> ChaCha20Rng {
        ChaCha20Rng::from_seed([seed; 32])
    }

    fn blinders(seed: u8) -> Vec<Scalar> {
        let mut rng = rng(seed);
        (0..P).map(|_| Scalar::random(&mut rng)).collect()
    }

    fn identity_game(params: &Parameters) -> Game<'_> {
        let identity = RistrettoPoint::default;
        let peer = VerifiedBoardCommitment::from_parts_for_test(
            (0..P).map(|_| identity()).collect(),
            std::array::from_fn(|_| identity()),
        );
        Game::new(
            params,
            Role::A,
            Role::A,
            (0..P).map(|_| identity()).collect(),
            placement_a(),
            vec![Scalar::ZERO; P],
            peer,
        )
        .unwrap()
    }

    #[test]
    fn forfeit_erases_secrets_and_stops_game() {
        let mut game = identity_game(Parameters::standard_v1());
        assert!(game.own_board.secrets.is_some());
        game.finish_by_forfeit(Role::B).unwrap();
        assert_eq!(game.state(), State::Finished { winner: Role::B });
        assert!(game.own_board.secrets.is_none());
        assert_eq!(game.finish_by_forfeit(Role::A), Err(GameError::WrongState));
        assert_eq!(game.receive_shot(0), Err(GameError::WrongState));
        assert_eq!(game.answer_shot(), Err(GameError::WrongState));
    }

    #[test]
    fn state_machine_rejects_wrong_state_out_of_range_and_repeated_shots() {
        let params = test_params();
        let mut game = identity_game(&params);
        assert_eq!(game.state(), State::AwaitingShot { shooter: Role::A });

        assert_eq!(game.receive_shot(3), Err(GameError::WrongState));
        assert_eq!(game.answer_shot(), Err(GameError::WrongState));

        let cell = CellIndex::from_index(10).unwrap();
        assert_eq!(game.fire_shot(cell), Ok(10));
        assert_eq!(game.fire_shot(cell), Err(GameError::WrongState));
        assert_eq!(game.receive_shot(3), Err(GameError::WrongState));

        // Miss with rho = 0 against the identity C_10.
        let outcome = game
            .accept_answer(&ShotAnswer::Miss { rho: Scalar::ZERO })
            .unwrap();
        assert_eq!(outcome, ShotOutcome::Miss);
        assert_eq!(game.state(), State::AwaitingShot { shooter: Role::B });

        assert_eq!(
            game.receive_shot(200),
            Err(GameError::OutOfRangeShot { cell: 200 })
        );
        assert_eq!(game.receive_shot(60), Ok(()));
        assert_eq!(game.receive_shot(4), Err(GameError::WrongState));
        let answer = game.answer_shot().unwrap();
        assert!(!answer.is_hit()); // cell 60 is not covered by placement_a
        assert_eq!(
            game.fire_shot(cell),
            Err(GameError::RepeatedShot { cell: 10 })
        );
    }

    #[test]
    fn short_commitment_vector_does_not_mutate_shot_state() {
        let params = Parameters::standard_v1();
        let mut board = BoardShots::new_verifier(params);
        let cell = CellIndex::from_index(0).unwrap();
        let counters = board.remaining_unshot_cells.clone();
        assert_eq!(
            board.register_shot(params.geometry(), &[], cell),
            Err(GameError::WrongCommitmentCount {
                expected: P,
                actual: 0
            })
        );
        assert!(!board.is_shot(cell));
        assert_eq!(board.remaining_unshot_cells, counters);
        assert!(board.fully_covered.iter().all(|covered| !covered));
        assert_eq!(
            board.sunk_commitments,
            [RistrettoPoint::default(); SUNK_REPORT_SIZE]
        );
    }

    #[test]
    fn board_shots_counters_match_from_scratch() {
        let params = test_params();
        let geometry = params.geometry();
        let e = placement_a();
        let s = blinders(0x51);
        let entry: Vec<RistrettoPoint> = pedersen::commit_vector(&params, &e, &s);
        let mut board = BoardShots::new_responder(&params, e.clone(), s.clone()).unwrap();
        let mut shot = [false; N];

        // Compare incremental state against a from-scratch recomputation.
        let cells: [u8; 8] = [0, 1, 60, 2, 61, 3, 62, 4];
        for &i in &cells {
            let cell = CellIndex::from_index(i).unwrap();
            board.register_shot(geometry, &entry, cell).unwrap();
            shot[i as usize] = true;

            for &length in geometry.distinct_lengths() {
                let index = length_index(geometry, length);
                let w = openings::sunk_positions(geometry, length, &shot);
                let expected_sum: RistrettoPoint = w.iter().map(|&p| entry[p]).sum();
                assert_eq!(board.sunk_commitments()[index], expected_sum);
            }
        }

        let mut board2 = BoardShots::new_verifier(&params);
        for &i in &[0u8, 1, 2, 3] {
            board2
                .register_shot(geometry, &entry, CellIndex::from_index(i).unwrap())
                .unwrap();
        }
        assert_eq!(
            board2.sunk_commitments()[length_index(geometry, 5)],
            RistrettoPoint::default()
        );
        board2
            .register_shot(geometry, &entry, CellIndex::from_index(4).unwrap())
            .unwrap();
        assert_eq!(
            board2.sunk_commitments()[length_index(geometry, 5)],
            entry[0]
        );

        let (e2, s2, counts, theta) = board.responder_material().unwrap();
        assert_eq!(counts[length_index(geometry, 5)], 1);
        assert_eq!(theta[length_index(geometry, 5)], s2[0]);
        assert_eq!(e2[0], 1);
        for &length in geometry.distinct_lengths() {
            let index = length_index(geometry, length);
            let w = openings::sunk_positions(geometry, length, &shot);
            let tau: u8 = w.iter().map(|&p| e[p]).sum();
            let expected_theta: Scalar = w.iter().map(|&p| s[p]).sum();
            assert_eq!(counts[index], tau);
            assert_eq!(theta[index], expected_theta);
        }
    }

    /// Real proofs; slow in debug.
    #[test]
    fn honest_full_game_completes() {
        let params = Parameters::standard_v1();
        let id_a = [0x0A; 32];
        let id_b = [0x0B; 32];
        let sid = [0x77; 32];

        let e_a = placement_a();
        let e_b = placement_b();
        let s_a = blinders(0xA0);
        let s_b = blinders(0xB0);
        let (board_a, proof_a) =
            wf::prove_with_rng(params, &id_a, &sid, &e_a, &s_a, rng(0xA1)).unwrap();
        let (board_b, proof_b) =
            wf::prove_with_rng(params, &id_b, &sid, &e_b, &s_b, rng(0xB1)).unwrap();
        let verified_a = wf::verify(params, &id_a, &sid, &board_a, &proof_a).unwrap();
        let verified_b = wf::verify(params, &id_b, &sid, &board_b, &proof_b).unwrap();

        let mut game_a = Game::new(
            params,
            Role::A,
            Role::A,
            board_a.entry_commitments().to_vec(),
            e_a,
            s_a,
            verified_b,
        )
        .unwrap();
        let mut game_b = Game::new(
            params,
            Role::B,
            Role::A,
            board_b.entry_commitments().to_vec(),
            e_b,
            s_b,
            verified_a,
        )
        .unwrap();

        let mut current = Role::A;
        let winner = loop {
            let defender = current.other();
            let (attacker, attacked) = match current {
                Role::A => (&mut game_a, &mut game_b),
                Role::B => (&mut game_b, &mut game_a),
            };
            let cell = (0..N as u8)
                .map(|i| CellIndex::from_index(i).unwrap())
                .find(|c| !attacker.shots_on_board(defender).is_shot(*c))
                .expect("unshot cells remain");
            let byte = attacker.fire_shot(cell).unwrap();
            attacked.receive_shot(byte).unwrap();
            let answer = attacked.answer_shot().unwrap();
            let bytes = answer.encode();
            let decoded = ShotAnswer::decode(&bytes).unwrap();
            match attacker.accept_answer(&decoded).unwrap() {
                ShotOutcome::Win => break current,
                ShotOutcome::Miss | ShotOutcome::Hit { .. } => current = defender,
            }
        };

        assert_eq!(winner, Role::A);
        assert_eq!(game_a.state(), State::Finished { winner: Role::A });
        assert_eq!(game_a.verified_hits(), T as u8);
        assert_eq!(game_a.accepted_sunk_counts().iter().sum::<u8>(), K as u8);
        assert!(game_b.verified_hits() < T as u8);
        assert_eq!(
            game_a.fire_shot(CellIndex::from_index(0).unwrap()),
            Err(GameError::WrongState)
        );

        // Loser finished at the same chain position by conceding T hits.
        assert_eq!(game_b.state(), State::Finished { winner: Role::A });
        assert_eq!(game_b.hits_conceded(), T as u8);
        assert_eq!(game_a.hits_conceded(), game_b.verified_hits());
        assert_eq!(
            game_b.fire_shot(CellIndex::from_index(99).unwrap()),
            Err(GameError::WrongState)
        );
        assert_eq!(game_b.receive_shot(99), Err(GameError::WrongState));
        assert_eq!(game_b.answer_shot(), Err(GameError::WrongState));
    }

    #[test]
    fn defender_finishes_when_conceding_the_last_hit() {
        let params = test_params();
        let geometry = params.geometry();
        let identity = RistrettoPoint::default;
        let peer = VerifiedBoardCommitment::from_parts_for_test(
            (0..P).map(|_| identity()).collect(),
            std::array::from_fn(|_| identity()),
        );
        let e = placement_a();
        let mut game = Game::new(
            &params,
            Role::B,
            Role::A,
            (0..P).map(|_| identity()).collect(),
            e.clone(),
            vec![Scalar::ZERO; P],
            peer,
        )
        .unwrap();

        let mut occupied: Vec<u8> = Vec::new();
        for (p, &bit) in e.iter().enumerate() {
            if bit == 1 {
                occupied.extend(geometry.cells_of_position(p).iter().map(|c| c.index()));
            }
        }
        assert_eq!(occupied.len(), T);

        for (n, &cell) in occupied.iter().enumerate() {
            assert_eq!(game.state(), State::AwaitingShot { shooter: Role::A });
            game.receive_shot(cell).unwrap();
            let answer = game.answer_shot().unwrap();
            assert!(answer.is_hit());
            assert_eq!(game.hits_conceded(), n as u8 + 1);
            if n + 1 < T {
                // Skip the defender's own turn with a miss (identity C_i).
                assert_eq!(game.state(), State::AwaitingShot { shooter: Role::B });
                game.fire_shot(CellIndex::from_index(n as u8).unwrap())
                    .unwrap();
                game.accept_answer(&ShotAnswer::Miss { rho: Scalar::ZERO })
                    .unwrap();
            }
        }
        assert_eq!(game.state(), State::Finished { winner: Role::A });
        assert_eq!(game.verified_hits(), 0);
        assert_eq!(game.answer_shot(), Err(GameError::WrongState));
        assert_eq!(game.receive_shot(99), Err(GameError::WrongState));
    }
}
