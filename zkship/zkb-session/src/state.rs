//! Session driver. Message order: A Commit, B Commit (only after A's proof verifies),
//! CoinCommit, CoinNonce, CoinReveal, then Shot/Answer alternating. At every nonterminal
//! chain position exactly one sender is expected; ordinary messages and `Resign` are accepted
//! only from it, so each chain position has one legitimate successor. To give up off-turn,
//! close the transport (class C).
//!
//! Error classes: A [`SessionError::Attributable`] = chain-extending, validly signed frame with
//! invalid content (session aborts, secrets erased, offending frame retained);
//! B [`SessionError::ClassB`] = non-extending/replayed/unauthenticated/corrupt, never evidence,
//! state unchanged; C timeout/silence is deliberately not representable, since a two-party
//! transcript cannot attribute silence (paper Construction 7.1, S7, and Section 10);
//! D [`SessionError::InternalInvariant`] = implementation incident.

use crate::codec::{CodecError, MessageType, COMMIT_ENTRY_LEN};
use crate::coin;
use crate::frame::{
    self, AuthenticatedFrame, ChainError, ChainExpectation, SignedFrame,
};
use crate::identity::{AuthenticatedPeer, IdentityKeypair};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use std::fmt;
use zkb_core::game::{Game, GameError, Role, ShotOutcome, State as GameState};
use zkb_core::openings::{AnswerDecodeError, AnswerRejection, ShotAnswer};
use zkb_core::params::{CellIndex, Parameters, P};
use zkb_core::wf::{self, UnverifiedBoardCommitment, VerifiedBoardCommitment, WfError, WfProof};
use zeroize::Zeroizing;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClassBReason {
    Malformed(CodecError),
    WrongSession,
    WrongSequence { expected: u64, actual: u64 },
    WrongPrevHash,
    BadSignature,
}

impl fmt::Display for ClassBReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClassBReason::Malformed(e) => write!(f, "malformed frame: {e}"),
            ClassBReason::WrongSession => write!(f, "frame belongs to a different session"),
            ClassBReason::WrongSequence { expected, actual } => {
                write!(f, "frame sequence {actual}, expected {expected}")
            }
            ClassBReason::WrongPrevHash => write!(f, "frame prev_hash does not match the chain head"),
            ClassBReason::BadSignature => write!(f, "frame signature does not verify"),
        }
    }
}

#[derive(Debug)]
pub enum Violation {
    SenderRoleMismatch { claimed: u8 },
    UnexpectedMessage { message_type: MessageType },
    OutOfTurnResign,
    InvalidCommit(WfError),
    InvalidAnswerEncoding(AnswerDecodeError),
    InvalidAnswer(AnswerRejection),
    InvalidShot(GameError),
    BadCoinReveal,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Violation::SenderRoleMismatch { claimed } => {
                write!(f, "frame claims impossible sender-role byte {claimed}")
            }
            Violation::UnexpectedMessage { message_type } => {
                write!(f, "unexpected {message_type:?} in the current session state")
            }
            Violation::OutOfTurnResign => write!(f, "out-of-turn resign"),
            Violation::InvalidCommit(e) => write!(f, "invalid commit: {e}"),
            Violation::InvalidAnswerEncoding(e) => write!(f, "invalid answer encoding: {e}"),
            Violation::InvalidAnswer(e) => write!(f, "invalid answer: {e}"),
            Violation::InvalidShot(e) => write!(f, "invalid shot: {e}"),
            Violation::BadCoinReveal => write!(f, "coin reveal does not match the commitment"),
        }
    }
}

#[derive(Debug)]
pub struct AttributableViolation {
    pub frame: SignedFrame,
    pub violation: Violation,
}

#[derive(Debug)]
pub enum SessionError {
    ClassB(ClassBReason),
    Attributable(Box<AttributableViolation>),
    InternalInvariant(&'static str),
    /// Local API misuse.
    WrongLocalState(&'static str),
    LocalGame(GameError),
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionError::ClassB(e) => write!(f, "class-B input: {e}"),
            SessionError::Attributable(e) => write!(f, "attributable peer violation: {}", e.violation),
            SessionError::InternalInvariant(m) => write!(f, "internal invariant failure: {m}"),
            SessionError::WrongLocalState(m) => write!(f, "wrong local state: {m}"),
            SessionError::LocalGame(e) => write!(f, "invalid local game data: {e}"),
        }
    }
}

impl std::error::Error for SessionError {}

#[derive(Debug)]
pub enum AcceptOutcome {
    CommitVerified,
    CoinProgress,
    GameReady {
        first_mover: Role,
    },
    /// Carries the `Answer` frame to send.
    ShotReceived {
        cell: CellIndex,
        hit: bool,
        answer: SignedFrame,
        /// `Some` when this answer concedes the T-th hit; `answer` is then the final frame.
        winner: Option<Role>,
    },
    Answer(ShotOutcome),
    GameFinished {
        winner: Role,
    },
    PeerResigned,
}

#[derive(Clone, Copy, Debug)]
struct ChainHead {
    sequence: u64,
    hash: [u8; 32],
}

#[derive(Default)]
struct OwnBoard {
    entry_commitments: Option<Vec<RistrettoPoint>>,
    e: Option<Zeroizing<Vec<u8>>>,
    s: Option<Zeroizing<Vec<Scalar>>>,
}

impl OwnBoard {
    fn take(&mut self) -> OwnBoard {
        std::mem::take(self)
    }
}

struct CommitPhase {
    a_done: bool,
    b_done: bool,
    own: OwnBoard,
    peer_verified: Option<VerifiedBoardCommitment>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CoinStep {
    Commit,
    Nonce,
    Reveal,
}

struct CoinPhase<'a> {
    step: CoinStep,
    coin_commit: Option<[u8; 32]>,
    r_a: Option<[u8; 32]>,
    r_b: Option<[u8; 32]>,
    own: OwnBoard,
    peer_verified: Option<VerifiedBoardCommitment>,
    game: Option<Game<'a>>,
}

enum Phase<'a> {
    Commit(Box<CommitPhase>),
    Coin(Box<CoinPhase<'a>>),
    Playing(Box<Game<'a>>),
    /// Board secrets dropped.
    Aborted,
    /// Retains the game for its public tallies; `Game` already dropped its secrets.
    Finished {
        winner: Role,
        game: Option<Box<Game<'a>>>,
    },
}

enum Transition {
    ToCoin,
    ToPlaying,
    Finished { winner: Role },
}

/// One local player's view.
pub struct Session<'a> {
    params: &'a Parameters,
    keypair: &'a IdentityKeypair,
    local_role: Role,
    peer: AuthenticatedPeer,
    sid: [u8; 32],
    head: ChainHead,
    phase: Phase<'a>,
    transcript: Vec<Vec<u8>>,
}

fn craft_next(
    keypair: &IdentityKeypair,
    sid: &[u8; 32],
    local_role: Role,
    head: &mut ChainHead,
    transcript: &mut Vec<Vec<u8>>,
    message_type: MessageType,
    payload: Vec<u8>,
) -> SignedFrame {
    let frame = SignedFrame::craft(
        keypair,
        sid,
        local_role,
        head.sequence + 1,
        message_type,
        &head.hash,
        payload,
    );
    head.sequence += 1;
    head.hash = frame.frame_hash();
    transcript.push(frame.bytes().to_vec());
    frame
}

fn advance_chain(head: &mut ChainHead, transcript: &mut Vec<Vec<u8>>, frame: &AuthenticatedFrame) {
    debug_assert_eq!(frame.frame().header().sequence, head.sequence + 1);
    head.sequence += 1;
    head.hash = frame.frame().frame_hash();
    transcript.push(frame.frame().bytes().to_vec());
}

fn attributable(frame: AuthenticatedFrame, violation: Violation) -> SessionError {
    SessionError::Attributable(Box::new(AttributableViolation {
        frame: frame.into_frame(),
        violation,
    }))
}

fn build_game<'a>(
    params: &'a Parameters,
    local_role: Role,
    first_mover: Role,
    own: &mut OwnBoard,
    peer_verified: &mut Option<VerifiedBoardCommitment>,
) -> Result<Game<'a>, SessionError> {
    let mut e = own.e.take().expect("witness present until game build");
    let mut s = own.s.take().expect("witness present until game build");
    let entry = own.entry_commitments.take().expect("local commit produced");
    let peer = peer_verified.take().expect("peer commit verified");
    Game::new(params, local_role, first_mover, entry, std::mem::take(&mut *e), std::mem::take(&mut *s), peer)
        .map_err(|_| SessionError::InternalInvariant("validated board could not initialize game"))
}

impl<'a> Session<'a> {
    /// `e`, `s`: secret placement and fresh blinders, moved in and zeroized on drop.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        params: &'a Parameters,
        keypair: &'a IdentityKeypair,
        local_role: Role,
        peer: AuthenticatedPeer,
        sid: [u8; 32],
        genesis_hash: [u8; 32],
        e: Vec<u8>,
        s: Vec<Scalar>,
    ) -> Result<Session<'a>, SessionError> {
        let e = Zeroizing::new(e);
        let s = Zeroizing::new(s);
        if s.len() != P {
            return Err(SessionError::LocalGame(GameError::WrongWitnessLength {
                expected: P,
                actual: s.len(),
            }));
        }
        params
            .geometry()
            .validate_placement(&e)
            .map_err(GameError::IllegalPlacement)
            .map_err(SessionError::LocalGame)?;
        Ok(Session {
            params,
            keypair,
            local_role,
            peer,
            sid,
            head: ChainHead {
                sequence: 0,
                hash: genesis_hash,
            },
            phase: Phase::Commit(Box::new(CommitPhase {
                a_done: false,
                b_done: false,
                own: OwnBoard {
                    entry_commitments: None,
                    e: Some(e),
                    s: Some(s),
                },
                peer_verified: None,
            })),
            transcript: Vec::new(),
        })
    }

    pub fn sid(&self) -> &[u8; 32] {
        &self.sid
    }

    pub fn local_role(&self) -> Role {
        self.local_role
    }

    pub fn head_sequence(&self) -> u64 {
        self.head.sequence
    }

    pub fn head_hash(&self) -> &[u8; 32] {
        &self.head.hash
    }

    /// Accepted and produced frames in chain order, byte-for-byte.
    pub fn transcript(&self) -> &[Vec<u8>] {
        &self.transcript
    }

    pub fn winner(&self) -> Option<Role> {
        match &self.phase {
            Phase::Finished { winner, .. } => Some(*winner),
            _ => None,
        }
    }

    /// Remains available after finish (public tallies only).
    pub fn game(&self) -> Option<&Game<'a>> {
        match &self.phase {
            Phase::Playing(game) => Some(game),
            Phase::Coin(cp) => cp.game.as_ref(),
            Phase::Finished { game, .. } => game.as_deref(),
            Phase::Commit(_) | Phase::Aborted => None,
        }
    }

    /// An abort assigns no winner.
    pub fn is_aborted(&self) -> bool {
        matches!(self.phase, Phase::Aborted)
    }

    /// Erases board secrets, keeps the public transcript; for disconnects/timeouts. Not evidence.
    pub fn abort(&mut self) {
        if !matches!(self.phase, Phase::Finished { .. }) {
            self.phase = Phase::Aborted;
        }
    }

    fn abort_on_failure<T>(&mut self, result: &Result<T, SessionError>) {
        if matches!(result, Err(SessionError::Attributable(_) | SessionError::InternalInvariant(_))) {
            self.abort();
        }
    }

    pub fn expected_sender(&self) -> Option<Role> {
        match &self.phase {
            Phase::Commit(cp) => Some(if cp.a_done { Role::B } else { Role::A }),
            Phase::Coin(cp) => Some(match cp.step {
                CoinStep::Commit => Role::A,
                CoinStep::Nonce => Role::B,
                CoinStep::Reveal => Role::A,
            }),
            Phase::Playing(game) => match game.state() {
                GameState::AwaitingShot { shooter } => Some(shooter),
                GameState::AwaitingAnswer { shooter, .. } => Some(shooter.other()),
                GameState::Finished { .. } => None,
            },
            Phase::Finished { .. } | Phase::Aborted => None,
        }
    }

    fn enter_coin_phase(&mut self) {
        let Phase::Commit(cp) = &mut self.phase else {
            return;
        };
        let own = cp.own.take();
        let peer_verified = cp.peer_verified.take().expect("both commits verified");
        self.phase = Phase::Coin(Box::new(CoinPhase {
            step: CoinStep::Commit,
            coin_commit: None,
            r_a: None,
            r_b: None,
            own,
            peer_verified: Some(peer_verified),
            game: None,
        }));
    }

    fn enter_playing_phase(&mut self) {
        let Phase::Coin(cp) = &mut self.phase else {
            return;
        };
        let game = cp.game.take().expect("game built before play");
        self.phase = Phase::Playing(Box::new(game));
    }

    fn finish(&mut self, winner: Role) {
        let previous = std::mem::replace(&mut self.phase, Phase::Finished { winner, game: None });
        let mut game = match previous {
            Phase::Playing(game) => Some(game),
            Phase::Coin(cp) => cp.game.map(Box::new),
            Phase::Commit(_) | Phase::Finished { .. } | Phase::Aborted => None,
        };
        if let Some(game) = &mut game {
            if !matches!(game.state(), GameState::Finished { .. }) {
                game.finish_by_forfeit(winner).expect("live game can finish by forfeit");
            }
        }
        self.phase = Phase::Finished { winner, game };
    }

    /// Next protocol-fixed message owed (Commit or a coin message), `None` while waiting.
    /// Shots go through [`Session::fire_shot`].
    pub fn produce<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<Option<SignedFrame>, SessionError> {
        let commit_turn = matches!(&self.phase, Phase::Commit(cp) if {
            let expected = if cp.a_done { Role::B } else { Role::A };
            expected == self.local_role
        });
        if commit_turn {
            let (board, proof) = {
                let Phase::Commit(cp) = &self.phase else {
                    unreachable!()
                };
                let e = cp.own.e.as_ref().expect("witness present");
                let s = cp.own.s.as_ref().expect("witness present");
                wf::prove(
                    self.params,
                    self.keypair.peer_key().as_bytes(),
                    &self.sid,
                    e,
                    s.as_slice(),
                )
                .map_err(|_| {
                    SessionError::InternalInvariant("local prover refused its validated witness")
                })?
            };
            let mut payload = board.to_bytes();
            payload.extend_from_slice(&proof.encode());
            let entry = board.entry_commitments().to_vec();
            let frame = craft_next(
                self.keypair,
                &self.sid,
                self.local_role,
                &mut self.head,
                &mut self.transcript,
                MessageType::Commit,
                payload,
            );
            let mut to_coin = false;
            if let Phase::Commit(cp) = &mut self.phase {
                cp.own.entry_commitments = Some(entry);
                match self.local_role {
                    Role::A => cp.a_done = true,
                    Role::B => cp.b_done = true,
                }
                to_coin = cp.a_done && cp.b_done;
            }
            if to_coin {
                self.enter_coin_phase();
            }
            return Ok(Some(frame));
        }

        let coin_action = match &mut self.phase {
            Phase::Coin(cp) => match cp.step {
                CoinStep::Commit if self.local_role == Role::A => {
                    let r_a = coin::sample_nonce(rng);
                    let commitment = coin::coin_commit(&self.sid, &r_a);
                    cp.r_a = Some(r_a);
                    cp.coin_commit = Some(commitment);
                    cp.step = CoinStep::Nonce;
                    Some((MessageType::CoinCommit, commitment.to_vec()))
                }
                CoinStep::Nonce if self.local_role == Role::B => {
                    let r_b = coin::sample_nonce(rng);
                    cp.r_b = Some(r_b);
                    cp.step = CoinStep::Reveal;
                    Some((MessageType::CoinNonce, r_b.to_vec()))
                }
                CoinStep::Reveal if self.local_role == Role::A => {
                    let r_a = cp.r_a.take().expect("A sampled r_A");
                    Some((MessageType::CoinReveal, r_a.to_vec()))
                }
                _ => None,
            },
            _ => None,
        };
        if let Some((message_type, payload)) = coin_action {
            let frame = craft_next(
                self.keypair,
                &self.sid,
                self.local_role,
                &mut self.head,
                &mut self.transcript,
                message_type,
                payload,
            );
            if message_type == MessageType::CoinReveal {
                self.enter_playing_phase();
            }
            return Ok(Some(frame));
        }
        Ok(None)
    }

    pub fn fire_shot(&mut self, cell: CellIndex) -> Result<SignedFrame, SessionError> {
        let Phase::Playing(game) = &mut self.phase else {
            return Err(SessionError::WrongLocalState("no game in progress"));
        };
        let byte = game.fire_shot(cell).map_err(SessionError::LocalGame)?;
        Ok(craft_next(
            self.keypair,
            &self.sid,
            self.local_role,
            &mut self.head,
            &mut self.transcript,
            MessageType::Shot,
            vec![byte],
        ))
    }

    /// Only while the local player is the expected next sender; otherwise close the transport.
    pub fn resign(&mut self) -> Result<SignedFrame, SessionError> {
        if self.expected_sender() != Some(self.local_role) {
            return Err(SessionError::WrongLocalState(
                "not the expected next sender; close the transport instead of an out-of-turn Resign",
            ));
        }
        let frame = craft_next(
            self.keypair,
            &self.sid,
            self.local_role,
            &mut self.head,
            &mut self.transcript,
            MessageType::Resign,
            Vec::new(),
        );
        self.finish(self.local_role.other());
        Ok(frame)
    }

    /// Structural parse, then chain gate (class B), then role/semantic checks (attributable).
    /// Attributable and internal failures abort the session permanently.
    pub fn accept(&mut self, bytes: &[u8]) -> Result<AcceptOutcome, SessionError> {
        if self.is_aborted() {
            return Err(SessionError::WrongLocalState("session has aborted"));
        }
        let result = self.accept_inner(bytes);
        self.abort_on_failure(&result);
        result
    }

    fn accept_inner(&mut self, bytes: &[u8]) -> Result<AcceptOutcome, SessionError> {
        let frame = SignedFrame::decode(bytes)
            .map_err(|e| SessionError::ClassB(ClassBReason::Malformed(e)))?;
        let expectation = ChainExpectation {
            sid: self.sid,
            sequence: self.head.sequence + 1,
            prev_hash: self.head.hash,
        };
        let frame = frame.authenticate(&expectation, &self.peer).map_err(|e| {
            SessionError::ClassB(match e {
                ChainError::WrongSession => ClassBReason::WrongSession,
                ChainError::WrongSequence { expected, actual } => {
                    ClassBReason::WrongSequence { expected, actual }
                }
                ChainError::WrongPrevHash => ClassBReason::WrongPrevHash,
                ChainError::BadSignature => ClassBReason::BadSignature,
            })
        })?;
        let claimed = frame.frame().header().sender_role;
        if claimed != frame::role_to_byte(self.local_role.other()) {
            return Err(attributable(frame, Violation::SenderRoleMismatch { claimed }));
        }
        self.accept_authenticated(frame)
    }

    fn accept_authenticated(
        &mut self,
        frame: AuthenticatedFrame,
    ) -> Result<AcceptOutcome, SessionError> {
        let sender = self.local_role.other();
        let message_type = frame.frame().header().message_type;

        if message_type == MessageType::Resign {
            if self.expected_sender() == Some(sender) {
                advance_chain(&mut self.head, &mut self.transcript, &frame);
                self.finish(self.local_role);
                return Ok(AcceptOutcome::PeerResigned);
            }
            return Err(attributable(frame, Violation::OutOfTurnResign));
        }

        let mut transition: Option<Transition> = None;
        let outcome = match &mut self.phase {
            Phase::Commit(cp) => {
                let expected = if cp.a_done { Role::B } else { Role::A };
                if message_type != MessageType::Commit || expected != sender {
                    return Err(attributable(
                        frame,
                        Violation::UnexpectedMessage { message_type },
                    ));
                }
                let payload = frame.frame().payload();
                let (entry_bytes, proof_bytes) = payload.split_at(COMMIT_ENTRY_LEN);
                let verified = (|| -> Result<VerifiedBoardCommitment, WfError> {
                    let board = UnverifiedBoardCommitment::from_bytes(entry_bytes)?;
                    let proof = WfProof::decode(proof_bytes)?;
                    wf::verify(self.params, self.peer.key().as_bytes(), &self.sid, &board, &proof)
                })();
                let verified = match verified {
                    Ok(v) => v,
                    Err(e) => return Err(attributable(frame, Violation::InvalidCommit(e))),
                };
                match sender {
                    Role::A => cp.a_done = true,
                    Role::B => cp.b_done = true,
                }
                cp.peer_verified = Some(verified);
                advance_chain(&mut self.head, &mut self.transcript, &frame);
                if cp.a_done && cp.b_done {
                    transition = Some(Transition::ToCoin);
                }
                Ok(AcceptOutcome::CommitVerified)
            }
            Phase::Coin(cp) => match (cp.step, message_type, sender) {
                (CoinStep::Commit, MessageType::CoinCommit, Role::A) => {
                    let commitment: [u8; 32] = frame
                        .frame()
                        .payload()
                        .try_into()
                        .expect("payload length checked structurally");
                    cp.coin_commit = Some(commitment);
                    cp.step = CoinStep::Nonce;
                    advance_chain(&mut self.head, &mut self.transcript, &frame);
                    Ok(AcceptOutcome::CoinProgress)
                }
                (CoinStep::Nonce, MessageType::CoinNonce, Role::B) => {
                    let r_b: [u8; 32] = frame
                        .frame()
                        .payload()
                        .try_into()
                        .expect("payload length checked structurally");
                    cp.r_b = Some(r_b);
                    cp.step = CoinStep::Reveal;
                    let mut outcome = AcceptOutcome::CoinProgress;
                    if self.local_role == Role::A {
                        let r_a = cp.r_a.as_ref().expect("A sampled r_A");
                        let first_mover = coin::first_mover(&self.sid, r_a, &r_b);
                        let game = build_game(
                            self.params,
                            self.local_role,
                            first_mover,
                            &mut cp.own,
                            &mut cp.peer_verified,
                        )?;
                        cp.game = Some(game);
                        outcome = AcceptOutcome::GameReady { first_mover };
                    }
                    advance_chain(&mut self.head, &mut self.transcript, &frame);
                    Ok(outcome)
                }
                (CoinStep::Reveal, MessageType::CoinReveal, Role::A) => {
                    let r_a: [u8; 32] = frame
                        .frame()
                        .payload()
                        .try_into()
                        .expect("payload length checked structurally");
                    let commitment = cp.coin_commit.as_ref().expect("commitment received");
                    if !coin::verify_reveal(&self.sid, commitment, &r_a) {
                        return Err(attributable(frame, Violation::BadCoinReveal));
                    }
                    let first_mover =
                        coin::first_mover(&self.sid, &r_a, cp.r_b.as_ref().expect("nonce received"));
                    let game = build_game(
                        self.params,
                        self.local_role,
                        first_mover,
                        &mut cp.own,
                        &mut cp.peer_verified,
                    )?;
                    cp.game = Some(game);
                    advance_chain(&mut self.head, &mut self.transcript, &frame);
                    transition = Some(Transition::ToPlaying);
                    Ok(AcceptOutcome::GameReady { first_mover })
                }
                _ => Err(attributable(
                    frame,
                    Violation::UnexpectedMessage { message_type },
                )),
            },
            Phase::Playing(game) => match message_type {
                MessageType::Shot => {
                    let expected = matches!(game.state(), GameState::AwaitingShot { shooter } if shooter == sender);
                    if !expected {
                        return Err(attributable(
                            frame,
                            Violation::UnexpectedMessage { message_type },
                        ));
                    }
                    let cell_byte = frame.frame().payload()[0];
                    if let Err(e) = game.receive_shot(cell_byte) {
                        return Err(attributable(frame, Violation::InvalidShot(e)));
                    }
                    let cell = CellIndex::from_index(cell_byte).expect("accepted shot is in range");
                    let answer = game
                        .answer_shot()
                        .map_err(|_| SessionError::InternalInvariant("answer owed but not producible"))?;
                    // Conceding the T-th hit finishes the defender here; the Answer is the final frame.
                    let winner = match game.state() {
                        GameState::Finished { winner } => Some(winner),
                        _ => None,
                    };
                    advance_chain(&mut self.head, &mut self.transcript, &frame);
                    let answer_frame = craft_next(
                        self.keypair,
                        &self.sid,
                        self.local_role,
                        &mut self.head,
                        &mut self.transcript,
                        MessageType::Answer,
                        answer.encode(),
                    );
                    if let Some(winner) = winner {
                        transition = Some(Transition::Finished { winner });
                    }
                    Ok(AcceptOutcome::ShotReceived {
                        cell,
                        hit: answer.is_hit(),
                        answer: answer_frame,
                        winner,
                    })
                }
                MessageType::Answer => {
                    let expected = matches!(game.state(), GameState::AwaitingAnswer { shooter, .. } if shooter == self.local_role);
                    if !expected {
                        return Err(attributable(
                            frame,
                            Violation::UnexpectedMessage { message_type },
                        ));
                    }
                    let decoded = match ShotAnswer::decode(frame.frame().payload()) {
                        Ok(a) => a,
                        Err(e) => {
                            return Err(attributable(frame, Violation::InvalidAnswerEncoding(e)))
                        }
                    };
                    match game.accept_answer(&decoded) {
                        Err(GameError::AnswerRejected(r)) => {
                            Err(attributable(frame, Violation::InvalidAnswer(r)))
                        }
                        Err(GameError::InternalInvariantFailure(m)) => {
                            Err(SessionError::InternalInvariant(m))
                        }
                        Err(_) => Err(SessionError::InternalInvariant("unexpected game error")),
                        Ok(ShotOutcome::Win) => {
                            advance_chain(&mut self.head, &mut self.transcript, &frame);
                            transition = Some(Transition::Finished {
                                winner: self.local_role,
                            });
                            Ok(AcceptOutcome::GameFinished {
                                winner: self.local_role,
                            })
                        }
                        Ok(outcome) => {
                            advance_chain(&mut self.head, &mut self.transcript, &frame);
                            Ok(AcceptOutcome::Answer(outcome))
                        }
                    }
                }
                _ => Err(attributable(
                    frame,
                    Violation::UnexpectedMessage { message_type },
                )),
            },
            Phase::Aborted => Err(SessionError::WrongLocalState("session has aborted")),
            Phase::Finished { .. } => Err(attributable(
                frame,
                Violation::UnexpectedMessage { message_type },
            )),
        };

        match transition {
            Some(Transition::ToCoin) => self.enter_coin_phase(),
            Some(Transition::ToPlaying) => self.enter_playing_phase(),
            Some(Transition::Finished { winner }) => self.finish(winner),
            None => {}
        }
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hello;
    use crate::identity::{ExpectedKey, IdentityKeypair, PeerAuthPolicy};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    const SID: [u8; 32] = [0x51; 32];
    const GENESIS: [u8; 32] = [0x6E; 32];

    fn rng(seed: u8) -> ChaCha20Rng {
        ChaCha20Rng::from_seed([seed; 32])
    }

    fn keypair(seed: u8) -> IdentityKeypair {
        IdentityKeypair::from_seed(&[seed; 32])
    }

    fn auth(key: &IdentityKeypair) -> AuthenticatedPeer {
        ExpectedKey::new(key.peer_key())
            .authenticate(&key.peer_key())
            .unwrap()
    }

    fn placement_a() -> Vec<u8> {
        let mut e = vec![0u8; P];
        e[0] = 1;
        e[134] = 1;
        e[292] = 1;
        e[460] = 1;
        e[643] = 1;
        e
    }

    fn placement_b() -> Vec<u8> {
        let mut e = vec![0u8; P];
        e[5] = 1;
        e[127] = 1;
        e[272] = 1;
        e[444] = 1;
        e[625] = 1;
        e
    }

    fn blinders(seed: u8) -> Vec<Scalar> {
        let mut rng = rng(seed);
        (0..P).map(|_| Scalar::random(&mut rng)).collect()
    }

    fn session<'b>(local: &'b IdentityKeypair, role: Role, peer: &IdentityKeypair) -> Session<'b> {
        let params = Parameters::standard_v1();
        Session::new(
            params,
            local,
            role,
            auth(peer),
            SID,
            GENESIS,
            placement_a(),
            blinders(0x01),
        )
        .unwrap()
    }

    #[test]
    fn new_rejects_bad_local_witness() {
        let params = Parameters::standard_v1();
        let ka = keypair(1);
        let kb = keypair(2);
        let mut e = placement_a();
        e[581] = 1; // two selected positions in block 4
        assert!(matches!(
            Session::new(params, &ka, Role::A, auth(&kb), SID, GENESIS, e, blinders(1)),
            Err(SessionError::LocalGame(GameError::IllegalPlacement(_)))
        ));
        assert!(matches!(
            Session::new(
                params,
                &ka,
                Role::A,
                auth(&kb),
                SID,
                GENESIS,
                placement_a(),
                blinders(1)[..P - 1].to_vec()
            ),
            Err(SessionError::LocalGame(GameError::WrongWitnessLength { .. }))
        ));
    }

    #[test]
    fn attributable_failure_aborts_and_cannot_be_corrected() {
        let ka = keypair(1);
        let kb = keypair(2);
        let mut sb = session(&kb, Role::B, &ka);
        let bad = SignedFrame::craft(&ka, &SID, Role::A, 1, MessageType::Shot, &GENESIS, vec![0]);
        assert!(matches!(sb.accept(bad.bytes()), Err(SessionError::Attributable(_))));
        assert!(sb.is_aborted());
        assert!(matches!(sb.phase, Phase::Aborted)); // OwnBoard was dropped.
        assert_eq!(sb.expected_sender(), None);
        assert_eq!(sb.head_sequence(), 0);
        assert!(sb.transcript().is_empty());
        let corrected = SignedFrame::craft(&ka, &SID, Role::A, 1, MessageType::Resign, &GENESIS, vec![]);
        assert!(matches!(sb.accept(corrected.bytes()), Err(SessionError::WrongLocalState(_))));
        assert!(sb.produce(&mut rng(1)).unwrap().is_none());
        assert!(matches!(sb.resign(), Err(SessionError::WrongLocalState(_))));
    }

    #[test]
    fn internal_prover_failure_drops_session_secrets() {
        let ka = keypair(1);
        let kb = keypair(2);
        let mut sa = session(&ka, Role::A, &kb);
        let Phase::Commit(cp) = &mut sa.phase else { unreachable!() };
        cp.own.e.as_mut().unwrap()[0] = 0;
        assert!(matches!(sa.produce(&mut rng(1)), Err(SessionError::InternalInvariant(_))));
        assert!(matches!(sa.phase, Phase::Aborted));
        assert_eq!(sa.expected_sender(), None);
        assert_eq!(sa.winner(), None);
        assert!(sa.produce(&mut rng(2)).unwrap().is_none());
    }

    #[test]
    fn local_abort_drops_secrets_without_attributing_timeout() {
        let ka = keypair(1);
        let kb = keypair(2);
        let mut sa = session(&ka, Role::A, &kb);
        sa.abort();
        assert!(matches!(sa.phase, Phase::Aborted));
        assert_eq!(sa.winner(), None);
        assert_eq!(sa.expected_sender(), None);
        assert_eq!(sa.head_sequence(), 0);
    }

    #[test]
    fn internal_game_handoff_failure_is_terminal_for_either_role() {
        let ka = keypair(1);
        let kb = keypair(2);
        for failing_role in [Role::A, Role::B] {
            let mut sa = session(&ka, Role::A, &kb);
            let mut sb = session(&kb, Role::B, &ka);
            let mut entropy = rng(12);
            let f = sa.produce(&mut entropy).unwrap().unwrap();
            sb.accept(f.bytes()).unwrap();
            let f = sb.produce(&mut entropy).unwrap().unwrap();
            sa.accept(f.bytes()).unwrap();
            let f = sa.produce(&mut entropy).unwrap().unwrap();
            sb.accept(f.bytes()).unwrap();
            let nonce = sb.produce(&mut entropy).unwrap().unwrap();
            let (failed, incoming) = match failing_role {
                Role::A => (&mut sa, nonce),
                Role::B => {
                    sa.accept(nonce.bytes()).unwrap();
                    let reveal = sa.produce(&mut entropy).unwrap().unwrap();
                    (&mut sb, reveal)
                }
            };
            let Phase::Coin(cp) = &mut failed.phase else { unreachable!() };
            // Corrupt the validated witness: the game handoff must fail terminally.
            cp.own.e.as_mut().unwrap()[0] = 0;
            let previous_head = *failed.head_hash();
            let previous_sequence = failed.head_sequence();
            assert!(matches!(
                failed.accept(incoming.bytes()),
                Err(SessionError::InternalInvariant("validated board could not initialize game"))
            ));
            assert!(matches!(failed.phase, Phase::Aborted));
            assert!(failed.game().is_none());
            assert_eq!(failed.expected_sender(), None);
            assert_eq!(failed.head_sequence(), previous_sequence);
            assert_eq!(*failed.head_hash(), previous_head);
            assert!(failed.produce(&mut entropy).unwrap().is_none());
            assert!(matches!(failed.accept(incoming.bytes()), Err(SessionError::WrongLocalState(_))));
            assert!(matches!(failed.resign(), Err(SessionError::WrongLocalState(_))));
        }
    }

    #[test]
    fn resignation_after_coin_nonce_finishes_retained_game() {
        let ka = keypair(1);
        let kb = keypair(2);
        let mut sa = session(&ka, Role::A, &kb);
        let mut sb = session(&kb, Role::B, &ka);
        let mut entropy = rng(12);
        let f = sa.produce(&mut entropy).unwrap().unwrap();
        sb.accept(f.bytes()).unwrap();
        let f = sb.produce(&mut entropy).unwrap().unwrap();
        sa.accept(f.bytes()).unwrap();
        let f = sa.produce(&mut entropy).unwrap().unwrap();
        sb.accept(f.bytes()).unwrap();
        let f = sb.produce(&mut entropy).unwrap().unwrap();
        sa.accept(f.bytes()).unwrap();
        assert!(matches!(sa.phase, Phase::Coin(_)));
        assert!(sa.game().is_some());
        let resignation = sa.resign().unwrap();
        sb.accept(resignation.bytes()).unwrap();
        assert_eq!(sa.game().unwrap().state(), GameState::Finished { winner: Role::B });
        assert_eq!(sa.head_hash(), sb.head_hash());
        assert_eq!(sa.winner(), Some(Role::B));
        assert_eq!(sb.winner(), Some(Role::B));
    }

    #[test]
    fn out_of_turn_resign_is_attributable() {
        let ka = keypair(1);
        let kb = keypair(2);
        // A owes the first commit, so a Resign from B is out of turn.
        let mut sa = session(&ka, Role::A, &kb);
        let frame = SignedFrame::craft(&kb, &SID, Role::B, 1, MessageType::Resign, &GENESIS, vec![]);
        match sa.accept(frame.bytes()) {
            Err(SessionError::Attributable(v)) => {
                assert!(matches!(v.violation, Violation::OutOfTurnResign));
                assert_eq!(v.frame.bytes(), frame.bytes());
            }
            other => panic!("expected attributable violation, got {other:?}"),
        }
        let kb2 = keypair(3);
        let ka2 = keypair(4);
        let mut sb = session(&kb2, Role::B, &ka2);
        assert!(matches!(
            sb.resign(),
            Err(SessionError::WrongLocalState(_))
        ));
    }

    #[test]
    fn in_turn_resign_accepted_and_replay_is_class_b() {
        let ka = keypair(1);
        let kb = keypair(2);
        let mut sb = session(&kb, Role::B, &ka);
        let frame = SignedFrame::craft(&ka, &SID, Role::A, 1, MessageType::Resign, &GENESIS, vec![]);
        assert!(matches!(
            sb.accept(frame.bytes()),
            Ok(AcceptOutcome::PeerResigned)
        ));
        assert_eq!(sb.winner(), Some(Role::B));
        assert_eq!(sb.head_sequence(), 1);

        match sb.accept(frame.bytes()) {
            Err(SessionError::ClassB(ClassBReason::WrongSequence {
                expected: 2,
                actual: 1,
            })) => {}
            other => panic!("expected class-B wrong sequence, got {other:?}"),
        }
    }

    #[test]
    fn class_b_rejections() {
        let ka = keypair(1);
        let kb = keypair(2);
        let mut sb = session(&kb, Role::B, &ka);

        let frame = SignedFrame::craft(&ka, &[0xEE; 32], Role::A, 1, MessageType::Resign, &GENESIS, vec![]);
        assert!(matches!(
            sb.accept(frame.bytes()),
            Err(SessionError::ClassB(ClassBReason::WrongSession))
        ));
        let frame = SignedFrame::craft(&ka, &SID, Role::A, 5, MessageType::Resign, &GENESIS, vec![]);
        assert!(matches!(
            sb.accept(frame.bytes()),
            Err(SessionError::ClassB(ClassBReason::WrongSequence { .. }))
        ));
        let frame = SignedFrame::craft(&ka, &SID, Role::A, 1, MessageType::Resign, &[0xEE; 32], vec![]);
        assert!(matches!(
            sb.accept(frame.bytes()),
            Err(SessionError::ClassB(ClassBReason::WrongPrevHash))
        ));
        let stranger = keypair(9);
        let frame = SignedFrame::craft(&stranger, &SID, Role::A, 1, MessageType::Resign, &GENESIS, vec![]);
        assert!(matches!(
            sb.accept(frame.bytes()),
            Err(SessionError::ClassB(ClassBReason::BadSignature))
        ));
        assert!(matches!(
            sb.accept(&[0u8; 10]),
            Err(SessionError::ClassB(ClassBReason::Malformed(_)))
        ));
        assert!(!sb.is_aborted());
        assert_eq!(sb.expected_sender(), Some(Role::A));
        let next = SignedFrame::craft(&ka, &SID, Role::A, 1, MessageType::Resign, &GENESIS, vec![]);
        assert!(matches!(sb.accept(next.bytes()), Ok(AcceptOutcome::PeerResigned)));
    }

    #[test]
    fn attributable_content_violations() {
        let ka = keypair(1);
        let kb = keypair(2);

        let mut sb = session(&kb, Role::B, &ka);
        let payload = vec![0xFF; crate::codec::COMMIT_PAYLOAD_LEN];
        let frame = SignedFrame::craft(&ka, &SID, Role::A, 1, MessageType::Commit, &GENESIS, payload);
        match sb.accept(frame.bytes()) {
            Err(SessionError::Attributable(v)) => {
                assert!(matches!(v.violation, Violation::InvalidCommit(_)));
            }
            other => panic!("expected attributable invalid commit, got {other:?}"),
        }

        let mut sb = session(&kb, Role::B, &ka);
        let frame = SignedFrame::craft(&ka, &SID, Role::A, 1, MessageType::Shot, &GENESIS, vec![0]);
        match sb.accept(frame.bytes()) {
            Err(SessionError::Attributable(v)) => {
                assert!(matches!(v.violation, Violation::UnexpectedMessage { message_type: MessageType::Shot }));
            }
            other => panic!("expected attributable unexpected message, got {other:?}"),
        }

        let mut sb = session(&kb, Role::B, &ka);
        let frame = SignedFrame::craft(&ka, &SID, Role::B, 1, MessageType::Resign, &GENESIS, vec![]);
        match sb.accept(frame.bytes()) {
            Err(SessionError::Attributable(v)) => {
                assert!(matches!(v.violation, Violation::SenderRoleMismatch { .. }));
            }
            other => panic!("expected attributable sender-role mismatch, got {other:?}"),
        }
    }

    /// The single slow test: real proofs.
    #[test]
    fn full_session_between_two_players() {
        let params = Parameters::standard_v1();
        let params_id = *params.params_id();
        let ka = keypair(0x11);
        let kb = keypair(0x22);
        let mut rng = rng(0x99);

        let hello_a = hello::Hello::create(&ka, params_id, &mut rng);
        let hello_b = hello::Hello::create(&kb, params_id, &mut rng);
        let checked_a = hello::check_hello(hello_a, &params_id, &ExpectedKey::new(ka.peer_key())).unwrap();
        let checked_b = hello::check_hello(hello_b, &params_id, &ExpectedKey::new(kb.peer_key())).unwrap();
        let bootstrap = hello::complete_bootstrap(checked_a, checked_b).unwrap();
        let sid = *bootstrap.sid();
        let genesis = *bootstrap.genesis_hash();
        let role_of = |k: &IdentityKeypair| bootstrap.role_of(&k.peer_key());

        let session_a = Session::new(
            params,
            &ka,
            role_of(&ka),
            auth(&kb),
            sid,
            genesis,
            placement_a(),
            blinders(0xA0),
        )
        .unwrap();
        let session_b = Session::new(
            params,
            &kb,
            role_of(&kb),
            auth(&ka),
            sid,
            genesis,
            placement_b(),
            blinders(0xB0),
        )
        .unwrap();
        let (mut s_a, mut s_b) = if role_of(&ka) == Role::A {
            (session_a, session_b)
        } else {
            (session_b, session_a)
        };

        let frame = s_a.produce(&mut rng).unwrap().unwrap();
        assert!(matches!(
            s_b.accept(frame.bytes()),
            Ok(AcceptOutcome::CommitVerified)
        ));
        let frame = s_b.produce(&mut rng).unwrap().unwrap();
        assert!(matches!(
            s_a.accept(frame.bytes()),
            Ok(AcceptOutcome::CommitVerified)
        ));

        let frame = s_a.produce(&mut rng).unwrap().unwrap(); // CoinCommit
        assert!(matches!(
            s_b.accept(frame.bytes()),
            Ok(AcceptOutcome::CoinProgress)
        ));
        let frame = s_b.produce(&mut rng).unwrap().unwrap(); // CoinNonce
        let first_mover = match s_a.accept(frame.bytes()).unwrap() {
            AcceptOutcome::GameReady { first_mover } => first_mover,
            other => panic!("expected GameReady, got {other:?}"),
        };
        let frame = s_a.produce(&mut rng).unwrap().unwrap(); // CoinReveal
        match s_b.accept(frame.bytes()).unwrap() {
            AcceptOutcome::GameReady { first_mover: fm_b } => assert_eq!(fm_b, first_mover),
            other => panic!("expected GameReady, got {other:?}"),
        }

        let mut current = first_mover;
        for _ in 0..6 {
            let (attacker, defender) = if current == Role::A {
                (&mut s_a, &mut s_b)
            } else {
                (&mut s_b, &mut s_a)
            };
            let cell = (0..100u8)
                .map(|i| CellIndex::from_index(i).unwrap())
                .find(|c| {
                    !attacker
                        .game()
                        .unwrap()
                        .shots_on_board(current.other())
                        .is_shot(*c)
                })
                .unwrap();
            let shot = attacker.fire_shot(cell).unwrap();
            let answer = match defender.accept(shot.bytes()).unwrap() {
                AcceptOutcome::ShotReceived {
                    answer,
                    cell: shot_cell,
                    winner: None,
                    ..
                } => {
                    assert_eq!(shot_cell, cell);
                    answer
                }
                other => panic!("expected ShotReceived, got {other:?}"),
            };
            match attacker.accept(answer.bytes()).unwrap() {
                AcceptOutcome::Answer(_) => {}
                other => panic!("expected Answer, got {other:?}"),
            }
            current = current.other();
        }

        assert_eq!(s_a.head_sequence(), s_b.head_sequence());
        assert_eq!(s_a.head_hash(), s_b.head_hash());
        assert_eq!(s_a.transcript().len(), s_b.transcript().len());

        let (resigner, other) = if current == Role::A {
            (&mut s_a, &mut s_b)
        } else {
            (&mut s_b, &mut s_a)
        };
        let frame = resigner.resign().unwrap();
        assert!(matches!(
            other.accept(frame.bytes()),
            Ok(AcceptOutcome::PeerResigned)
        ));
        assert_eq!(other.winner(), Some(current.other()));
        assert_eq!(resigner.winner(), Some(current.other()));
        assert_eq!(other.expected_sender(), None);
        assert_eq!(resigner.expected_sender(), None);
        assert!(other.game().is_some());
        assert!(resigner.game().is_some());
        assert_eq!(other.game().unwrap().state(), GameState::Finished { winner: current.other() });
        assert_eq!(resigner.game().unwrap().state(), GameState::Finished { winner: current.other() });
    }
}
