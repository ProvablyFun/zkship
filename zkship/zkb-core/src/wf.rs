//! Non-interactive parallel well-formedness proof Π_wf (paper Construction 4.1):
//! 860 bit instances (E_0..E_759 then C_0..C_99) and 5 Schnorr instances (D_k)
//! under one Fiat-Shamir challenge. C_i and D_k are always derived locally
//! from E, never accepted from the peer.
//!
//! Transcript, exact order: `Transcript::new(b"zkbattleship/reference/v1/wf")`,
//! `pp` = canonical parameter bytes, `prover-id`, `sid`, `E` (760 compressed
//! points), then `bit-ca`/`bit-cb` for j in 0..860, then `block-R` for k in
//! 0..5, then 64 challenge bytes under `x` reduced mod-order-wide.

use crate::params::{CellIndex, Parameters, PlacementError, K, N, P};
use crate::pedersen;
use crate::sigma::bit::{BitFirstMessage, BitProver, BitResponse};
use crate::sigma::schnorr::SchnorrProver;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimeMultiscalarMul;
use merlin::Transcript;
use rand_core::{CryptoRng, OsRng, RngCore};
use std::fmt;
use zeroize::Zeroizing;

pub const BIT_INSTANCES: usize = P + N;

const TRANSCRIPT_LABEL: &[u8] = b"zkbattleship/reference/v1/wf";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WfError {
    /// Illegal witness (paper Lemma 3.2); the prover refuses to run.
    IllegalPlacement(PlacementError),
    WrongWitnessLength {
        expected: usize,
        actual: usize,
    },
    WrongCommitmentCount {
        expected: usize,
        actual: usize,
    },
    WrongCommitmentBytes {
        expected: usize,
        actual: usize,
    },
    InvalidPointEncoding {
        index: usize,
    },
    WrongProofBytes {
        expected: usize,
        actual: usize,
    },
    NonCanonicalScalar {
        offset: usize,
    },
    VerificationFailed,
}

impl fmt::Display for WfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WfError::IllegalPlacement(e) => write!(f, "illegal placement witness: {e}"),
            WfError::WrongWitnessLength { expected, actual } => {
                write!(f, "blinder vector has length {actual}, expected {expected}")
            }
            WfError::WrongCommitmentCount { expected, actual } => {
                write!(f, "got {actual} entry commitments, expected {expected}")
            }
            WfError::WrongCommitmentBytes { expected, actual } => {
                write!(f, "entry commitment encoding is {actual} bytes, expected {expected}")
            }
            WfError::InvalidPointEncoding { index } => {
                write!(f, "entry commitment {index} is not a canonical Ristretto encoding")
            }
            WfError::WrongProofBytes { expected, actual } => {
                write!(f, "proof encoding is {actual} bytes, expected {expected}")
            }
            WfError::NonCanonicalScalar { offset } => {
                write!(f, "proof scalar at byte offset {offset} is not canonical")
            }
            WfError::VerificationFailed => write!(f, "well-formedness proof does not verify"),
        }
    }
}

impl std::error::Error for WfError {}

fn encode_scalars(scalars: &[Scalar]) -> Vec<u8> {
    // Reserve first: growth would leave unwiped copies of secret scalars.
    let mut bytes = Vec::with_capacity(32 * scalars.len());
    for scalar in scalars {
        bytes.extend_from_slice(scalar.as_bytes());
    }
    bytes
}

fn encode_points(points: &[RistrettoPoint]) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 * points.len());
    for point in points {
        out.extend_from_slice(point.compress().as_bytes());
    }
    out
}

/// Entry commitments E as received, before proof verification.
pub struct UnverifiedBoardCommitment {
    entry_commitments: Vec<RistrettoPoint>,
}

impl UnverifiedBoardCommitment {
    /// 760 * 32 = 24,320 bytes.
    pub const ENCODED_LEN: usize = 32 * P;

    pub fn from_points(points: Vec<RistrettoPoint>) -> Result<Self, WfError> {
        if points.len() != P {
            return Err(WfError::WrongCommitmentCount {
                expected: P,
                actual: points.len(),
            });
        }
        Ok(UnverifiedBoardCommitment {
            entry_commitments: points,
        })
    }

    /// Exact length; every chunk must be a canonical compressed Ristretto point.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WfError> {
        if bytes.len() != Self::ENCODED_LEN {
            return Err(WfError::WrongCommitmentBytes {
                expected: Self::ENCODED_LEN,
                actual: bytes.len(),
            });
        }
        let mut points = Vec::with_capacity(P);
        for (index, chunk) in bytes.chunks_exact(32).enumerate() {
            let point = CompressedRistretto::from_slice(chunk)
                .expect("chunks_exact(32) yields 32-byte chunks")
                .decompress()
                .ok_or(WfError::InvalidPointEncoding { index })?;
            points.push(point);
        }
        Ok(UnverifiedBoardCommitment {
            entry_commitments: points,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        encode_points(&self.entry_commitments)
    }

    pub fn entry_commitments(&self) -> &[RistrettoPoint] {
        &self.entry_commitments
    }
}

/// Board commitment whose proof verified under the session context. Caches
/// the C_i derived during verification for play-phase cell checks.
pub struct VerifiedBoardCommitment {
    entry_commitments: Vec<RistrettoPoint>,
    cell_commitments: [RistrettoPoint; N],
}

impl VerifiedBoardCommitment {
    pub fn entry_commitments(&self) -> &[RistrettoPoint] {
        &self.entry_commitments
    }

    pub fn cell_commitments(&self) -> &[RistrettoPoint; N] {
        &self.cell_commitments
    }
}

/// π_wf (paper Construction 4.1).
pub struct WfProof {
    pub x: Scalar,
    /// 860 triples, instance order E_0..E_759 then C_0..C_99.
    pub bit_responses: Vec<BitResponse>,
    pub schnorr_responses: Vec<Scalar>,
}

impl WfProof {
    /// 32 + 860 * 96 + 5 * 32 = 82,752 bytes.
    pub const ENCODED_LEN: usize = 32 + 96 * BIT_INSTANCES + 32 * K;

    /// `x || (f, z_a, z_b) * 860 || z_k * 5`, all canonical 32-byte scalars.
    pub fn encode(&self) -> Vec<u8> {
        assert_eq!(self.bit_responses.len(), BIT_INSTANCES);
        assert_eq!(self.schnorr_responses.len(), K);
        let mut out = Vec::with_capacity(Self::ENCODED_LEN);
        out.extend_from_slice(&self.x.to_bytes());
        for r in &self.bit_responses {
            out.extend_from_slice(&r.f.to_bytes());
            out.extend_from_slice(&r.z_a.to_bytes());
            out.extend_from_slice(&r.z_b.to_bytes());
        }
        out.extend_from_slice(&encode_scalars(&self.schnorr_responses));
        out
    }

    /// Exact length; every scalar must be canonical.
    pub fn decode(bytes: &[u8]) -> Result<Self, WfError> {
        if bytes.len() != Self::ENCODED_LEN {
            return Err(WfError::WrongProofBytes {
                expected: Self::ENCODED_LEN,
                actual: bytes.len(),
            });
        }
        let scalar_at = |offset: usize| -> Result<Scalar, WfError> {
            let chunk: [u8; 32] = bytes[offset..offset + 32]
                .try_into()
                .expect("offset within checked length");
            Option::from(Scalar::from_canonical_bytes(chunk))
                .ok_or(WfError::NonCanonicalScalar { offset })
        };
        let x = scalar_at(0)?;
        let mut bit_responses = Vec::with_capacity(BIT_INSTANCES);
        for j in 0..BIT_INSTANCES {
            let base = 32 + 96 * j;
            bit_responses.push(BitResponse {
                f: scalar_at(base)?,
                z_a: scalar_at(base + 32)?,
                z_b: scalar_at(base + 64)?,
            });
        }
        let mut schnorr_responses = Vec::with_capacity(K);
        for k in 0..K {
            schnorr_responses.push(scalar_at(32 + 96 * BIT_INSTANCES + 32 * k)?);
        }
        Ok(WfProof {
            x,
            bit_responses,
            schnorr_responses,
        })
    }
}

fn statement_transcript(
    params: &Parameters,
    prover_id: &[u8; 32],
    sid: &[u8; 32],
    entry_bytes: &[u8],
) -> Transcript {
    let mut transcript = Transcript::new(TRANSCRIPT_LABEL);
    transcript.append_message(b"pp", params.canonical_params_bytes());
    transcript.append_message(b"prover-id", prover_id);
    transcript.append_message(b"sid", sid);
    transcript.append_message(b"E", entry_bytes);
    transcript
}

fn append_first_messages(
    transcript: &mut Transcript,
    bit_firsts: &[BitFirstMessage],
    schnorr_firsts: &[RistrettoPoint],
) {
    for first in bit_firsts {
        transcript.append_message(b"bit-ca", first.c_a.compress().as_bytes());
        transcript.append_message(b"bit-cb", first.c_b.compress().as_bytes());
    }
    for r in schnorr_firsts {
        transcript.append_message(b"block-R", r.compress().as_bytes());
    }
}

fn challenge(transcript: &mut Transcript) -> Scalar {
    let mut x_bytes = [0u8; 64];
    transcript.challenge_bytes(b"x", &mut x_bytes);
    Scalar::from_bytes_mod_order_wide(&x_bytes)
}

/// Bit-instance openings: `(e_p, s_p)` for j < P; for j >= P the derived
/// cell opening summed over the public support of cell j - P.
fn cell_opening(geometry: &crate::params::Geometry, e: &[u8], s: &[Scalar], i: usize) -> (Scalar, Scalar) {
    let cell = CellIndex::from_index(i as u8).expect("i < N");
    let support = geometry.support_of_cell(cell);
    let b: u64 = support.iter().map(|&p| u64::from(e[p])).sum();
    let rho: Scalar = support.iter().map(|&p| s[p]).sum();
    (Scalar::from(b), rho)
}

/// Production prover; finalizes the hedged RNG with `OsRng`.
pub fn prove(
    params: &Parameters,
    prover_id: &[u8; 32],
    sid: &[u8; 32],
    e: &[u8],
    s: &[Scalar],
) -> Result<(UnverifiedBoardCommitment, WfProof), WfError> {
    prove_with_rng(params, prover_id, sid, e, s, OsRng)
}

/// Prover with injected finalization RNG so tests can pin proof bytes. Never
/// pass a deterministic RNG outside tests.
pub fn prove_with_rng<R: RngCore + CryptoRng>(
    params: &Parameters,
    prover_id: &[u8; 32],
    sid: &[u8; 32],
    e: &[u8],
    s: &[Scalar],
    mut finalize_rng: R,
) -> Result<(UnverifiedBoardCommitment, WfProof), WfError> {
    if s.len() != P {
        return Err(WfError::WrongWitnessLength {
            expected: P,
            actual: s.len(),
        });
    }
    params
        .geometry()
        .validate_placement(e)
        .map_err(WfError::IllegalPlacement)?;

    let board = UnverifiedBoardCommitment {
        entry_commitments: pedersen::commit_vector(params, e, s),
    };
    let entry_bytes = board.to_bytes();
    let mut transcript = statement_transcript(params, prover_id, sid, &entry_bytes);

    // Hedged nonces: Merlin RNG over the statement prefix, rekeyed with the
    // witness (`e`, `s`), finalized with external entropy. This makes the
    // proof's witness indistinguishability computational; the paper's perfect
    // WI (Theorem 5.7) assumes uniform independent nonces. `s_bytes` is a
    // second copy of the secret blinders; erase it once absorbed.
    let s_bytes = Zeroizing::new(encode_scalars(s));
    let mut proof_rng = transcript
        .build_rng()
        .rekey_with_witness_bytes(b"e", e)
        .rekey_with_witness_bytes(b"s", &s_bytes)
        .finalize(&mut finalize_rng);
    drop(s_bytes);

    let mut bit_provers = Zeroizing::new(Vec::with_capacity(BIT_INSTANCES));
    let mut bit_firsts = Vec::with_capacity(BIT_INSTANCES);
    for p in 0..P {
        let (prover, first) = BitProver::new(params, &Scalar::from(e[p]), &s[p], &mut proof_rng);
        bit_provers.push(prover);
        bit_firsts.push(first);
    }
    let geometry = params.geometry();
    for i in 0..N {
        let opening = Zeroizing::new(cell_opening(geometry, e, s, i));
        let (prover, first) = BitProver::new(params, &opening.0, &opening.1, &mut proof_rng);
        bit_provers.push(prover);
        bit_firsts.push(first);
    }

    let mut schnorr_provers = Zeroizing::new(Vec::with_capacity(K));
    let mut schnorr_firsts = Vec::with_capacity(K);
    for k in 0..K {
        let eps = Zeroizing::new(geometry.block_range(k).map(|p| s[p]).sum::<Scalar>());
        let (prover, first) = SchnorrProver::new(params, &eps, &mut proof_rng);
        schnorr_provers.push(prover);
        schnorr_firsts.push(first);
    }

    append_first_messages(&mut transcript, &bit_firsts, &schnorr_firsts);
    let x = challenge(&mut transcript);

    // Respond in place: moving states out of a Vec leaves nonce bytes in the
    // backing allocation even though the moved value zeroizes on drop.
    let bit_responses = bit_provers
        .iter_mut()
        .map(|prover| prover.respond_in_place(&x))
        .collect();
    let schnorr_responses = schnorr_provers
        .iter_mut()
        .map(|prover| prover.respond_in_place(&x))
        .collect();

    Ok((
        board,
        WfProof {
            x,
            bit_responses,
            schnorr_responses,
        },
    ))
}

/// Verifier (paper Construction 4.1). Variable-time multiscalar
/// multiplication is fine here: all inputs are public.
pub fn verify(
    params: &Parameters,
    prover_id: &[u8; 32],
    sid: &[u8; 32],
    board: &UnverifiedBoardCommitment,
    proof: &WfProof,
) -> Result<VerifiedBoardCommitment, WfError> {
    if proof.bit_responses.len() != BIT_INSTANCES || proof.schnorr_responses.len() != K {
        return Err(WfError::VerificationFailed);
    }
    let cell_commitments = pedersen::cell_commitments(params, board.entry_commitments());
    let block_sums = pedersen::block_sum_commitments(params, board.entry_commitments());

    let entry_bytes = board.to_bytes();
    let mut transcript = statement_transcript(params, prover_id, sid, &entry_bytes);

    let g = params.g();
    let h = params.h();
    let neg_x = -proof.x;
    for (j, r) in proof.bit_responses.iter().enumerate() {
        let x_j = if j < P {
            &board.entry_commitments()[j]
        } else {
            &cell_commitments[j - P]
        };
        let c_a = RistrettoPoint::vartime_multiscalar_mul([&r.f, &r.z_a, &neg_x], [g, h, x_j]);
        let f_minus_x = r.f - proof.x;
        let c_b = RistrettoPoint::vartime_multiscalar_mul([&r.z_b, &f_minus_x], [h, x_j]);
        transcript.append_message(b"bit-ca", c_a.compress().as_bytes());
        transcript.append_message(b"bit-cb", c_b.compress().as_bytes());
    }
    for (k, z_k) in proof.schnorr_responses.iter().enumerate() {
        let r_hat =
            RistrettoPoint::vartime_multiscalar_mul([z_k, &neg_x], [h, &block_sums[k]]);
        transcript.append_message(b"block-R", r_hat.compress().as_bytes());
    }

    if challenge(&mut transcript) != proof.x {
        return Err(WfError::VerificationFailed);
    }
    Ok(VerifiedBoardCommitment {
        entry_commitments: board.entry_commitments.clone(),
        cell_commitments,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use sha2::{Digest, Sha512_256};

    const PROVER_ID: [u8; 32] = [0xA1; 32];
    const SID: [u8; 32] = [0x5D; 32];

    fn rng(seed: u8) -> ChaCha20Rng {
        ChaCha20Rng::from_seed([seed; 32])
    }

    fn fixed_placement() -> Vec<u8> {
        let mut e = vec![0u8; P];
        e[0] = 1; // block 0, cells 0-4
        e[134] = 1; // block 1, cells 20-23
        e[292] = 1; // block 2, cells 40-42
        e[460] = 1; // block 3, cells 50-52
        e[643] = 1; // block 4, cells 70-71
        e
    }

    fn fixed_blinders() -> Vec<Scalar> {
        let mut rng = rng(0x42);
        (0..P).map(|_| Scalar::random(&mut rng)).collect()
    }

    fn random_legal_placement<R: Rng>(rng: &mut R, params: &Parameters) -> Vec<u8> {
        let geometry = params.geometry();
        loop {
            let mut e = vec![0u8; P];
            for k in 0..K {
                e[rng.gen_range(geometry.block_range(k))] = 1;
            }
            if geometry.is_legal_placement(&e) {
                return e;
            }
        }
    }

    #[test]
    fn deterministic_vector_is_pinned() {
        let params = Parameters::standard_v1();
        let e = fixed_placement();
        let s = fixed_blinders();
        let (board, proof) =
            prove_with_rng(params, &PROVER_ID, &SID, &e, &s, rng(0x77)).unwrap();

        // Digest of E || proof for this fixed witness, context, and RNG.
        let mut hasher = Sha512_256::new();
        hasher.update(board.to_bytes());
        hasher.update(proof.encode());
        let digest: [u8; 32] = hasher.finalize().into();
        assert_eq!(
            digest.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "6e3ef00a8bf9108596929e80f14530a83c1fd23842e417c42e83f9e767861a71"
        );
        assert_eq!(proof.encode().len(), WfProof::ENCODED_LEN);
        assert_eq!(board.to_bytes().len(), UnverifiedBoardCommitment::ENCODED_LEN);

        let decoded_proof = WfProof::decode(&proof.encode()).unwrap();
        assert_eq!(decoded_proof.encode(), proof.encode());
        let decoded_board = UnverifiedBoardCommitment::from_bytes(&board.to_bytes()).unwrap();
        assert_eq!(decoded_board.to_bytes(), board.to_bytes());

        verify(params, &PROVER_ID, &SID, &board, &proof).unwrap();
    }

    #[test]
    fn random_legal_placements_prove_and_verify() {
        let params = Parameters::standard_v1();
        let mut chacha = rng(0x11);
        for round in 0..2u8 {
            let e = random_legal_placement(&mut chacha, params);
            let s: Vec<Scalar> = (0..P).map(|_| Scalar::random(&mut chacha)).collect();
            let (board, proof) =
                prove_with_rng(params, &PROVER_ID, &SID, &e, &s, rng(0x20 + round)).unwrap();
            let verified = verify(params, &PROVER_ID, &SID, &board, &proof).unwrap();
            assert_eq!(verified.entry_commitments(), board.entry_commitments());
            assert_eq!(
                verified.cell_commitments(),
                &pedersen::cell_commitments(params, board.entry_commitments())
            );
        }
    }

    // Adversarial prover: bypasses legality checks on purpose, accepts
    // arbitrary field entries, and can lie about a derived cell opening.
    fn adversarial_proof(
        e: &[Scalar],
        corrupted_cell: Option<usize>,
    ) -> (UnverifiedBoardCommitment, WfProof) {
        let params = Parameters::standard_v1();
        let geometry = params.geometry();
        let s = fixed_blinders();
        let board = UnverifiedBoardCommitment::from_points(
            e.iter().zip(&s).map(|(v, r)| pedersen::commit(params, v, r)).collect(),
        ).unwrap();
        let mut transcript = statement_transcript(params, &PROVER_ID, &SID, &board.to_bytes());
        let mut random = rng(0x95);
        let mut bit_states = Vec::new();
        for j in 0..BIT_INSTANCES {
            let (mut v, r) = if j < P {
                (e[j], s[j])
            } else {
                let cell = CellIndex::from_index((j - P) as u8).unwrap();
                let support = geometry.support_of_cell(cell);
                (support.iter().map(|&p| e[p]).sum::<Scalar>(),
                 support.iter().map(|&p| s[p]).sum::<Scalar>())
            };
            if j >= P && corrupted_cell == Some(j - P) {
                v = Scalar::ONE - v;
            }
            let (state, first) = BitProver::new(params, &v, &r, &mut random);
            transcript.append_message(b"bit-ca", first.c_a.compress().as_bytes());
            transcript.append_message(b"bit-cb", first.c_b.compress().as_bytes());
            bit_states.push(state);
        }
        let mut block_states = Vec::new();
        for k in 0..K {
            let eps = geometry.block_range(k).map(|p| s[p]).sum::<Scalar>();
            let (state, first) = SchnorrProver::new(params, &eps, &mut random);
            transcript.append_message(b"block-R", first.compress().as_bytes());
            block_states.push(state);
        }
        let x = challenge(&mut transcript);
        (board, WfProof {
            x,
            bit_responses: bit_states.into_iter().map(|state| state.respond(&x)).collect(),
            schnorr_responses: block_states.into_iter().map(|state| state.respond(&x)).collect(),
        })
    }

    #[test]
    fn verifier_rejects_adversarial_illegal_witness_proofs() {
        let params = Parameters::standard_v1();
        let legal: Vec<Scalar> = fixed_placement().into_iter().map(Scalar::from).collect();
        let (board, proof) = adversarial_proof(&legal, None);
        verify(params, &PROVER_ID, &SID, &board, &proof).unwrap();

        let mut overlap = legal.clone();
        overlap[460] = Scalar::ZERO;
        overlap[420] = Scalar::ONE;
        let mut empty_block = legal.clone();
        empty_block[0] = Scalar::ZERO;
        let mut two_positions = legal.clone();
        two_positions[589] = Scalar::ONE; // disjoint cells 10-11
        let mut nonbit_two = legal.clone();
        nonbit_two[7] = Scalar::from(2u64);
        let mut nonbit_minus_one = legal.clone();
        nonbit_minus_one[7] = -Scalar::ONE;
        for (name, witness) in [
            ("overlap", overlap),
            ("empty block", empty_block),
            ("two selected positions", two_positions),
            ("nonbit 2", nonbit_two),
            ("nonbit q-1", nonbit_minus_one),
        ] {
            let (board, proof) = adversarial_proof(&witness, None);
            assert!(matches!(verify(params, &PROVER_ID, &SID, &board, &proof),
                Err(WfError::VerificationFailed)), "accepted {name}");
        }
        let (board, proof) = adversarial_proof(&legal, Some(0));
        assert!(matches!(verify(params, &PROVER_ID, &SID, &board, &proof),
            Err(WfError::VerificationFailed)), "accepted a false derived-cell opening");
    }

    #[test]
    fn prover_refuses_illegal_witnesses() {
        let params = Parameters::standard_v1();
        let s = fixed_blinders();

        // Overlap: blocks 0 and 3 both cover cells 0-2.
        let mut e = fixed_placement();
        e[460] = 0;
        e[420] = 1;
        assert!(matches!(
            prove(params, &PROVER_ID, &SID, &e, &s),
            Err(WfError::IllegalPlacement(PlacementError::OverlappingShips { .. }))
        ));

        let e = vec![0u8; P];
        assert!(matches!(
            prove(params, &PROVER_ID, &SID, &e, &s),
            Err(WfError::IllegalPlacement(PlacementError::BlockNotOneHot { block: 0, sum: 0 }))
        ));

        let mut e = fixed_placement();
        e[581] = 1;
        assert!(matches!(
            prove(params, &PROVER_ID, &SID, &e, &s),
            Err(WfError::IllegalPlacement(PlacementError::BlockNotOneHot { block: 4, sum: 2 }))
        ));

        let mut e = fixed_placement();
        e[7] = 2;
        assert!(matches!(
            prove(params, &PROVER_ID, &SID, &e, &s),
            Err(WfError::IllegalPlacement(PlacementError::NonBitEntry { .. }))
        ));

        let e = fixed_placement();
        assert!(matches!(
            prove(params, &PROVER_ID, &SID, &e, &s[..P - 1]),
            Err(WfError::WrongWitnessLength { .. })
        ));
    }

    #[test]
    fn decode_rejects_structurally_bad_input_without_panicking() {
        let params = Parameters::standard_v1();
        let (board, proof) =
            prove_with_rng(params, &PROVER_ID, &SID, &fixed_placement(), &fixed_blinders(), rng(0x77))
                .unwrap();
        let proof_bytes = proof.encode();
        let board_bytes = board.to_bytes();

        assert!(matches!(
            WfProof::decode(&proof_bytes[..WfProof::ENCODED_LEN - 1]),
            Err(WfError::WrongProofBytes { .. })
        ));
        let mut long = proof_bytes.clone();
        long.push(0);
        assert!(matches!(
            WfProof::decode(&long),
            Err(WfError::WrongProofBytes { .. })
        ));

        // 0xff..ff >= q.
        let mut bad = proof_bytes.clone();
        for b in &mut bad[..32] {
            *b = 0xff;
        }
        assert!(matches!(
            WfProof::decode(&bad),
            Err(WfError::NonCanonicalScalar { offset: 0 })
        ));
        let mut bad = proof_bytes.clone();
        for b in &mut bad[32..64] {
            *b = 0xff;
        }
        assert!(matches!(
            WfProof::decode(&bad),
            Err(WfError::NonCanonicalScalar { offset: 32 })
        ));

        assert!(matches!(
            UnverifiedBoardCommitment::from_bytes(&board_bytes[..UnverifiedBoardCommitment::ENCODED_LEN - 1]),
            Err(WfError::WrongCommitmentBytes { .. })
        ));
        let mut long = board_bytes.clone();
        long.push(0);
        assert!(matches!(
            UnverifiedBoardCommitment::from_bytes(&long),
            Err(WfError::WrongCommitmentBytes { .. })
        ));

        // 0xff..ff is not a canonical field element.
        let mut bad = board_bytes.clone();
        for b in &mut bad[64..96] {
            *b = 0xff;
        }
        assert!(matches!(
            UnverifiedBoardCommitment::from_bytes(&bad),
            Err(WfError::InvalidPointEncoding { index: 2 })
        ));
    }

    #[test]
    fn tampered_proofs_and_contexts_are_rejected() {
        let params = Parameters::standard_v1();
        let (board, proof) =
            prove_with_rng(params, &PROVER_ID, &SID, &fixed_placement(), &fixed_blinders(), rng(0x77))
                .unwrap();

        let reject = |board: &UnverifiedBoardCommitment, proof: &WfProof, id: &[u8; 32], sid: &[u8; 32]| {
            assert!(matches!(
                verify(params, id, sid, board, proof),
                Err(WfError::VerificationFailed)
            ));
        };

        let mut p = WfProof::decode(&proof.encode()).unwrap();
        p.x += Scalar::ONE;
        reject(&board, &p, &PROVER_ID, &SID);

        let mut p = WfProof::decode(&proof.encode()).unwrap();
        p.bit_responses[0].f += Scalar::ONE;
        reject(&board, &p, &PROVER_ID, &SID);
        let mut p = WfProof::decode(&proof.encode()).unwrap();
        p.bit_responses[500].z_b += Scalar::ONE;
        reject(&board, &p, &PROVER_ID, &SID);

        let mut p = WfProof::decode(&proof.encode()).unwrap();
        p.bit_responses.swap(0, 1);
        reject(&board, &p, &PROVER_ID, &SID);

        let mut p = WfProof::decode(&proof.encode()).unwrap();
        p.schnorr_responses[2] += Scalar::ONE;
        reject(&board, &p, &PROVER_ID, &SID);

        reject(&board, &proof, &PROVER_ID, &[0xEE; 32]);
        reject(&board, &proof, &[0xEE; 32], &SID);

        let (board2, _) = prove_with_rng(
            params,
            &PROVER_ID,
            &SID,
            &random_legal_placement(&mut rng(0x33), params),
            &fixed_blinders(),
            rng(0x44),
        )
        .unwrap();
        reject(&board2, &proof, &PROVER_ID, &SID);
    }
}
