//! Semantic shot and sunk openings (paper §3.3, Construction 4.2). Only the
//! game functionals of Definition 3.4 are ever opened: M_i for the shot cell
//! and, on a hit, w_{l,S} for lengths (5, 4, 3, 2). Weight vectors come from
//! public geometry and the public shot set only, never from secret positions.
//! `b` and `tau` are u8 on the wire (the paper writes them as field elements)
//! and are lifted to scalars only for the group equations.

use crate::params::{CellIndex, Geometry, Parameters, DISTINCT_LENGTHS, N, P};
use crate::pedersen;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use std::fmt;

pub const SUNK_REPORT_SIZE: usize = DISTINCT_LENGTHS.len();

/// `(tau_l, theta_l)` (paper §3.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SunkOpening {
    pub tau: u8,
    pub theta: Scalar,
}

/// Wire: `b = 0` -> 33 bytes `b || rho`; `b = 1` -> 165 bytes
/// `b || rho || 4 * (tau u8 || theta)`, lengths (5, 4, 3, 2) in that order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShotAnswer {
    Miss {
        rho: Scalar,
    },
    Hit {
        rho: Scalar,
        sunk: [SunkOpening; SUNK_REPORT_SIZE],
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnswerDecodeError {
    WrongLength { expected: usize, actual: usize },
    InvalidAnswerFlag(u8),
    NonCanonicalScalar { offset: usize },
}

impl fmt::Display for AnswerDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AnswerDecodeError::WrongLength { expected, actual } => {
                write!(f, "answer encoding is {actual} bytes, expected {expected}")
            }
            AnswerDecodeError::InvalidAnswerFlag(b) => {
                write!(f, "answer flag b = {b}, expected 0 or 1")
            }
            AnswerDecodeError::NonCanonicalScalar { offset } => {
                write!(f, "answer scalar at byte offset {offset} is not canonical")
            }
        }
    }
}

impl std::error::Error for AnswerDecodeError {}

impl ShotAnswer {
    pub const MISS_LEN: usize = 33;
    pub const HIT_LEN: usize = 33 + SUNK_REPORT_SIZE * 33;

    pub fn is_hit(&self) -> bool {
        matches!(self, ShotAnswer::Hit { .. })
    }

    pub fn encode(&self) -> Vec<u8> {
        match self {
            ShotAnswer::Miss { rho } => {
                let mut out = Vec::with_capacity(Self::MISS_LEN);
                out.push(0);
                out.extend_from_slice(&rho.to_bytes());
                out
            }
            ShotAnswer::Hit { rho, sunk } => {
                let mut out = Vec::with_capacity(Self::HIT_LEN);
                out.push(1);
                out.extend_from_slice(&rho.to_bytes());
                for opening in sunk {
                    out.push(opening.tau);
                    out.extend_from_slice(&opening.theta.to_bytes());
                }
                out
            }
        }
    }

    /// `b` determines the required exact length; scalars must be canonical.
    pub fn decode(bytes: &[u8]) -> Result<ShotAnswer, AnswerDecodeError> {
        let Some((&flag, _)) = bytes.split_first() else {
            return Err(AnswerDecodeError::WrongLength {
                expected: Self::MISS_LEN,
                actual: 0,
            });
        };
        let scalar_at = |offset: usize| -> Result<Scalar, AnswerDecodeError> {
            let chunk: [u8; 32] = bytes[offset..offset + 32]
                .try_into()
                .expect("offset within checked length");
            Option::from(Scalar::from_canonical_bytes(chunk))
                .ok_or(AnswerDecodeError::NonCanonicalScalar { offset })
        };
        match flag {
            0 => {
                if bytes.len() != Self::MISS_LEN {
                    return Err(AnswerDecodeError::WrongLength {
                        expected: Self::MISS_LEN,
                        actual: bytes.len(),
                    });
                }
                Ok(ShotAnswer::Miss { rho: scalar_at(1)? })
            }
            1 => {
                if bytes.len() != Self::HIT_LEN {
                    return Err(AnswerDecodeError::WrongLength {
                        expected: Self::HIT_LEN,
                        actual: bytes.len(),
                    });
                }
                let rho = scalar_at(1)?;
                let mut sunk = Vec::with_capacity(SUNK_REPORT_SIZE);
                for i in 0..SUNK_REPORT_SIZE {
                    let tau = bytes[33 + 33 * i];
                    let theta = scalar_at(34 + 33 * i)?;
                    sunk.push(SunkOpening { tau, theta });
                }
                let sunk: [SunkOpening; SUNK_REPORT_SIZE] =
                    sunk.try_into().expect("exactly SUNK_REPORT_SIZE openings");
                Ok(ShotAnswer::Hit { rho, sunk })
            }
            other => Err(AnswerDecodeError::InvalidAnswerFlag(other)),
        }
    }
}

/// Positions of length-`length` ships lying entirely inside the public shot
/// set (support of w_{l,S}, paper §3.3). Diagnostic; play maintains this
/// incrementally in `game::BoardShots`.
pub fn sunk_positions(geometry: &Geometry, length: u8, is_shot: &[bool; N]) -> Vec<usize> {
    let mut out = Vec::new();
    for block in 0..geometry.k() {
        if geometry.ship_length_of_block(block) != length {
            continue;
        }
        for p in geometry.block_range(block) {
            if geometry
                .cells_of_position(p)
                .iter()
                .all(|cell| is_shot[cell.index() as usize])
            {
                out.push(p);
            }
        }
    }
    out
}

/// Honest answer to a shot at `cell`. The cell must already be in the public
/// shot set; sunk openings come from the caller's incrementally maintained
/// running sums. Loop structure depends on public indices only.
pub fn answer_shot(
    params: &Parameters,
    cell: CellIndex,
    e: &[u8],
    s: &[Scalar],
    sunk_counts: &[u8; SUNK_REPORT_SIZE],
    sunk_blinders: &[Scalar; SUNK_REPORT_SIZE],
) -> ShotAnswer {
    debug_assert_eq!(e.len(), P);
    debug_assert_eq!(s.len(), P);
    let support = params.geometry().support_of_cell(cell);
    let b: u8 = support.iter().map(|&p| e[p]).sum();
    debug_assert!(b <= 1, "legal placement covers a cell at most once");
    let rho: Scalar = support.iter().map(|&p| s[p]).sum();
    match b {
        0 => ShotAnswer::Miss { rho },
        _ => ShotAnswer::Hit {
            rho,
            sunk: std::array::from_fn(|i| SunkOpening {
                tau: sunk_counts[i],
                theta: sunk_blinders[i],
            }),
        },
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnswerOutcome {
    pub hit: bool,
    /// Cumulative, wire order (5, 4, 3, 2); unchanged on a miss.
    pub sunk_counts: [u8; SUNK_REPORT_SIZE],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnswerRejection {
    /// `C_i != b*G + rho*H`.
    CellOpeningFailed,
    SunkOpeningFailed {
        length: u8,
    },
    TauExceedsFleetCount {
        length: u8,
        tau: u8,
        max: u8,
    },
    SunkCountDecreased {
        length: u8,
        previous: u8,
        current: u8,
    },
    TooManyNewlySunk {
        newly_sunk: u8,
    },
    SunkCellsExceedHits {
        sunk_cells: u64,
        hits: u64,
    },
}

impl fmt::Display for AnswerRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AnswerRejection::CellOpeningFailed => {
                write!(f, "hit/miss opening does not match the cell commitment")
            }
            AnswerRejection::SunkOpeningFailed { length } => {
                write!(
                    f,
                    "sunk opening for length {length} does not match the commitment sum"
                )
            }
            AnswerRejection::TauExceedsFleetCount { length, tau, max } => {
                write!(f, "tau_{length} = {tau} exceeds the fleet count {max}")
            }
            AnswerRejection::SunkCountDecreased {
                length,
                previous,
                current,
            } => {
                write!(f, "tau_{length} decreased from {previous} to {current}")
            }
            AnswerRejection::TooManyNewlySunk { newly_sunk } => {
                write!(f, "answer claims {newly_sunk} newly sunk ships on one hit")
            }
            AnswerRejection::SunkCellsExceedHits { sunk_cells, hits } => {
                write!(
                    f,
                    "claimed {sunk_cells} sunk cells exceed {hits} verified hit cells"
                )
            }
        }
    }
}

impl std::error::Error for AnswerRejection {}

/// `cell_commitment` is the cached C_i from proof verification;
/// `sunk_commitments` are the public sums S_l = sum_{p in W_{l,S}} E_p after
/// registering this shot. The semantic checks after the group equations
/// (fleet bound, monotone tau, <= 1 newly sunk per hit, sunk cells <= verified
/// hits) are hardening, not assumptions of the binding theorem (5.4).
pub fn verify_answer(
    params: &Parameters,
    cell_commitment: &RistrettoPoint,
    sunk_commitments: &[RistrettoPoint; SUNK_REPORT_SIZE],
    previous_sunk_counts: &[u8; SUNK_REPORT_SIZE],
    verified_hits_so_far: u8,
    answer: &ShotAnswer,
) -> Result<AnswerOutcome, AnswerRejection> {
    let geometry = params.geometry();
    match answer {
        ShotAnswer::Miss { rho } => {
            if *cell_commitment != pedersen::commit(params, &Scalar::ZERO, rho) {
                return Err(AnswerRejection::CellOpeningFailed);
            }
            Ok(AnswerOutcome {
                hit: false,
                sunk_counts: *previous_sunk_counts,
            })
        }
        ShotAnswer::Hit { rho, sunk } => {
            if *cell_commitment != pedersen::commit(params, &Scalar::ONE, rho) {
                return Err(AnswerRejection::CellOpeningFailed);
            }
            for (i, opening) in sunk.iter().enumerate() {
                let expected = pedersen::commit(params, &Scalar::from(opening.tau), &opening.theta);
                if sunk_commitments[i] != expected {
                    return Err(AnswerRejection::SunkOpeningFailed {
                        length: DISTINCT_LENGTHS[i],
                    });
                }
            }

            let mut new_counts = [0u8; SUNK_REPORT_SIZE];
            for (i, opening) in sunk.iter().enumerate() {
                let length = DISTINCT_LENGTHS[i];
                let max = geometry.ship_count_of_length(length);
                if opening.tau > max {
                    return Err(AnswerRejection::TauExceedsFleetCount {
                        length,
                        tau: opening.tau,
                        max,
                    });
                }
                if opening.tau < previous_sunk_counts[i] {
                    return Err(AnswerRejection::SunkCountDecreased {
                        length,
                        previous: previous_sunk_counts[i],
                        current: opening.tau,
                    });
                }
                new_counts[i] = opening.tau;
            }
            let newly_sunk: u8 =
                new_counts.iter().sum::<u8>() - previous_sunk_counts.iter().sum::<u8>();
            if newly_sunk > 1 {
                return Err(AnswerRejection::TooManyNewlySunk { newly_sunk });
            }
            let sunk_cells: u64 = (0..SUNK_REPORT_SIZE)
                .map(|i| u64::from(DISTINCT_LENGTHS[i]) * u64::from(new_counts[i]))
                .sum();
            let hits = u64::from(verified_hits_so_far) + 1;
            if sunk_cells > hits {
                return Err(AnswerRejection::SunkCellsExceedHits { sunk_cells, hits });
            }

            Ok(AnswerOutcome {
                hit: true,
                sunk_counts: new_counts,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use sha2::Sha512;

    fn test_params() -> Parameters {
        let h = RistrettoPoint::hash_from_bytes::<Sha512>(b"zkbattleship/test-only/openings-H");
        Parameters::from_test_generators(RISTRETTO_BASEPOINT_POINT, h)
    }

    fn scalar(byte: u8) -> Scalar {
        Scalar::from(byte as u64)
    }

    fn hit_answer(
        taus: [u8; SUNK_REPORT_SIZE],
    ) -> (ShotAnswer, Scalar, [Scalar; SUNK_REPORT_SIZE]) {
        let rho = scalar(9);
        let thetas: [Scalar; SUNK_REPORT_SIZE] = std::array::from_fn(|i| scalar(20 + i as u8));
        let sunk: [SunkOpening; SUNK_REPORT_SIZE] = std::array::from_fn(|i| SunkOpening {
            tau: taus[i],
            theta: thetas[i],
        });
        (ShotAnswer::Hit { rho, sunk }, rho, thetas)
    }

    fn sunk_commitments_for(
        params: &Parameters,
        taus: [u8; SUNK_REPORT_SIZE],
        thetas: &[Scalar; SUNK_REPORT_SIZE],
    ) -> [RistrettoPoint; SUNK_REPORT_SIZE] {
        std::array::from_fn(|i| pedersen::commit(params, &Scalar::from(taus[i]), &thetas[i]))
    }

    #[test]
    fn codec_roundtrips() {
        let miss = ShotAnswer::Miss { rho: scalar(7) };
        let bytes = miss.encode();
        assert_eq!(bytes.len(), ShotAnswer::MISS_LEN);
        assert!(
            matches!(ShotAnswer::decode(&bytes), Ok(ShotAnswer::Miss { rho }) if rho == scalar(7))
        );

        let (hit, _, _) = hit_answer([1, 0, 2, 1]);
        let bytes = hit.encode();
        assert_eq!(bytes.len(), ShotAnswer::HIT_LEN);
        match ShotAnswer::decode(&bytes).unwrap() {
            ShotAnswer::Hit { rho, sunk } => {
                assert_eq!(rho, scalar(9));
                for (i, opening) in sunk.iter().enumerate() {
                    assert_eq!(opening.tau, [1, 0, 2, 1][i]);
                    assert_eq!(opening.theta, scalar(20 + i as u8));
                }
            }
            ShotAnswer::Miss { .. } => panic!("expected hit"),
        }
    }

    #[test]
    fn codec_rejects_bad_input_without_panicking() {
        let (hit, _, _) = hit_answer([0, 0, 0, 0]);
        let hit_bytes = hit.encode();
        let miss_bytes = ShotAnswer::Miss { rho: scalar(1) }.encode();

        assert_eq!(
            ShotAnswer::decode(&[]),
            Err(AnswerDecodeError::WrongLength {
                expected: ShotAnswer::MISS_LEN,
                actual: 0
            })
        );
        let mut bad = miss_bytes.clone();
        bad[0] = 2;
        assert_eq!(
            ShotAnswer::decode(&bad),
            Err(AnswerDecodeError::InvalidAnswerFlag(2))
        );
        let mut long = miss_bytes.clone();
        long.push(0);
        assert!(matches!(
            ShotAnswer::decode(&long),
            Err(AnswerDecodeError::WrongLength { .. })
        ));
        assert!(matches!(
            ShotAnswer::decode(&miss_bytes[..ShotAnswer::MISS_LEN - 1]),
            Err(AnswerDecodeError::WrongLength { .. })
        ));
        assert!(matches!(
            ShotAnswer::decode(&hit_bytes[..ShotAnswer::HIT_LEN - 1]),
            Err(AnswerDecodeError::WrongLength { .. })
        ));
        // 0xff..ff >= q.
        let mut bad = miss_bytes.clone();
        for b in &mut bad[1..33] {
            *b = 0xff;
        }
        assert_eq!(
            ShotAnswer::decode(&bad),
            Err(AnswerDecodeError::NonCanonicalScalar { offset: 1 })
        );
        let mut bad = hit_bytes.clone();
        for b in &mut bad[34..66] {
            *b = 0xff;
        }
        assert_eq!(
            ShotAnswer::decode(&bad),
            Err(AnswerDecodeError::NonCanonicalScalar { offset: 34 })
        );
    }

    #[test]
    fn honest_hit_and_miss_answers_verify() {
        let params = test_params();
        let rho = scalar(3);
        let c = pedersen::commit(&params, &Scalar::ZERO, &rho);
        let sunk = [RistrettoPoint::default(); SUNK_REPORT_SIZE];
        let answer = ShotAnswer::Miss { rho };
        let outcome =
            verify_answer(&params, &c, &sunk, &[0; SUNK_REPORT_SIZE], 0, &answer).unwrap();
        assert!(!outcome.hit);

        let taus = [0, 0, 1, 0];
        let (answer, rho, thetas) = hit_answer(taus);
        let c = pedersen::commit(&params, &Scalar::ONE, &rho);
        let sunk = sunk_commitments_for(&params, taus, &thetas);
        let outcome =
            verify_answer(&params, &c, &sunk, &[0; SUNK_REPORT_SIZE], 5, &answer).unwrap();
        assert!(outcome.hit);
        assert_eq!(outcome.sunk_counts, taus);
    }

    #[test]
    fn wrong_rho_or_replayed_answer_fails_cell_opening() {
        let params = test_params();
        let rho = scalar(4);
        let c_i = pedersen::commit(&params, &Scalar::ONE, &rho);
        let c_j = pedersen::commit(&params, &Scalar::ZERO, &rho);
        let sunk = [RistrettoPoint::default(); SUNK_REPORT_SIZE];

        // Miss answer on a hit cell.
        let answer = ShotAnswer::Miss { rho };
        assert_eq!(
            verify_answer(&params, &c_i, &sunk, &[0; SUNK_REPORT_SIZE], 0, &answer),
            Err(AnswerRejection::CellOpeningFailed)
        );
        // Cell-i answer replayed for cell j; then wrong rho.
        let answer = ShotAnswer::Hit {
            rho,
            sunk: std::array::from_fn(|_| SunkOpening {
                tau: 0,
                theta: Scalar::ZERO,
            }),
        };
        assert_eq!(
            verify_answer(&params, &c_j, &sunk, &[0; SUNK_REPORT_SIZE], 0, &answer),
            Err(AnswerRejection::CellOpeningFailed)
        );
        let answer = ShotAnswer::Miss {
            rho: rho + Scalar::ONE,
        };
        assert_eq!(
            verify_answer(&params, &c_j, &sunk, &[0; SUNK_REPORT_SIZE], 0, &answer),
            Err(AnswerRejection::CellOpeningFailed)
        );
    }

    #[test]
    fn tampered_tau_or_theta_fails_sunk_opening() {
        let params = test_params();
        let taus = [0, 1, 1, 0];
        let (answer, rho, thetas) = hit_answer(taus);
        let c = pedersen::commit(&params, &Scalar::ONE, &rho);
        let sunk = sunk_commitments_for(&params, taus, &thetas);

        let mut bad = answer.clone();
        if let ShotAnswer::Hit { sunk, .. } = &mut bad {
            sunk[1].tau += 1;
        }
        assert_eq!(
            verify_answer(&params, &c, &sunk, &[0; SUNK_REPORT_SIZE], 9, &bad),
            Err(AnswerRejection::SunkOpeningFailed { length: 4 })
        );

        let mut bad = answer.clone();
        if let ShotAnswer::Hit { sunk, .. } = &mut bad {
            sunk[0].theta += Scalar::ONE;
        }
        assert_eq!(
            verify_answer(&params, &c, &sunk, &[0; SUNK_REPORT_SIZE], 9, &bad),
            Err(AnswerRejection::SunkOpeningFailed { length: 5 })
        );
    }

    #[test]
    fn defensive_semantic_checks() {
        let params = test_params();
        let c = pedersen::commit(&params, &Scalar::ONE, &scalar(9));

        // S_3 is built to match, so only the semantic check can reject.
        let taus = [0, 0, 3, 0];
        let (answer, _, thetas) = hit_answer(taus);
        let sunk = sunk_commitments_for(&params, taus, &thetas);
        assert_eq!(
            verify_answer(&params, &c, &sunk, &[0; SUNK_REPORT_SIZE], 16, &answer),
            Err(AnswerRejection::TauExceedsFleetCount {
                length: 3,
                tau: 3,
                max: 2
            })
        );

        let taus = [0, 0, 0, 0];
        let (answer, _, thetas) = hit_answer(taus);
        let sunk = sunk_commitments_for(&params, taus, &thetas);
        assert_eq!(
            verify_answer(&params, &c, &sunk, &[0, 0, 1, 0], 16, &answer),
            Err(AnswerRejection::SunkCountDecreased {
                length: 3,
                previous: 1,
                current: 0
            })
        );

        let taus = [1, 1, 0, 0];
        let (answer, _, thetas) = hit_answer(taus);
        let sunk = sunk_commitments_for(&params, taus, &thetas);
        assert_eq!(
            verify_answer(&params, &c, &sunk, &[0; SUNK_REPORT_SIZE], 10, &answer),
            Err(AnswerRejection::TooManyNewlySunk { newly_sunk: 2 })
        );

        let taus = [1, 0, 0, 0];
        let (answer, _, thetas) = hit_answer(taus);
        let sunk = sunk_commitments_for(&params, taus, &thetas);
        assert_eq!(
            verify_answer(&params, &c, &sunk, &[0; SUNK_REPORT_SIZE], 1, &answer),
            Err(AnswerRejection::SunkCellsExceedHits {
                sunk_cells: 5,
                hits: 2
            })
        );
    }
}
