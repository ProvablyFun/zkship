//! Pedersen commitments (paper §2.2) in additive notation: `Com(v; r) = vG + rH`,
//! paper `g` = `G`, paper `h` = `H`. No public arbitrary linear-opening API by
//! design: peers only ever get the semantic openings in `openings`.

use crate::params::{CellIndex, Parameters, K, N, P};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimeMultiscalarMul;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

/// Constant-time.
pub fn commit(params: &Parameters, v: &Scalar, r: &Scalar) -> RistrettoPoint {
    v * params.g() + r * params.h()
}

/// `E_p = e_p*G + s_p*H`. Constant-time. Local prover-side API: panics on
/// bad shape; validate peer-influenced input with `Geometry::validate_placement`.
pub fn commit_vector(params: &Parameters, e: &[u8], s: &[Scalar]) -> Vec<RistrettoPoint> {
    assert_eq!(e.len(), P, "placement vector must have exactly P entries");
    assert_eq!(s.len(), P, "blinder vector must have exactly P entries");
    e.iter()
        .zip(s.iter())
        .map(|(&v, r)| {
            assert!(v <= 1, "placement entries must be bits");
            commit(params, &Scalar::from(v), r)
        })
        .collect()
}

/// `C_i = sum_{p in support_of_cell[i]} E_p` (paper Construction 4.1).
pub fn cell_commitments(
    params: &Parameters,
    entry_commitments: &[RistrettoPoint],
) -> [RistrettoPoint; N] {
    assert_eq!(entry_commitments.len(), P);
    let geometry = params.geometry();
    std::array::from_fn(|i| {
        let cell = CellIndex::from_index(i as u8).expect("i < N");
        geometry
            .support_of_cell(cell)
            .iter()
            .map(|&p| entry_commitments[p])
            .sum()
    })
}

/// `D_k = (sum_{p in block k} E_p) - G` (paper Construction 4.1).
pub fn block_sum_commitments(
    params: &Parameters,
    entry_commitments: &[RistrettoPoint],
) -> [RistrettoPoint; K] {
    assert_eq!(entry_commitments.len(), P);
    let geometry = params.geometry();
    std::array::from_fn(|k| {
        geometry
            .block_range(k)
            .map(|p| entry_commitments[p])
            .sum::<RistrettoPoint>()
            - params.g()
    })
}

/// Verifier-only: variable-time. Never call with secret scalars.
#[allow(dead_code)]
pub(crate) fn weighted_sum(points: &[RistrettoPoint], weights: &[Scalar]) -> RistrettoPoint {
    assert_eq!(points.len(), weights.len());
    RistrettoPoint::vartime_multiscalar_mul(weights, points)
}

/// Linear opening check (paper §2.2). `pub(crate)` by design: an
/// arbitrary-weight opening oracle exposed to a peer would leak the placement.
/// Verifier-only: variable-time.
#[allow(dead_code)]
pub(crate) fn verify_linear_opening(
    params: &Parameters,
    points: &[RistrettoPoint],
    weights: &[Scalar],
    a: &Scalar,
    c: &Scalar,
) -> bool {
    weighted_sum(points, weights) == commit(params, a, c)
}

/// Zeroized on drop. Never reuse blinders with a different placement.
pub struct BlindingVector(Zeroizing<Vec<Scalar>>);

impl BlindingVector {
    pub fn sample<R: RngCore + CryptoRng>(rng: &mut R, len: usize) -> BlindingVector {
        BlindingVector(Zeroizing::new(
            (0..len).map(|_| Scalar::random(rng)).collect(),
        ))
    }

    pub fn as_slice(&self) -> &[Scalar] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{Geometry, P};
    use rand::Rng;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed([7u8; 32])
    }

    fn random_legal_placement<R: Rng>(rng: &mut R, geometry: &Geometry) -> Vec<u8> {
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
    fn homomorphism() {
        let params = Parameters::standard_v1();
        let mut rng = rng();
        let v1 = Scalar::random(&mut rng);
        let r1 = Scalar::random(&mut rng);
        let v2 = Scalar::random(&mut rng);
        let r2 = Scalar::random(&mut rng);
        assert_eq!(
            commit(params, &v1, &r1) + commit(params, &v2, &r2),
            commit(params, &(v1 + v2), &(r1 + r2))
        );
    }

    #[test]
    fn honest_linear_opening_verifies() {
        let params = Parameters::standard_v1();
        let mut rng = rng();
        let len = 10;
        let v: Vec<Scalar> = (0..len).map(|_| Scalar::random(&mut rng)).collect();
        let r: Vec<Scalar> = (0..len).map(|_| Scalar::random(&mut rng)).collect();
        let points: Vec<RistrettoPoint> = v
            .iter()
            .zip(&r)
            .map(|(v, r)| commit(params, v, r))
            .collect();
        let w: Vec<Scalar> = (0..len).map(|_| Scalar::random(&mut rng)).collect();

        let a: Scalar = w.iter().zip(&v).map(|(w, v)| w * v).sum();
        let c: Scalar = w.iter().zip(&r).map(|(w, r)| w * r).sum();

        assert!(verify_linear_opening(params, &points, &w, &a, &c));
        assert!(!verify_linear_opening(
            params,
            &points,
            &w,
            &(a + Scalar::ONE),
            &c
        ));
        assert!(!verify_linear_opening(
            params,
            &points,
            &w,
            &a,
            &(c + Scalar::ONE)
        ));
        let mut w_bad = w.clone();
        w_bad[3] += Scalar::ONE;
        assert!(!verify_linear_opening(params, &points, &w_bad, &a, &c));
    }

    #[test]
    fn derived_cell_commitments_match_honest_opening() {
        let params = Parameters::standard_v1();
        let mut rng = rng();
        let e = random_legal_placement(&mut rng, params.geometry());
        let s = BlindingVector::sample(&mut rng, P);
        let entry_commitments = commit_vector(params, &e, s.as_slice());
        let cells = cell_commitments(params, &entry_commitments);

        let geometry = params.geometry();
        for (i, c_i) in cells.iter().enumerate() {
            let cell = CellIndex::from_index(i as u8).unwrap();
            let support = geometry.support_of_cell(cell);
            let b: u64 = support.iter().map(|&p| u64::from(e[p])).sum();
            let rho: Scalar = support.iter().map(|&p| s.as_slice()[p]).sum();
            assert_eq!(*c_i, commit(params, &Scalar::from(b), &rho));
        }
    }

    #[test]
    fn derived_block_sums_are_h_only_for_legal_placement() {
        let params = Parameters::standard_v1();
        let mut rng = rng();
        let e = random_legal_placement(&mut rng, params.geometry());
        let s = BlindingVector::sample(&mut rng, P);
        let entry_commitments = commit_vector(params, &e, s.as_slice());
        let block_sums = block_sum_commitments(params, &entry_commitments);

        for (k, d_k) in block_sums.iter().enumerate() {
            let epsilon_k: Scalar = params
                .geometry()
                .block_range(k)
                .map(|p| s.as_slice()[p])
                .sum();
            assert_eq!(*d_k, epsilon_k * params.h());
        }
    }

    #[test]
    #[should_panic(expected = "placement vector must have exactly P entries")]
    fn commit_vector_rejects_wrong_length() {
        let params = Parameters::standard_v1();
        let s = BlindingVector::sample(&mut rng(), P);
        commit_vector(params, &[0u8; P - 1], s.as_slice());
    }

    #[test]
    #[should_panic(expected = "placement entries must be bits")]
    fn commit_vector_rejects_non_bit() {
        let params = Parameters::standard_v1();
        let s = BlindingVector::sample(&mut rng(), P);
        let mut e = vec![0u8; P];
        e[0] = 2;
        commit_vector(params, &e, s.as_slice());
    }
}
