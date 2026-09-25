//! Squaring Σ-protocol in the style of Chaum-Pedersen (paper Construction
//! 2.8): given `X = a G + r1 H` and `Q`, prove `Q` commits to `a^2`, by proving
//! knowledge of `(a, r1, r2)` with `X = a G + r1 H` and `Q = a X + r2 H`
//! (so `Q = a^2 G + (a r1 + r2) H`).
//!
//! First message `T1 = ka G + k1 H`, `T2 = ka X + k2 H`; responses
//! `za = ka + c a`, `z1 = k1 + c r1`, `z2 = k2 + c r2`. Verifier checks
//! `za G + z1 H = T1 + c X` and `za X + z2 H = T2 + c Q`.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{MultiscalarMul, VartimeMultiscalarMul};
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SquareFirstMessage {
    pub t1: RistrettoPoint,
    pub t2: RistrettoPoint,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SquareResponse {
    pub za: Scalar,
    pub z1: Scalar,
    pub z2: Scalar,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SquareProver {
    a: Scalar,
    r1: Scalar,
    r2: Scalar,
    ka: Scalar,
    k1: Scalar,
    k2: Scalar,
}

impl SquareProver {
    /// `x` is the public `X`; `r_q` the blinder of `Q = a^2 G + r_q H`.
    pub fn new<R: RngCore + CryptoRng>(
        g: &RistrettoPoint,
        h: &RistrettoPoint,
        x: &RistrettoPoint,
        a: &Scalar,
        r1: &Scalar,
        r_q: &Scalar,
        rng: &mut R,
    ) -> (SquareProver, SquareFirstMessage) {
        let ka = Scalar::random(rng);
        let k1 = Scalar::random(rng);
        let k2 = Scalar::random(rng);
        let first = SquareFirstMessage {
            t1: RistrettoPoint::multiscalar_mul([ka, k1], [g, h]),
            t2: RistrettoPoint::multiscalar_mul([ka, k2], [x, h]),
        };
        let prover = SquareProver {
            a: *a,
            r1: *r1,
            r2: r_q - a * r1,
            ka,
            k1,
            k2,
        };
        (prover, first)
    }

    /// Zeroizes in place: moving the state out of a `Vec` would leave the
    /// nonces in the old heap slot.
    pub fn respond_in_place(&mut self, c: &Scalar) -> SquareResponse {
        let response = SquareResponse {
            za: self.ka + c * self.a,
            z1: self.k1 + c * self.r1,
            z2: self.k2 + c * self.r2,
        };
        self.zeroize();
        response
    }
}

/// The first message the verifier expects for `(X, Q)` under challenge `c`;
/// Fiat-Shamir compares it through the transcript.
pub fn recompute_first(
    g: &RistrettoPoint,
    h: &RistrettoPoint,
    x: &RistrettoPoint,
    q: &RistrettoPoint,
    c: &Scalar,
    z: &SquareResponse,
) -> SquareFirstMessage {
    SquareFirstMessage {
        t1: RistrettoPoint::vartime_multiscalar_mul([z.za, z.z1, -c], [g, h, x]),
        t2: RistrettoPoint::vartime_multiscalar_mul([z.za, z.z2, -c], [x, h, q]),
    }
}

pub fn verify(
    g: &RistrettoPoint,
    h: &RistrettoPoint,
    x: &RistrettoPoint,
    q: &RistrettoPoint,
    first: &SquareFirstMessage,
    c: &Scalar,
    z: &SquareResponse,
) -> bool {
    recompute_first(g, h, x, q, c, z) == *first
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use sha2::Sha512;

    fn h() -> RistrettoPoint {
        RistrettoPoint::hash_from_bytes::<Sha512>(b"zkbattleship/test-only/square-H")
    }

    fn statement(a: u64, r1: &Scalar, r_q: &Scalar) -> (RistrettoPoint, RistrettoPoint) {
        let a = Scalar::from(a);
        (a * G + r1 * h(), a * a * G + r_q * h())
    }

    #[test]
    fn completeness_and_zeroization() {
        let mut rng = ChaCha20Rng::from_seed([1; 32]);
        let (r1, r_q) = (Scalar::random(&mut rng), Scalar::random(&mut rng));
        for a in [0u64, 1, 7, 45] {
            let (x, q) = statement(a, &r1, &r_q);
            let (mut prover, first) =
                SquareProver::new(&G, &h(), &x, &Scalar::from(a), &r1, &r_q, &mut rng);
            let c = Scalar::random(&mut rng);
            let z = prover.respond_in_place(&c);
            assert!(verify(&G, &h(), &x, &q, &first, &c, &z));
            assert_eq!([prover.a, prover.ka, prover.r2], [Scalar::ZERO; 3]);
        }
    }

    #[test]
    fn extraction_from_two_challenges() {
        let mut rng = ChaCha20Rng::from_seed([2; 32]);
        let (r1, r_q) = (Scalar::random(&mut rng), Scalar::random(&mut rng));
        let (x, q) = statement(12, &r1, &r_q);
        let (mut p1, first) = SquareProver::new(
            &G,
            &h(),
            &x,
            &Scalar::from(12u64),
            &r1,
            &r_q,
            &mut ChaCha20Rng::from_seed([3; 32]),
        );
        let (mut p2, first2) = SquareProver::new(
            &G,
            &h(),
            &x,
            &Scalar::from(12u64),
            &r1,
            &r_q,
            &mut ChaCha20Rng::from_seed([3; 32]),
        );
        assert_eq!(first, first2);
        let (c1, c2) = (Scalar::from(5u64), Scalar::from(9u64));
        let (z1, z2) = (p1.respond_in_place(&c1), p2.respond_in_place(&c2));
        let inv = (c1 - c2).invert();
        let a = (z1.za - z2.za) * inv;
        let r1x = (z1.z1 - z2.z1) * inv;
        let r2x = (z1.z2 - z2.z2) * inv;
        assert_eq!(x, a * G + r1x * h());
        assert_eq!(q, a * x + r2x * h());
        assert_eq!(a, Scalar::from(12u64));
    }

    #[test]
    fn non_square_is_rejected() {
        let mut rng = ChaCha20Rng::from_seed([4; 32]);
        let (r1, r_q) = (Scalar::random(&mut rng), Scalar::random(&mut rng));
        let (x, _) = statement(6, &r1, &r_q);
        // Q commits to 35, not 36.
        let q = Scalar::from(35u64) * G + r_q * h();
        let (mut prover, first) =
            SquareProver::new(&G, &h(), &x, &Scalar::from(6u64), &r1, &r_q, &mut rng);
        let c = Scalar::random(&mut rng);
        let z = prover.respond_in_place(&c);
        assert!(!verify(&G, &h(), &x, &q, &first, &c, &z));
    }

    #[test]
    fn tampered_responses_fail() {
        let mut rng = ChaCha20Rng::from_seed([5; 32]);
        let (r1, r_q) = (Scalar::random(&mut rng), Scalar::random(&mut rng));
        let (x, q) = statement(3, &r1, &r_q);
        let (mut prover, first) =
            SquareProver::new(&G, &h(), &x, &Scalar::from(3u64), &r1, &r_q, &mut rng);
        let c = Scalar::random(&mut rng);
        let z = prover.respond_in_place(&c);
        for i in 0..3 {
            let mut t = z;
            match i {
                0 => t.za += Scalar::ONE,
                1 => t.z1 += Scalar::ONE,
                _ => t.z2 += Scalar::ONE,
            }
            assert!(!verify(&G, &h(), &x, &q, &first, &c, &t));
        }
        assert!(!verify(&G, &h(), &x, &q, &first, &(c + Scalar::ONE), &z));
    }
}
