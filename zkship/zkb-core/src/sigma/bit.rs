//! Groth-Kohlweiss bit protocol (paper Construction 2.6), additive notation.
//! Verifier recomputes `c_a_hat = fG + z_a*H - x*X`, `c_b_hat = z_b*H + (f - x)*X`.
//! The prover never branches on the secret bit: `(a*v)G` is computed algebraically.

use crate::params::Parameters;
use crate::pedersen;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Debug)]
pub struct BitFirstMessage {
    /// `c_a = aG + dH`.
    pub c_a: RistrettoPoint,
    /// `c_b = (a*v)G + tH`.
    pub c_b: RistrettoPoint,
}

#[derive(Clone, Debug)]
pub struct BitResponse {
    /// `f = v*x + a`.
    pub f: Scalar,
    /// `z_a = u*x + d`.
    pub z_a: Scalar,
    /// `z_b = u*(x - f) + t`.
    pub z_b: Scalar,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct BitProver {
    v: Scalar,
    u: Scalar,
    a: Scalar,
    d: Scalar,
    t: Scalar,
}

impl BitProver {
    /// `v` must be `Scalar::ZERO` or `Scalar::ONE`.
    pub fn new<R: RngCore + CryptoRng>(
        params: &Parameters,
        v: &Scalar,
        u: &Scalar,
        rng: &mut R,
    ) -> (BitProver, BitFirstMessage) {
        let a = Scalar::random(rng);
        let d = Scalar::random(rng);
        let t = Scalar::random(rng);
        let first = BitFirstMessage {
            c_a: pedersen::commit(params, &a, &d),
            c_b: pedersen::commit(params, &(a * v), &t),
        };
        let prover = BitProver {
            v: *v,
            u: *u,
            a,
            d,
            t,
        };
        (prover, first)
    }

    pub fn respond(mut self, x: &Scalar) -> BitResponse {
        self.respond_in_place(x)
    }

    /// Zeroizes in place: moving the state out of a `Vec` would leave the
    /// nonces in the old heap slot.
    pub(crate) fn respond_in_place(&mut self, x: &Scalar) -> BitResponse {
        let f = self.v * x + self.a;
        let z_a = self.u * x + self.d;
        let z_b = self.u * (*x - f) + self.t;
        self.zeroize();
        BitResponse { f, z_a, z_b }
    }
}

pub fn recompute_c_a(
    params: &Parameters,
    statement: &RistrettoPoint,
    x: &Scalar,
    response: &BitResponse,
) -> RistrettoPoint {
    response.f * params.g() + response.z_a * params.h() - x * statement
}

pub fn recompute_c_b(
    params: &Parameters,
    statement: &RistrettoPoint,
    x: &Scalar,
    response: &BitResponse,
) -> RistrettoPoint {
    response.z_b * params.h() + (response.f - x) * statement
}

pub fn verify(
    params: &Parameters,
    statement: &RistrettoPoint,
    first: &BitFirstMessage,
    x: &Scalar,
    response: &BitResponse,
) -> bool {
    recompute_c_a(params, statement, x, response) == first.c_a
        && recompute_c_b(params, statement, x, response) == first.c_b
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn rng(seed: u8) -> ChaCha20Rng {
        ChaCha20Rng::from_seed([seed; 32])
    }

    #[test]
    fn in_place_response_erases_nonce_storage() {
        let params = Parameters::standard_v1();
        let u = Scalar::from(23u64);
        let statement = pedersen::commit(params, &Scalar::ONE, &u);
        let (mut prover, first) = BitProver::new(params, &Scalar::ONE, &u, &mut rng(7));
        let x = Scalar::from(19u64);
        let response = prover.respond_in_place(&x);
        assert!(verify(params, &statement, &first, &x, &response));
        assert_eq!(
            [prover.v, prover.u, prover.a, prover.d, prover.t],
            [Scalar::ZERO; 5]
        );
    }

    #[test]
    fn completeness_for_both_bits() {
        let params = Parameters::standard_v1();
        for v in [Scalar::ZERO, Scalar::ONE] {
            let mut rng = rng(1);
            let u = Scalar::random(&mut rng);
            let statement = pedersen::commit(params, &v, &u);
            let (prover, first) = BitProver::new(params, &v, &u, &mut rng);
            let x = Scalar::random(&mut rng);
            let response = prover.respond(&x);
            assert!(verify(params, &statement, &first, &x, &response));
        }
    }

    #[test]
    fn shvzk_simulator_equations() {
        // Simulator of paper Lemma 2.7.
        let params = Parameters::standard_v1();
        let mut rng = rng(2);
        let statement = pedersen::commit(params, &Scalar::ONE, &Scalar::random(&mut rng));
        let x = Scalar::random(&mut rng);
        let response = BitResponse {
            f: Scalar::random(&mut rng),
            z_a: Scalar::random(&mut rng),
            z_b: Scalar::random(&mut rng),
        };
        let first = BitFirstMessage {
            c_a: recompute_c_a(params, &statement, &x, &response),
            c_b: recompute_c_b(params, &statement, &x, &response),
        };
        assert!(verify(params, &statement, &first, &x, &response));
    }

    #[test]
    fn special_soundness_extraction() {
        // Extractor of paper Lemma 2.7.
        let params = Parameters::standard_v1();
        let v = Scalar::ONE;
        let u = Scalar::random(&mut rng(3));
        let statement = pedersen::commit(params, &v, &u);

        let (p1, first1) = BitProver::new(params, &v, &u, &mut rng(4));
        let (p2, first2) = BitProver::new(params, &v, &u, &mut rng(4));
        assert_eq!(first1.c_a.compress(), first2.c_a.compress());
        assert_eq!(first1.c_b.compress(), first2.c_b.compress());

        let x1 = Scalar::from(5u64);
        let x2 = Scalar::from(6u64);
        let r1 = p1.respond(&x1);
        let r2 = p2.respond(&x2);
        assert!(verify(params, &statement, &first1, &x1, &r1));
        assert!(verify(params, &statement, &first1, &x2, &r2));

        let delta_inv = (x1 - x2).invert();
        let b = (r1.f - r2.f) * delta_inv;
        let r = (r1.z_a - r2.z_a) * delta_inv;
        assert_eq!(statement, pedersen::commit(params, &b, &r));
        assert!(b == Scalar::ZERO || b == Scalar::ONE);
        assert_eq!(b * (Scalar::ONE - b), Scalar::ZERO);
        assert_eq!(b, v);
        assert_eq!(r, u);
    }

    #[test]
    fn proof_for_one_fails_against_zero_statement() {
        let params = Parameters::standard_v1();
        let mut rng = rng(5);
        let u = Scalar::random(&mut rng);
        let statement_one = pedersen::commit(params, &Scalar::ONE, &u);
        let statement_zero = pedersen::commit(params, &Scalar::ZERO, &u);
        let (prover, first) = BitProver::new(params, &Scalar::ONE, &u, &mut rng);
        let x = Scalar::random(&mut rng);
        let response = prover.respond(&x);
        assert!(verify(params, &statement_one, &first, &x, &response));
        assert!(!verify(params, &statement_zero, &first, &x, &response));
    }

    #[test]
    fn tampered_response_fails() {
        let params = Parameters::standard_v1();
        let mut rng = rng(6);
        let v = Scalar::ZERO;
        let u = Scalar::random(&mut rng);
        let statement = pedersen::commit(params, &v, &u);
        let (prover, first) = BitProver::new(params, &v, &u, &mut rng);
        let x = Scalar::random(&mut rng);
        let response = prover.respond(&x);

        let mut bad = response.clone();
        bad.f += Scalar::ONE;
        assert!(!verify(params, &statement, &first, &x, &bad));

        let mut bad = response.clone();
        bad.z_a += Scalar::ONE;
        assert!(!verify(params, &statement, &first, &x, &bad));

        let mut bad = response.clone();
        bad.z_b += Scalar::ONE;
        assert!(!verify(params, &statement, &first, &x, &bad));
    }
}
