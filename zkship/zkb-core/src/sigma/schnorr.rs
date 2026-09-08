//! Schnorr (paper §2.4) for `D = eps*H`: `R = t*H`, `z = t + x*eps`,
//! verifier recomputes `R_hat = z*H - x*D`.

use crate::params::Parameters;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SchnorrProver {
    eps: Scalar,
    t: Scalar,
}

impl SchnorrProver {
    pub fn new<R: RngCore + CryptoRng>(
        params: &Parameters,
        eps: &Scalar,
        rng: &mut R,
    ) -> (SchnorrProver, RistrettoPoint) {
        let t = Scalar::random(rng);
        (SchnorrProver { eps: *eps, t }, t * params.h())
    }

    pub fn respond(mut self, x: &Scalar) -> Scalar {
        self.respond_in_place(x)
    }

    /// Zeroizes in place: moving the state out of a `Vec` would leave the
    /// nonce in the old heap slot.
    pub(crate) fn respond_in_place(&mut self, x: &Scalar) -> Scalar {
        let z = self.t + x * self.eps;
        self.zeroize();
        z
    }
}

pub fn recompute_r(
    params: &Parameters,
    statement: &RistrettoPoint,
    x: &Scalar,
    z: &Scalar,
) -> RistrettoPoint {
    z * params.h() - x * statement
}

pub fn verify(
    params: &Parameters,
    statement: &RistrettoPoint,
    r: &RistrettoPoint,
    x: &Scalar,
    z: &Scalar,
) -> bool {
    recompute_r(params, statement, x, z) == *r
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
        let eps = Scalar::from(23u64);
        let statement = eps * params.h();
        let (mut prover, first) = SchnorrProver::new(params, &eps, &mut rng(7));
        let x = Scalar::from(19u64);
        let response = prover.respond_in_place(&x);
        assert!(verify(params, &statement, &first, &x, &response));
        assert_eq!([prover.eps, prover.t], [Scalar::ZERO; 2]);
    }

    #[test]
    fn completeness() {
        let params = Parameters::standard_v1();
        let mut rng = rng(1);
        let eps = Scalar::random(&mut rng);
        let statement = eps * params.h();
        let (prover, r) = SchnorrProver::new(params, &eps, &mut rng);
        let x = Scalar::random(&mut rng);
        let z = prover.respond(&x);
        assert!(verify(params, &statement, &r, &x, &z));
    }

    #[test]
    fn extraction_from_two_challenges() {
        let params = Parameters::standard_v1();
        let eps = Scalar::random(&mut rng(2));
        let statement = eps * params.h();

        let (p1, r1) = SchnorrProver::new(params, &eps, &mut rng(3));
        let (p2, r2) = SchnorrProver::new(params, &eps, &mut rng(3));
        assert_eq!(r1.compress(), r2.compress());

        let x1 = Scalar::from(11u64);
        let x2 = Scalar::from(12u64);
        let z1 = p1.respond(&x1);
        let z2 = p2.respond(&x2);
        assert!(verify(params, &statement, &r1, &x1, &z1));
        assert!(verify(params, &statement, &r1, &x2, &z2));

        let extracted = (z1 - z2) * (x1 - x2).invert();
        assert_eq!(extracted, eps);
        assert_eq!(statement, extracted * params.h());
    }

    #[test]
    fn tampered_response_or_statement_fails() {
        let params = Parameters::standard_v1();
        let mut rng = rng(4);
        let eps = Scalar::random(&mut rng);
        let statement = eps * params.h();
        let (prover, r) = SchnorrProver::new(params, &eps, &mut rng);
        let x = Scalar::random(&mut rng);
        let z = prover.respond(&x);

        assert!(!verify(params, &statement, &r, &x, &(z + Scalar::ONE)));
        let wrong_statement = statement + params.g();
        assert!(!verify(params, &wrong_statement, &r, &x, &z));
        let wrong_x = x + Scalar::ONE;
        assert!(!verify(params, &statement, &r, &wrong_x, &z));
    }
}
