//! Public parameters of the paper's construction (Definition 3.1). Peers
//! never exchange generators, only `params_id`, which also fixes the rule
//! set.

use crate::bp::BpGens;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{RistrettoBasepointTable, RistrettoPoint};
use curve25519_dalek::traits::Identity;
use sha2::{Digest, Sha512, Sha512_256};
use std::sync::OnceLock;

pub const BOARD_N: usize = 10;
pub const N: usize = BOARD_N * BOARD_N;
pub const K: usize = 5;
pub const FLEET_LENGTHS: [u8; K] = [5, 4, 3, 3, 2];
pub const T: usize = 17;

const H_DERIVATION_DOMAIN: &[u8] = b"zkbattleship/reference/v1/pedersen-H";
const PARAMS_ID_DOMAIN: &[u8] = b"zkbattleship/reference/v1/params-id";

const PROTOCOL_ID: &[u8] = b"zkbattleship";
const PROTOCOL_VERSION: u16 = 2;
const CRYPTO_SUITE_ID: &[u8] = b"ristretto255+sha512";
const CONSTRUCTION_ID: &[u8] = b"zkbattleship/construction/ship-indicators";
const CONSTRUCTION_VERSION: u16 = 1;
const BP_GENERATORS_DOMAIN: &[u8] = b"zkbattleship/paper/v1/bp-generators";

/// Rule set. Part of the parameters (and so of `params_id`): peers agree on
/// it before any proof is exchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rules {
    Standard,
    /// Ships may not touch, diagonals included (paper Section 6).
    NoTouch,
}

impl Rules {
    fn id(self) -> u8 {
        match self {
            Rules::Standard => 0,
            Rules::NoTouch => 1,
        }
    }

    /// Bulletproofs generators needed: 605 setup bits pad to 1,024; the
    /// no-touch proof's 500 eight-bit values pad to 4,096.
    fn bp_capacity(self) -> usize {
        match self {
            Rules::Standard => 1024,
            Rules::NoTouch => 4096,
        }
    }
}

/// Index `row * BOARD_N + col`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CellIndex(u8);

impl CellIndex {
    pub fn from_row_col(row: u8, col: u8) -> Option<CellIndex> {
        if row < BOARD_N as u8 && col < BOARD_N as u8 {
            Some(CellIndex(row * BOARD_N as u8 + col))
        } else {
            None
        }
    }

    pub fn from_index(index: u8) -> Option<CellIndex> {
        if (index as usize) < N {
            Some(CellIndex(index))
        } else {
            None
        }
    }

    pub fn index(self) -> u8 {
        self.0
    }

    pub fn row(self) -> u8 {
        self.0 / BOARD_N as u8
    }

    pub fn col(self) -> u8 {
        self.0 % BOARD_N as u8
    }
}

pub struct Parameters {
    rules: Rules,
    bp_gens: BpGens,
    g_table: RistrettoBasepointTable,
    h_table: RistrettoBasepointTable,
    g: RistrettoPoint,
    h: RistrettoPoint,
    g_bytes: [u8; 32],
    h_bytes: [u8; 32],
    canonical_bytes: Box<[u8]>,
    params_id: [u8; 32],
}

impl Parameters {
    /// The standard game.
    pub fn standard() -> &'static Parameters {
        static STANDARD: OnceLock<Parameters> = OnceLock::new();
        STANDARD.get_or_init(|| Parameters::production(Rules::Standard))
    }

    /// The no-touch variant.
    pub fn no_touch() -> &'static Parameters {
        static NO_TOUCH: OnceLock<Parameters> = OnceLock::new();
        NO_TOUCH.get_or_init(|| Parameters::production(Rules::NoTouch))
    }

    pub fn for_rules(rules: Rules) -> &'static Parameters {
        match rules {
            Rules::Standard => Parameters::standard(),
            Rules::NoTouch => Parameters::no_touch(),
        }
    }

    /// `G` = Ristretto basepoint; `H` = hash-to-group of the domain string,
    /// never `scalar * G` (that would publish `log_G H` and break binding).
    fn production(rules: Rules) -> Parameters {
        let g = RISTRETTO_BASEPOINT_POINT;
        let h = RistrettoPoint::hash_from_bytes::<Sha512>(H_DERIVATION_DOMAIN);
        assert!(
            h != RistrettoPoint::identity(),
            "derived H must not be the identity"
        );
        assert!(h != g, "derived H must differ from G");
        Parameters::new(g, h, rules)
    }

    fn new(g: RistrettoPoint, h: RistrettoPoint, rules: Rules) -> Parameters {
        let g_bytes = g.compress().to_bytes();
        let h_bytes = h.compress().to_bytes();
        let canonical_bytes =
            canonical_parameter_bytes(&g_bytes, &h_bytes, rules).into_boxed_slice();
        let params_id = derive_params_id(&canonical_bytes);
        Parameters {
            rules,
            bp_gens: BpGens::derive(BP_GENERATORS_DOMAIN, rules.bp_capacity()),
            g_table: RistrettoBasepointTable::create(&g),
            h_table: RistrettoBasepointTable::create(&h),
            g,
            h,
            g_bytes,
            h_bytes,
            canonical_bytes,
            params_id,
        }
    }

    /// Trapdoored generators for the coupling test. Unreachable from
    /// production/network code; the trapdoor scalar is never stored here.
    #[cfg(test)]
    pub(crate) fn from_test_generators(
        g: RistrettoPoint,
        h: RistrettoPoint,
        rules: Rules,
    ) -> Parameters {
        Parameters::new(g, h, rules)
    }

    pub fn rules(&self) -> Rules {
        self.rules
    }

    pub fn bp_gens(&self) -> &BpGens {
        &self.bp_gens
    }

    /// Constant-time fixed-base multiplication by `g`, for secret values.
    pub fn g_table(&self) -> &RistrettoBasepointTable {
        &self.g_table
    }

    /// Constant-time fixed-base multiplication by `h`, for secret blinders.
    pub fn h_table(&self) -> &RistrettoBasepointTable {
        &self.h_table
    }

    /// Paper `g`.
    pub fn g(&self) -> &RistrettoPoint {
        &self.g
    }

    /// Paper `h`.
    pub fn h(&self) -> &RistrettoPoint {
        &self.h
    }

    pub fn g_encoding(&self) -> &[u8; 32] {
        &self.g_bytes
    }

    pub fn h_encoding(&self) -> &[u8; 32] {
        &self.h_bytes
    }

    /// Bound in full into every Fiat-Shamir transcript (paper `pp`). Integers
    /// little-endian; strings `u16`-length-prefixed.
    ///
    /// ```text
    /// u16+bytes  protocol identifier = "zkbattleship"
    /// u16        protocol version (= 2)
    /// u16+bytes  crypto-suite identifier = "ristretto255+sha512"
    /// u8         board size n (= 10)
    /// u16        number of ships (= 5)
    /// u8 x 5     ordered fleet lengths (= 05 04 03 03 02)
    /// u16+bytes  construction identifier = "zkbattleship/construction/ship-indicators"
    /// u16        construction version (= 1)
    /// u8         rules (0 standard, 1 no-touch)
    /// u16+bytes  Bulletproofs generator domain
    /// u32        Bulletproofs generator capacity
    /// 32         canonical G encoding
    /// 32         canonical H encoding
    /// ```
    pub fn canonical_params_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// `SHA-512/256(PARAMS_ID_DOMAIN || canonical_params_bytes)`.
    pub fn params_id(&self) -> &[u8; 32] {
        &self.params_id
    }
}

fn push_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(bytes);
}

fn canonical_parameter_bytes(g_bytes: &[u8; 32], h_bytes: &[u8; 32], rules: Rules) -> Vec<u8> {
    let mut out = Vec::with_capacity(196);
    push_len_prefixed(&mut out, PROTOCOL_ID);
    out.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    push_len_prefixed(&mut out, CRYPTO_SUITE_ID);
    out.push(BOARD_N as u8);
    out.extend_from_slice(&(FLEET_LENGTHS.len() as u16).to_le_bytes());
    out.extend_from_slice(&FLEET_LENGTHS);
    push_len_prefixed(&mut out, CONSTRUCTION_ID);
    out.extend_from_slice(&CONSTRUCTION_VERSION.to_le_bytes());
    out.push(rules.id());
    push_len_prefixed(&mut out, BP_GENERATORS_DOMAIN);
    out.extend_from_slice(&(rules.bp_capacity() as u32).to_le_bytes());
    out.extend_from_slice(g_bytes);
    out.extend_from_slice(h_bytes);
    out
}

fn derive_params_id(canonical_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha512_256::new();
    hasher.update(PARAMS_ID_DOMAIN);
    hasher.update(canonical_bytes);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn profiles_are_singletons() {
        assert!(std::ptr::eq(Parameters::standard(), Parameters::standard()));
        assert!(std::ptr::eq(
            Parameters::no_touch(),
            Parameters::for_rules(Rules::NoTouch)
        ));
    }

    #[test]
    fn generator_encodings_are_pinned() {
        let params = Parameters::standard();
        assert_eq!(
            hex(params.g_encoding()),
            "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"
        );
        assert_eq!(
            hex(params.h_encoding()),
            "8e0798914faacfe5a3cecddc2b04bd0ee008695f09c43b2bac3342734fd54773"
        );
        assert_ne!(params.h(), &RistrettoPoint::identity());
        assert_ne!(params.h(), params.g());
        assert_eq!(Parameters::no_touch().h(), params.h());
    }

    #[test]
    fn profiles_are_pinned() {
        let standard = Parameters::standard();
        let no_touch = Parameters::no_touch();
        assert_eq!(standard.rules(), Rules::Standard);
        assert_eq!(no_touch.rules(), Rules::NoTouch);
        assert_eq!(standard.bp_gens().capacity(), 1024);
        assert_eq!(no_touch.bp_gens().capacity(), 4096);
        assert_eq!(
            standard.bp_gens().g(1024),
            &no_touch.bp_gens().g(4096)[..1024]
        );
        assert_eq!(standard.canonical_params_bytes().len(), 196);
        assert_eq!(
            hex(standard.params_id()),
            "481b5e4f343d6a06959e00cb452b26411e10672a1945db52a6f65a1de86124f5"
        );
        assert_eq!(
            hex(no_touch.params_id()),
            "17d332c9cd578ca3e1b6987e8b4edfe972317990f6311bd49bb761265b07d9c8"
        );
    }

    #[test]
    fn test_generators_do_not_touch_the_production_profile() {
        use curve25519_dalek::scalar::Scalar;

        let xi = Scalar::from(42u64);
        let h = RistrettoPoint::hash_from_bytes::<Sha512>(b"zkbattleship/test-only/H");
        let g = xi * h;
        let test_params = Parameters::from_test_generators(g, h, Rules::Standard);
        assert_eq!(test_params.g(), &g);
        assert_eq!(test_params.h(), &h);
        assert_ne!(Parameters::standard().params_id(), test_params.params_id());
    }
}
