//! First-mover coin flip (paper Construction 7.1, S5), run only after both setup messages
//! verify. Never derived from setup bytes: whoever chooses those last could grind the outcome.

use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512_256};
use zkb_core::game::Role;

/// `coin_commit = SHA-512/256(COIN_COMMIT_DOMAIN || sid || r_A)`.
pub const COIN_COMMIT_DOMAIN: &[u8] = b"zkbattleship/reference/v1/coin-commit";

/// `coin = SHA-512/256(FIRST_MOVER_DOMAIN || sid || r_A || r_B)`; `first_mover = coin[0] & 1`.
pub const FIRST_MOVER_DOMAIN: &[u8] = b"zkbattleship/reference/v1/first-mover";

pub fn sample_nonce<R: RngCore + CryptoRng>(rng: &mut R) -> [u8; 32] {
    let mut nonce = [0u8; 32];
    rng.fill_bytes(&mut nonce);
    nonce
}

pub fn coin_commit(sid: &[u8; 32], r_a: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha512_256::new();
    hasher.update(COIN_COMMIT_DOMAIN);
    hasher.update(sid);
    hasher.update(r_a);
    hasher.finalize().into()
}

pub fn verify_reveal(sid: &[u8; 32], commitment: &[u8; 32], r_a: &[u8; 32]) -> bool {
    &coin_commit(sid, r_a) == commitment
}

/// `coin[0] & 1`: 0 -> A, 1 -> B.
pub fn first_mover(sid: &[u8; 32], r_a: &[u8; 32], r_b: &[u8; 32]) -> Role {
    let mut hasher = Sha512_256::new();
    hasher.update(FIRST_MOVER_DOMAIN);
    hasher.update(sid);
    hasher.update(r_a);
    hasher.update(r_b);
    let coin: [u8; 32] = hasher.finalize().into();
    match coin[0] & 1 {
        0 => Role::A,
        _ => Role::B,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SID: [u8; 32] = [0x55; 32];
    const R_A: [u8; 32] = [0x66; 32];
    const R_B: [u8; 32] = [0x77; 32];

    #[test]
    fn coin_vector_is_pinned() {
        let hex = |b: &[u8]| b.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(
            hex(&coin_commit(&SID, &R_A)),
            "cce633e74b823a0d7a47f4c80ec38025fe3a2703f190a8f75b68aa1aa557f2ee"
        );
        assert_eq!(first_mover(&SID, &R_A, &R_B), Role::A);
    }

    #[test]
    fn bad_reveal_is_rejected() {
        let commitment = coin_commit(&SID, &R_A);
        assert!(verify_reveal(&SID, &commitment, &R_A));
        assert!(!verify_reveal(&SID, &commitment, &R_B));
        let wrong_sid = [0x99; 32];
        assert!(!verify_reveal(&wrong_sid, &commitment, &R_A));
    }
}
