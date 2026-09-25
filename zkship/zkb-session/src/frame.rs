//! Signed session frame and linear chain.
//!
//! ```text
//! header:  sid[32] || sender_role u8 || sequence u64 LE ||
//!          message_type u8 || prev_hash[32] || payload_len u32 LE   (78 bytes)
//!          payload[payload_len]
//!          signature[64]
//! ```
//!
//! Signature covers `FRAME_SIGN_DOMAIN || header || payload`.
//! `frame_hash = SHA-512/256(FRAME_HASH_DOMAIN || full_signed_frame_bytes)`.
//! Genesis is sequence 0; the next frame must carry BOTH `sequence = n + 1`
//! AND `prev_hash = frame_hash(frame_n)`.

use crate::codec::{CodecError, MessageType, HEADER_LEN, MAX_FRAME_SIZE, SIGNATURE_LEN};
use crate::identity::{AuthenticatedPeer, IdentityKeypair};
use ed25519_dalek::Signature;
use sha2::{Digest, Sha512_256};
use std::fmt;
use zkb_core::game::Role;

pub const FRAME_SIGN_DOMAIN: &[u8] = b"zkbattleship/reference/v1/frame-sign";

pub const FRAME_HASH_DOMAIN: &[u8] = b"zkbattleship/reference/v1/frame";

pub const ROLE_A_BYTE: u8 = 0;
pub const ROLE_B_BYTE: u8 = 1;

pub fn role_to_byte(role: Role) -> u8 {
    match role {
        Role::A => ROLE_A_BYTE,
        Role::B => ROLE_B_BYTE,
    }
}

pub fn role_from_byte(b: u8) -> Option<Role> {
    match b {
        ROLE_A_BYTE => Some(Role::A),
        ROLE_B_BYTE => Some(Role::B),
        _ => None,
    }
}

pub fn frame_hash(frame_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha512_256::new();
    hasher.update(FRAME_HASH_DOMAIN);
    hasher.update(frame_bytes);
    hasher.finalize().into()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameHeader {
    pub sid: [u8; 32],
    pub sender_role: u8,
    pub sequence: u64,
    pub message_type: MessageType,
    pub prev_hash: [u8; 32],
    pub payload_len: u32,
}

impl FrameHeader {
    fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0..32].copy_from_slice(&self.sid);
        out[32] = self.sender_role;
        out[33..41].copy_from_slice(&self.sequence.to_le_bytes());
        out[41] = self.message_type.to_u8();
        out[42..74].copy_from_slice(&self.prev_hash);
        out[74..78].copy_from_slice(&self.payload_len.to_le_bytes());
        out
    }

    fn decode(bytes: &[u8]) -> FrameHeader {
        debug_assert_eq!(bytes.len(), HEADER_LEN);
        FrameHeader {
            sid: bytes[0..32].try_into().expect("length checked"),
            sender_role: bytes[32],
            sequence: u64::from_le_bytes(bytes[33..41].try_into().expect("length checked")),
            message_type: MessageType::from_u8(bytes[41]).expect("caller checks discriminant"),
            prev_hash: bytes[42..74].try_into().expect("length checked"),
            payload_len: u32::from_le_bytes(bytes[74..78].try_into().expect("length checked")),
        }
    }
}

/// Structurally valid, retained byte-for-byte; authentication is [`SignedFrame::authenticate`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedFrame {
    bytes: Vec<u8>,
    header: FrameHeader,
}

impl SignedFrame {
    /// Structural checks only, before any cryptography.
    pub fn decode(bytes: &[u8]) -> Result<SignedFrame, CodecError> {
        if bytes.len() < HEADER_LEN + SIGNATURE_LEN {
            return Err(CodecError::FrameTooSmall {
                actual: bytes.len(),
            });
        }
        if bytes.len() > MAX_FRAME_SIZE {
            return Err(CodecError::FrameTooLarge {
                actual: bytes.len(),
            });
        }
        let declared = u32::from_le_bytes(bytes[74..78].try_into().expect("length checked"));
        // Never form `HEADER_LEN + declared + SIGNATURE_LEN`: it overflows usize on 32-bit
        // targets (wasm32) and would panic on network input. `bytes.len()` is bounded by
        // MAX_FRAME_SIZE, so the subtraction cannot underflow.
        let actual = bytes.len() - HEADER_LEN - SIGNATURE_LEN;
        if u64::from(declared) != actual as u64 {
            return Err(CodecError::LengthMismatch { declared, actual });
        }
        let payload_len = actual;
        let message_type =
            MessageType::from_u8(bytes[41]).ok_or(CodecError::UnknownMessageType(bytes[41]))?;
        let payload = &bytes[HEADER_LEN..HEADER_LEN + payload_len];
        message_type.check_payload(payload)?;
        let header = FrameHeader::decode(&bytes[..HEADER_LEN]);
        Ok(SignedFrame {
            bytes: bytes.to_vec(),
            header,
        })
    }

    pub fn craft(
        keypair: &IdentityKeypair,
        sid: &[u8; 32],
        sender_role: Role,
        sequence: u64,
        message_type: MessageType,
        prev_hash: &[u8; 32],
        payload: Vec<u8>,
    ) -> SignedFrame {
        message_type
            .check_payload(&payload)
            .expect("locally crafted payload must satisfy the size rule");
        let header = FrameHeader {
            sid: *sid,
            sender_role: role_to_byte(sender_role),
            sequence,
            message_type,
            prev_hash: *prev_hash,
            payload_len: payload.len() as u32,
        };
        let header_bytes = header.encode();
        let mut bytes = Vec::with_capacity(HEADER_LEN + payload.len() + SIGNATURE_LEN);
        bytes.extend_from_slice(&header_bytes);
        bytes.extend_from_slice(&payload);
        let signature = keypair.sign(&signing_message(&bytes));
        bytes.extend_from_slice(&signature.to_bytes());
        SignedFrame { bytes, header }
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn header(&self) -> &FrameHeader {
        &self.header
    }

    pub fn payload(&self) -> &[u8] {
        let len = self.header.payload_len as usize;
        &self.bytes[HEADER_LEN..HEADER_LEN + len]
    }

    pub fn signature(&self) -> Signature {
        let start = self.bytes.len() - SIGNATURE_LEN;
        Signature::from_bytes(self.bytes[start..].try_into().expect("length checked"))
    }

    pub fn frame_hash(&self) -> [u8; 32] {
        frame_hash(&self.bytes)
    }

    /// Chain gate: exact sid, sequence, and prev_hash as one invariant, then strict signature
    /// under the authenticated peer key. Only after all pass is content attributable; every
    /// error here is class B.
    pub fn authenticate(
        self,
        expected: &ChainExpectation,
        peer: &AuthenticatedPeer,
    ) -> Result<AuthenticatedFrame, ChainError> {
        if self.header.sid != expected.sid {
            return Err(ChainError::WrongSession);
        }
        if self.header.sequence != expected.sequence {
            return Err(ChainError::WrongSequence {
                expected: expected.sequence,
                actual: self.header.sequence,
            });
        }
        if self.header.prev_hash != expected.prev_hash {
            return Err(ChainError::WrongPrevHash);
        }
        peer.verify_strict(&signing_message(self.signed_portion()), &self.signature())
            .map_err(|_| ChainError::BadSignature)?;
        Ok(AuthenticatedFrame(self))
    }

    fn signed_portion(&self) -> &[u8] {
        &self.bytes[..self.bytes.len() - SIGNATURE_LEN]
    }
}

fn signing_message(signed_portion: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(FRAME_SIGN_DOMAIN.len() + signed_portion.len());
    out.extend_from_slice(FRAME_SIGN_DOMAIN);
    out.extend_from_slice(signed_portion);
    out
}

pub struct ChainExpectation {
    pub sid: [u8; 32],
    pub sequence: u64,
    pub prev_hash: [u8; 32],
}

/// All class B: never evidence of peer cheating.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChainError {
    WrongSession,
    WrongSequence { expected: u64, actual: u64 },
    WrongPrevHash,
    BadSignature,
}

impl fmt::Display for ChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChainError::WrongSession => write!(f, "frame belongs to a different session"),
            ChainError::WrongSequence { expected, actual } => {
                write!(f, "frame sequence {actual}, expected {expected}")
            }
            ChainError::WrongPrevHash => write!(f, "frame prev_hash does not match the chain head"),
            ChainError::BadSignature => write!(f, "frame signature does not verify"),
        }
    }
}

impl std::error::Error for ChainError {}

/// Passed the chain gate; content is attributable to the authenticated peer key.
#[derive(Debug, PartialEq, Eq)]
pub struct AuthenticatedFrame(SignedFrame);

impl AuthenticatedFrame {
    pub fn frame(&self) -> &SignedFrame {
        &self.0
    }

    pub fn into_frame(self) -> SignedFrame {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::ANSWER_MISS_LEN;
    use crate::identity::{ExpectedKey, PeerAuthPolicy};

    fn keypair() -> IdentityKeypair {
        IdentityKeypair::from_seed(&[5; 32])
    }

    fn peer() -> AuthenticatedPeer {
        ExpectedKey::new(keypair().peer_key())
            .authenticate(&keypair().peer_key())
            .unwrap()
    }

    fn sid() -> [u8; 32] {
        [0x5E; 32]
    }

    fn genesis() -> [u8; 32] {
        [0x6E; 32]
    }

    fn shot_frame(sequence: u64, prev_hash: &[u8; 32]) -> SignedFrame {
        SignedFrame::craft(
            &keypair(),
            &sid(),
            Role::A,
            sequence,
            MessageType::Shot,
            prev_hash,
            vec![42],
        )
    }

    #[test]
    fn frame_roundtrip_and_hash() {
        let frame = shot_frame(1, &genesis());
        let decoded = SignedFrame::decode(frame.bytes()).unwrap();
        assert_eq!(decoded.bytes(), frame.bytes());
        assert_eq!(decoded.header().sequence, 1);
        assert_eq!(decoded.header().sender_role, ROLE_A_BYTE);
        assert_eq!(decoded.payload(), &[42]);
        assert_eq!(decoded.frame_hash(), frame_hash(frame.bytes()));
    }

    #[test]
    fn structural_rejections() {
        let frame = shot_frame(1, &genesis());
        let bytes = frame.bytes().to_vec();

        assert!(matches!(
            SignedFrame::decode(&bytes[..bytes.len() - 1]),
            Err(CodecError::LengthMismatch { .. })
        ));
        let mut long = bytes.clone();
        long.push(0);
        assert!(matches!(
            SignedFrame::decode(&long),
            Err(CodecError::LengthMismatch { .. })
        ));
        assert!(matches!(
            SignedFrame::decode(&bytes[..HEADER_LEN + SIGNATURE_LEN - 1]),
            Err(CodecError::FrameTooSmall { .. })
        ));

        let huge = vec![0u8; MAX_FRAME_SIZE + 1];
        assert!(matches!(
            SignedFrame::decode(&huge),
            Err(CodecError::FrameTooLarge { .. })
        ));

        let mut bad = bytes.clone();
        bad[41] = 99;
        assert_eq!(
            SignedFrame::decode(&bad),
            Err(CodecError::UnknownMessageType(99))
        );
    }

    #[test]
    fn huge_declared_payload_len_is_rejected_without_overflow() {
        // Must be an ordinary length mismatch, not a usize overflow on 32-bit targets.
        for declared in [u32::MAX, u32::MAX - 141, u32::MAX - 142, 1 << 31] {
            let mut bytes = vec![0u8; HEADER_LEN + SIGNATURE_LEN];
            bytes[74..78].copy_from_slice(&declared.to_le_bytes());
            assert_eq!(
                SignedFrame::decode(&bytes),
                Err(CodecError::LengthMismatch {
                    declared,
                    actual: 0
                })
            );
        }
    }

    #[test]
    fn answer_length_triple_consistency() {
        // Header declares 33, but no hit answer is 33 bytes long.
        let payload = {
            let mut p = vec![0u8; ANSWER_MISS_LEN];
            p[0] = 1;
            p
        };
        let header = FrameHeader {
            sid: sid(),
            sender_role: ROLE_A_BYTE,
            sequence: 1,
            message_type: MessageType::Answer,
            prev_hash: genesis(),
            payload_len: payload.len() as u32,
        };
        let mut bytes = header.encode().to_vec();
        bytes.extend_from_slice(&payload);
        bytes.extend_from_slice(&[0u8; SIGNATURE_LEN]);
        assert_eq!(
            SignedFrame::decode(&bytes),
            Err(CodecError::WrongAnswerLength { tag: 1, actual: 33 })
        );

        let mut bad = bytes.clone();
        bad[HEADER_LEN] = 3;
        assert_eq!(
            SignedFrame::decode(&bad),
            Err(CodecError::InvalidAnswerFlag(3))
        );
    }

    #[test]
    fn chain_gate() {
        let peer = peer();
        let frame = shot_frame(1, &genesis());
        let expectation = ChainExpectation {
            sid: sid(),
            sequence: 1,
            prev_hash: genesis(),
        };
        let auth = frame.clone().authenticate(&expectation, &peer).unwrap();
        assert_eq!(auth.frame().bytes(), frame.bytes());

        let bad = ChainExpectation {
            sid: [0xEE; 32],
            ..expectation
        };
        assert_eq!(
            frame.clone().authenticate(&bad, &peer),
            Err(ChainError::WrongSession)
        );
        let bad = ChainExpectation {
            sequence: 2,
            ..expectation
        };
        assert_eq!(
            frame.clone().authenticate(&bad, &peer),
            Err(ChainError::WrongSequence {
                expected: 2,
                actual: 1
            })
        );
        let bad = ChainExpectation {
            prev_hash: [0xEE; 32],
            ..expectation
        };
        assert_eq!(
            frame.clone().authenticate(&bad, &peer),
            Err(ChainError::WrongPrevHash)
        );

        let stranger = IdentityKeypair::from_seed(&[6; 32]);
        let forged = SignedFrame::craft(
            &stranger,
            &sid(),
            Role::A,
            1,
            MessageType::Shot,
            &genesis(),
            vec![42],
        );
        assert_eq!(
            forged.authenticate(&expectation, &peer),
            Err(ChainError::BadSignature)
        );

        let head = frame.frame_hash();
        let second = SignedFrame::craft(
            &keypair(),
            &sid(),
            Role::B,
            2,
            MessageType::Shot,
            &head,
            vec![7],
        );
        second
            .clone()
            .authenticate(
                &ChainExpectation {
                    sid: sid(),
                    sequence: 2,
                    prev_hash: head,
                },
                &peer,
            )
            .unwrap();
        assert_eq!(
            frame.authenticate(
                &ChainExpectation {
                    sid: sid(),
                    sequence: 2,
                    prev_hash: head,
                },
                &peer
            ),
            Err(ChainError::WrongSequence {
                expected: 2,
                actual: 1
            })
        );
    }
}
