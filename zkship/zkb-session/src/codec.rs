//! Canonical wire codec. Every structural check runs before any allocation or group
//! arithmetic; no input may panic.

use std::fmt;
use zkb_core::wf::{UnverifiedBoardCommitment, WfProof};

/// Bounds all allocations; the largest legitimate frame is `Commit`: 78 + 107,072 + 64 = 107,214.
pub const MAX_FRAME_SIZE: usize = 128 * 1024;

/// `sid[32] || sender_role u8 || sequence u64 LE || message_type u8 || prev_hash[32] || payload_len u32 LE`.
pub const HEADER_LEN: usize = 32 + 1 + 8 + 1 + 32 + 4;

pub const SIGNATURE_LEN: usize = 64;

/// `E` (760 * 32 = 24,320) || proof (82,752) = 107,072.
pub const COMMIT_PAYLOAD_LEN: usize = UnverifiedBoardCommitment::ENCODED_LEN + WfProof::ENCODED_LEN;

pub const COMMIT_ENTRY_LEN: usize = UnverifiedBoardCommitment::ENCODED_LEN;

pub const COIN_PAYLOAD_LEN: usize = 32;

pub const SHOT_PAYLOAD_LEN: usize = 1;

pub const ANSWER_MISS_LEN: usize = zkb_core::openings::ShotAnswer::MISS_LEN;

pub const ANSWER_HIT_LEN: usize = zkb_core::openings::ShotAnswer::HIT_LEN;

/// Wire discriminants. Payload sizes: Commit 107,072; coin messages 32; Shot 1 (cell index);
/// Answer 33 (`b = 0`) or 165 (`b = 1`), implied by the first payload byte; Resign 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageType {
    Commit = 1,
    CoinCommit = 2,
    CoinNonce = 3,
    CoinReveal = 4,
    Shot = 5,
    Answer = 6,
    Resign = 7,
}

impl MessageType {
    pub fn from_u8(v: u8) -> Option<MessageType> {
        match v {
            1 => Some(MessageType::Commit),
            2 => Some(MessageType::CoinCommit),
            3 => Some(MessageType::CoinNonce),
            4 => Some(MessageType::CoinReveal),
            5 => Some(MessageType::Shot),
            6 => Some(MessageType::Answer),
            7 => Some(MessageType::Resign),
            _ => None,
        }
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// For `Answer`, header length, actual length, and `b`-implied length must all agree
    /// before any group arithmetic.
    pub fn check_payload(self, payload: &[u8]) -> Result<(), CodecError> {
        let expected = match self {
            MessageType::Commit => COMMIT_PAYLOAD_LEN,
            MessageType::CoinCommit | MessageType::CoinNonce | MessageType::CoinReveal => {
                COIN_PAYLOAD_LEN
            }
            MessageType::Shot => SHOT_PAYLOAD_LEN,
            MessageType::Resign => 0,
            MessageType::Answer => match payload.first() {
                Some(&0) => ANSWER_MISS_LEN,
                Some(&1) => ANSWER_HIT_LEN,
                Some(&b) => return Err(CodecError::InvalidAnswerFlag(b)),
                None => ANSWER_MISS_LEN,
            },
        };
        if payload.len() != expected {
            return Err(CodecError::WrongPayloadLength {
                message_type: self,
                expected,
                actual: payload.len(),
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CodecError {
    FrameTooSmall {
        actual: usize,
    },
    FrameTooLarge {
        actual: usize,
    },
    LengthMismatch {
        declared: u32,
        actual: usize,
    },
    UnknownMessageType(u8),
    WrongPayloadLength {
        message_type: MessageType,
        expected: usize,
        actual: usize,
    },
    InvalidAnswerFlag(u8),
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CodecError::FrameTooSmall { actual } => {
                write!(
                    f,
                    "frame is {actual} bytes, smaller than header + signature"
                )
            }
            CodecError::FrameTooLarge { actual } => {
                write!(
                    f,
                    "frame is {actual} bytes, exceeding the {MAX_FRAME_SIZE}-byte maximum"
                )
            }
            CodecError::LengthMismatch { declared, actual } => {
                write!(
                    f,
                    "header declares {declared} payload bytes but {actual} are present"
                )
            }
            CodecError::UnknownMessageType(v) => write!(f, "unknown message type {v}"),
            CodecError::WrongPayloadLength {
                message_type,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "{message_type:?} payload is {actual} bytes, expected {expected}"
                )
            }
            CodecError::InvalidAnswerFlag(b) => {
                write!(f, "answer payload starts with b = {b}, expected 0 or 1")
            }
        }
    }
}

impl std::error::Error for CodecError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_payload_len_matches_spec() {
        const _: () = assert!(HEADER_LEN + COMMIT_PAYLOAD_LEN + SIGNATURE_LEN <= MAX_FRAME_SIZE);
        assert_eq!(COMMIT_PAYLOAD_LEN, 107_072);
        assert_eq!(HEADER_LEN, 78);
    }

    #[test]
    fn message_type_roundtrip() {
        for v in 1..=7u8 {
            let mt = MessageType::from_u8(v).unwrap();
            assert_eq!(mt.to_u8(), v);
        }
        assert_eq!(MessageType::from_u8(0), None);
        assert_eq!(MessageType::from_u8(8), None);
    }

    #[test]
    fn payload_size_rules() {
        assert!(MessageType::Commit
            .check_payload(&vec![0u8; COMMIT_PAYLOAD_LEN])
            .is_ok());
        assert!(matches!(
            MessageType::Commit.check_payload(&[0u8; 32]),
            Err(CodecError::WrongPayloadLength { .. })
        ));
        assert!(MessageType::CoinCommit.check_payload(&[0u8; 32]).is_ok());
        assert!(MessageType::Shot.check_payload(&[7]).is_ok());
        assert!(MessageType::Resign.check_payload(&[]).is_ok());
        assert!(matches!(
            MessageType::Resign.check_payload(&[0]),
            Err(CodecError::WrongPayloadLength { .. })
        ));

        assert!(MessageType::Answer
            .check_payload(&[0u8; ANSWER_MISS_LEN])
            .is_ok());
        let mut hit = vec![0u8; ANSWER_HIT_LEN];
        hit[0] = 1;
        assert!(MessageType::Answer.check_payload(&hit).is_ok());
        assert!(matches!(
            MessageType::Answer.check_payload(&hit[..ANSWER_MISS_LEN]),
            Err(CodecError::WrongPayloadLength { .. })
        ));
        let mut bad = vec![0u8; ANSWER_MISS_LEN];
        bad[0] = 2;
        assert_eq!(
            MessageType::Answer.check_payload(&bad),
            Err(CodecError::InvalidAnswerFlag(2))
        );
        assert!(matches!(
            MessageType::Answer.check_payload(&[]),
            Err(CodecError::WrongPayloadLength { .. })
        ));
    }
}
