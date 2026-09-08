//! Security-critical reference implementation; not independently audited.
//! Changes to parameter derivation, encodings, transcript order, game
//! functionals, session binding, or secret-side constant-time behavior need
//! cryptographic review and new vectors.

#![forbid(unsafe_code)]

pub mod game;
pub mod openings;
pub mod params;
pub mod pedersen;
pub mod sigma;
pub mod wf;

#[cfg(test)]
mod coupling_tests;
#[cfg(test)]
mod game_proptest;
