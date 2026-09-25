//! Security-critical reference implementation; not independently audited.
//! Changes to parameter derivation, encodings, transcript order, game
//! functionals, session binding, or secret-side constant-time behavior need
//! cryptographic review and new vectors.

#![forbid(unsafe_code)]

pub mod answers;
pub mod bp;
pub mod fleet;
pub mod game;
pub mod params;
pub mod setup;
pub mod sigma;

#[cfg(test)]
mod coupling_tests;
#[cfg(test)]
mod game_proptest;
