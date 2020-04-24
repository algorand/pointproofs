#![cfg_attr(feature = "cargo-clippy", allow(clippy::cognitive_complexity))]
#![cfg_attr(feature = "cargo-clippy", allow(clippy::missing_safety_doc))]
extern crate bigint;
extern crate ff_zeroize as ff;
extern crate pairing_plus as pairing;
extern crate pointproofs_paramgen;
extern crate sha2;
pub mod pairings;

#[cfg(test)]
mod test;
