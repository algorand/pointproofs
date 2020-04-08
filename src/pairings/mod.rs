//! this file is part of the pointproofs,
//! a pairing based vector commitment scheme, implemented with BLS12-381 curve.

use self::param::Ciphersuite;
use pairing::bls12_381::*;
use pairing::Engine;

// Uncomment the following if we want the proofs/commits lie in BLS12::G1
// the groups are not switched

/// A wrapper of BLS::G1. Groups are not switched and proof/commits are in BLS::G1
pub type PointproofsG1 = G1;
/// A wrapper of BLS::G2. Groups are not switched and proof/commits are in BLS::G1
pub type PointproofsG2 = G2;
/// A wrapper of BLS::G1Affine. Groups are not switched and proof/commits are in BLS::G1
pub type PointproofsG1Affine = G1Affine;
/// A wrapper of BLS::G2Affine. Groups are not switched and proof/commits are in BLS::G1
pub type PointproofsG2Affine = G2Affine;
pub const POINTPROOFSG1_LEN: usize = 48;
pub const POINTPROOFSG2_LEN: usize = 96;

/// A wrapper of BLS::pairing_product. Groups are switched and proof/commits are in BLS::G1
pub(crate) fn pointproofs_pairing(p1: PointproofsG1Affine, q1: PointproofsG2Affine) -> Fq12 {
    Bls12::pairing(p1, q1)
}
/// A wrapper of BLS::pairing_product. Groups are switched and proof/commits are in BLS::G1
pub(crate) fn pointproofs_pairing_product(
    p1: PointproofsG1Affine,
    q1: PointproofsG2Affine,
    p2: PointproofsG1Affine,
    q2: PointproofsG2Affine,
) -> Fq12 {
    Bls12::pairing_product(p1, q1, p2, q2)
}
/// A wrapper of BLS::pairing_multi_product. Groups are switched and proof/commits are in BLS::G1
pub(crate) fn pointproofs_pairing_multi_product(
    g1_vec: &[PointproofsG1Affine],
    g2_vec: &[PointproofsG2Affine],
) -> Fq12 {
    Bls12::pairing_multi_product(g1_vec, g2_vec)
}
/// Size for serialized verifier parameter:
/// ciphersuite `(1 byte) + n (4 bytes) + n * G2 (96 bytes) + pp_len (4 bytes) + Gt (576 bytes)`
pub const VP_LEN: usize = 98889; // n = 1024
/// Size for serialized prover parameter:
/// ciphersuite `(1 byte) + n (4 bytes) + 2n * G1 (48 bytes) + pp_len (4 bytes)`.
/// Does not include the size for pre-computed parameters.
pub const PP_LEN: usize = 98313; // n = 1024

/// Size for serialized commitment.
pub const COMMIT_LEN: usize = 49;

/// Size for serialized proof.
pub const PROOF_LEN: usize = 49;

// Uncomment the following if we want the proofs/commits lie in BLS12::G2
// the groups are switched
/*
// the groups are switched
/// A wrapper of BLS::G2. Groups are switched and proof/commits are in BLS::G2
pub type PointproofsG1 = G2;
/// A wrapper of BLS::G1. Groups are switched and proof/commits are in BLS::G2
pub type PointproofsG2 = G1;
/// A wrapper of BLS::G2Affine. Groups are switched and proof/commits are in BLS::G2
pub type PointproofsG1Affine = G2Affine;
/// A wrapper of BLS::G1Affine. Groups are switched and proof/commits are in BLS::G2
pub type PointproofsG2Affine = G1Affine;

pub const POINTPROOFSG1_LEN: usize = 96;
pub const POINTPROOFSG2_LEN: usize = 48;

/// A wrapper of BLS::pairing. Groups are switched and proof/commits are in BLS::G2
pub(crate) fn pointproofs_pairing(p1: PointproofsG1Affine, q1: PointproofsG2Affine) -> Fq12 {
    Bls12::pairing(q1, p1)
}
/// A wrapper of BLS::pairing_product. Groups are switched and proof/commits are in BLS::G2
pub(crate) fn pointproofs_pairing_product(
    p1: PointproofsG1Affine,
    q1: PointproofsG2Affine,
    p2: PointproofsG1Affine,
    q2: PointproofsG2Affine,
) -> Fq12 {
    Bls12::pairing_product(q1, p1, q2, p2)
}
/// A wrapper of BLS::pairing_multi_product. Groups are switched and proof/commits are in BLS::G2
pub(crate) fn pointproofs_pairing_multi_product(
    g1_vec: &[PointproofsG1Affine],
    g2_vec: &[PointproofsG2Affine],
) -> Fq12 {
    Bls12::pairing_multi_product(g2_vec, g1_vec)
}
/// Size for serialized verifier parameter:
/// ciphersuite `(1 byte) + n (4 bytes) + n * G1 (48 bytes) + pp_len (4 bytes) + Gt (576 bytes)`
pub const VP_LEN: usize = 49737; // n = 1024

/// Size for serialized prover parameter:
/// ciphersuite `(1 byte) + n (4 bytes) + 2n * G2 (96 bytes) + pp_len (4 bytes)`.
/// Does not include the size for pre-computed parameters.
pub const PP_LEN: usize = 196_617; // n = 1024

/// Size for serialized commitment.
pub const COMMIT_LEN: usize = 97;

/// Size for serialized proof.
pub const PROOF_LEN: usize = 97;
*/

/// Structure for porver parameters.
#[derive(Clone, Debug)]
pub struct ProverParams {
    pub(crate) ciphersuite: Ciphersuite,
    pub(crate) n: usize,
    generators: Vec<PointproofsG1Affine>,
    pp_len: usize,
    precomp: Vec<PointproofsG1Affine>,
}

/// Structure for verifier parameters.
#[derive(Clone, Debug)]
pub struct VerifierParams {
    pub(crate) ciphersuite: Ciphersuite,
    pub(crate) n: usize,
    generators: Vec<PointproofsG2Affine>,
    pp_len: usize,
    precomp: Vec<PointproofsG2Affine>,
    gt_elt: Fq12,
}

/// Structure to hold a commitment.
#[derive(Clone, Debug, PartialEq)]
pub struct Commitment {
    pub(crate) ciphersuite: Ciphersuite,
    pub(crate) commit: PointproofsG1,
}

/// Structure to hold a proof.
#[derive(Clone, Debug, PartialEq)]
pub struct Proof {
    pub(crate) ciphersuite: Ciphersuite,
    pub(crate) proof: PointproofsG1,
}

pub(crate) mod commit;
pub mod param;
pub(crate) mod prove;

pub(crate) mod hash_to_field_pointproofs;

//mod c_api;
pub(crate) mod c_api;
mod err;
mod misc;
mod serdes;
