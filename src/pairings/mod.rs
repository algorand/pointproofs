//! A pairing based vector commitment scheme, implemented with BLS12-381 curve.

use self::param::Ciphersuite;
use pairing::bls12_381::*;
use pairing::Engine;

// Uncomment the following if we want the proofs/commits lie in BLS12::G1
// the groups are not switched
/*
/// A wrapper of BLS::G1. Groups are not switched and proof/commits are in BLS::G1
pub type VeccomG1 = G1;
/// A wrapper of BLS::G2. Groups are not switched and proof/commits are in BLS::G1
pub type VeccomG2 = G2;
/// A wrapper of BLS::G1Affine. Groups are not switched and proof/commits are in BLS::G1
pub type VeccomG1Affine = G1Affine;
/// A wrapper of BLS::G2Affine. Groups are not switched and proof/commits are in BLS::G1
pub type VeccomG2Affine = G2Affine;
/// A wrapper of BLS::pairing_product. Groups are switched and proof/commits are in BLS::G1
pub(crate) fn veccom_pairing(p1: VeccomG1Affine, q1: VeccomG2Affine) -> Fq12 {
    Bls12::pairing(p1, q1)
}
/// A wrapper of BLS::pairing_product. Groups are switched and proof/commits are in BLS::G1
pub(crate) fn veccom_pairing_product(
    p1: VeccomG1Affine,
    q1: VeccomG2Affine,
    p2: VeccomG1Affine,
    q2: VeccomG2Affine,
) -> Fq12 {
    Bls12::pairing_product(p1, q1, p2, q2)
}
/// A wrapper of BLS::pairing_multi_product. Groups are switched and proof/commits are in BLS::G1
pub(crate) fn veccom_pairing_multi_product(
    g1_vec: &[VeccomG1Affine],
    g2_vec: &[VeccomG2Affine],
) -> Fq12 {
    Bls12::pairing_multi_product(g1_vec, g2_vec)
}
*/

// the groups are switched
/// A wrapper of BLS::G2. Groups are switched and proof/commits are in BLS::G2
pub type VeccomG1 = G2;
/// A wrapper of BLS::G1. Groups are switched and proof/commits are in BLS::G2
pub type VeccomG2 = G1;
/// A wrapper of BLS::G2Affine. Groups are switched and proof/commits are in BLS::G2
pub type VeccomG1Affine = G2Affine;
/// A wrapper of BLS::G1Affine. Groups are switched and proof/commits are in BLS::G2
pub type VeccomG2Affine = G1Affine;
/// A wrapper of BLS::pairing. Groups are switched and proof/commits are in BLS::G2
pub(crate) fn veccom_pairing(p1: VeccomG1Affine, q1: VeccomG2Affine) -> Fq12 {
    Bls12::pairing(q1, p1)
}
/// A wrapper of BLS::pairing_product. Groups are switched and proof/commits are in BLS::G2
pub(crate) fn veccom_pairing_product(
    p1: VeccomG1Affine,
    q1: VeccomG2Affine,
    p2: VeccomG1Affine,
    q2: VeccomG2Affine,
) -> Fq12 {
    Bls12::pairing_product(q1, p1, q2, p2)
}
/// A wrapper of BLS::pairing_multi_product. Groups are switched and proof/commits are in BLS::G2
pub(crate) fn veccom_pairing_multi_product(
    g1_vec: &[VeccomG1Affine],
    g2_vec: &[VeccomG2Affine],
) -> Fq12 {
    Bls12::pairing_multi_product(g2_vec, g1_vec)
}

/// Structure for porver parameters.
#[derive(Clone, Debug)]
pub struct ProverParams {
    pub(crate) ciphersuite: Ciphersuite,
    pub(crate) n: usize,
    generators: Vec<VeccomG1Affine>,
    pp_len: usize,
    precomp: Vec<VeccomG1Affine>,
}
/// Size for serialized prover parameter:
/// ciphersuite `(1 byte) + n (8 bytes) + 2n * G2 (96 bytes) + pp_len (8 bytes)`.
/// Does not include the size for pre-computed parameters.
pub const RAW_PP_LEN: usize = 196_625; // n = 1024

/// Structure for verifier parameters.
#[derive(Clone, Debug)]
pub struct VerifierParams {
    pub(crate) ciphersuite: Ciphersuite,
    pub(crate) n: usize,
    generators: Vec<VeccomG2Affine>,
    pp_len: usize,
    precomp: Vec<VeccomG2Affine>,
    gt_elt: Fq12,
}
/// Size for serialized verifier parameter:
/// ciphersuite `(1 byte) + n (8 bytes) + n * G1 (48 bytes) + pp_len (8 bytes) + Gt (576 bytes)`
pub const VP_LEN: usize = 49745; // n = 1024

/// Structure to hold a commitment.
#[derive(Clone, Debug, PartialEq)]
pub struct Commitment {
    pub(crate) ciphersuite: Ciphersuite,
    pub(crate) commit: VeccomG1,
}
/// Size for serialized commitment.
pub const COMMIT_LEN: usize = 97;

/// Structure to hold a proof.
#[derive(Clone, Debug, PartialEq)]
pub struct Proof {
    pub(crate) ciphersuite: Ciphersuite,
    pub(crate) proof: VeccomG1,
}
/// Size for serialized proof.
pub const PROOF_LEN: usize = 97;

pub(crate) mod commit;
pub mod param;
pub(crate) mod prove;

pub(crate) mod hash_to_field_veccom;

//mod c_api;
pub(crate) mod c_api;
mod err;
mod misc;
mod serdes;
