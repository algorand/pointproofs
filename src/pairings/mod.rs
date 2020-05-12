//! this file is part of the pointproofs,
//! a pairing based vector commitment scheme, implemented with BLS12-381 curve.

use self::param::Ciphersuite;
use self::pointproofs_groups::*;
use pairing::bls12_381::*;

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
pub mod pointproofs_groups;

//mod c_api;
pub(crate) mod c_api;
mod err;
mod misc;
mod serdes;
