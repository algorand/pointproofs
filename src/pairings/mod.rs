pub use self::param::Ciphersuite;
use pairing::bls12_381::*;

pub type VeccomG1 = G2;
pub type VeccomG2 = G1;
pub type VeccomG1Affine = G2Affine;
pub type VeccomG2Affine = G1Affine;

#[derive(Clone, Debug)]
pub struct ProverParams {
    pub(crate) ciphersuite: Ciphersuite,
    pub(crate) n: usize,
    generators: Vec<VeccomG1Affine>,
    pp_len: usize,
    precomp: Vec<VeccomG1Affine>,
}
#[derive(Clone, Debug)]
pub struct VerifierParams {
    pub(crate) ciphersuite: Ciphersuite,
    pub(crate) n: usize,
    generators: Vec<VeccomG2Affine>,
    gt_elt: Fq12,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Commitment {
    ciphersuite: Ciphersuite,
    commit: VeccomG1,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Proof {
    ciphersuite: Ciphersuite,
    proof: VeccomG1,
}

pub mod commit;
pub mod param;
pub mod prove;

pub(crate) mod hash_to_field_veccom;

mod c_api;
mod err;
mod serdes;
