use self::ciphersuite::Ciphersuite;
use pairing::bls12_381::*;

type VeccomG1 = G2;
type VeccomG2 = G1;
type VeccomG1Affine = G2Affine;
type VeccomG2Affine = G1Affine;

#[derive(Clone, Debug)]
pub struct ProverParams {
    pub ciphersuite: Ciphersuite,
    pub n: usize,
    pub generators: Vec<VeccomG1Affine>,
    pub pp_len: usize,
    pub precomp: Vec<VeccomG1Affine>,
}
#[derive(Clone, Debug)]
pub struct VerifierParams {
    ciphersuite: Ciphersuite,
    pub n: usize,
    generators: Vec<VeccomG2Affine>,
    gt_elt: Fq12,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Commitment {
    pub ciphersuite: Ciphersuite,
    pub commit: VeccomG1,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Proof {
    ciphersuite: Ciphersuite,
    proof: VeccomG1,
}

// TODO: refactor what's public and what's not
pub mod c_api;
pub mod ciphersuite;
pub mod commit;
mod err;
pub mod hash_to_field_veccom;
pub mod paramgen;
pub mod prove;
mod proverparam;
mod verifierparam;


pub use self::paramgen::paramgen_from_seed;
