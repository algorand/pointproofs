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
// ciphersuite (1 byte) + n (8 bytes) + 2n * G2 (96 bytes) + pp_len (8 bytes)
pub const RAW_PP_LEN: usize = 196625; // n = 1024

#[derive(Clone, Debug)]
pub struct VerifierParams {
    pub(crate) ciphersuite: Ciphersuite,
    pub(crate) n: usize,
    generators: Vec<VeccomG2Affine>,
    gt_elt: Fq12,
}

// ciphersuite (1 byte) + n (8 bytes) + n * G1 (48 bytes) + Gt (576 bytes)
pub const VP_LEN: usize = 49737; // n = 1024

#[derive(Clone, Debug, PartialEq)]
pub struct Commitment {
    pub(crate) ciphersuite: Ciphersuite,
    pub(crate) commit: VeccomG1,
}

pub const COMMIT_LEN: usize = 97;

#[derive(Clone, Debug, PartialEq)]
pub struct Proof {
    pub(crate) ciphersuite: Ciphersuite,
    pub(crate) proof: VeccomG1,
}

pub const PROOF_LEN: usize = 97;

pub mod commit;
pub mod param;
pub mod prove;

pub(crate) mod hash_to_field_veccom;

//mod c_api;
mod err;
mod serdes;
