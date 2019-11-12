use self::ciphersuite::Ciphersuite;
use pairing::bls12_381::*;

#[derive(Clone, Debug)]
pub struct SystemParam {
    ciphersuite: Ciphersuite,
    pub n: usize,
    pp_len: usize,
}

#[derive(Clone, Debug)]
pub struct ProverParams {
    ciphersuite: Ciphersuite,
    pub generators: Vec<G1Affine>,
    pub precomp: Vec<G1Affine>,
}
#[derive(Clone, Debug)]
pub struct VerifierParams {
    ciphersuite: Ciphersuite,
    generators: Vec<G2Affine>,
    gt_elt: Fq12,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Commitment {
    pub ciphersuite: Ciphersuite,
    pub commit: G1,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Proof {
    ciphersuite: Ciphersuite,
    proof: G1,
}

// TODO: refactor what's public and what's not
pub mod c_api;
pub mod ciphersuite;
pub mod commit;
mod err;
pub mod hash_to_field_veccom;
mod paramgen;
pub mod prove;
mod proverparam;
mod verifierparam;
mod verify;

pub use self::paramgen::paramgen_from_seed;

#[cfg(test)]
mod tests;
