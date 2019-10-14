use self::ciphersuite::Ciphersuite;
use pairing::bls12_381::*;

#[derive(Clone, Debug)]
pub struct SystemParam {
    ciphersuite: Ciphersuite,
    n: usize,
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
    ciphersuite: Ciphersuite,
    commit: G1,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Proof {
    ciphersuite: Ciphersuite,
    proof: G1,
}

// TODO: refactor what's public and what's not
/// pub mod c_api;
mod ciphersuite;
mod commit;
mod err;
mod paramgen;
mod prove;
mod proverparam;
mod verifierparam;
mod verify;

// pub use self::commit::commit;
// pub use self::commit::commit_update;
// pub use self::commit::convert_bytes_to_commitment;
// pub use self::commit::convert_commitment_to_bytes;
//pub use self::paramgen::paramgen_from_alpha;
pub use self::paramgen::paramgen_from_seed;
pub use self::prove::convert_bytes_to_proof;
pub use self::prove::convert_proof_to_bytes;
// pub use self::prove::proof_update;
// pub use self::prove::prove;
pub use self::prove::write_proof_into_slice;
// pub use self::verify::verify;

#[cfg(test)]
mod tests;
