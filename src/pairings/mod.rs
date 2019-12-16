pub use self::param::Ciphersuite;
use pairing::bls12_381::*;
use pairing::Engine;

// the groups are not switched
#[cfg(unswitch_group)]
pub type VeccomG1 = G1;
#[cfg(unswitch_group)]
pub type VeccomG2 = G2;
#[cfg(unswitch_group)]
pub type VeccomG1Affine = G1Affine;
#[cfg(unswitch_group)]
pub type VeccomG2Affine = G2Affine;
#[cfg(unswitch_group)]
pub(crate) fn veccom_pairing(p1: VeccomG1Affine, q1: VeccomG2Affine) -> Fq12 {
    Bls12::pairing(p1, q1)
}
#[cfg(unswitch_group)]
pub(crate) fn veccom_pairing_product(
    p1: VeccomG1Affine,
    q1: VeccomG2Affine,
    p2: VeccomG1Affine,
    q2: VeccomG2Affine,
) -> Fq12 {
    Bls12::pairing_product(p1, q1, p2, q2)
}
#[cfg(unswitch_group)]
pub(crate) fn veccom_pairing_multi_product(
    g1_vec: &[VeccomG1Affine],
    g2_vec: &[VeccomG2Affine],
) -> Fq12 {
    Bls12::pairing_multi_product(g1_vec, g2_vec)
}

// the groups are switched
#[cfg(not(unswitch_group))]
pub type VeccomG1 = G2;
#[cfg(not(unswitch_group))]
pub type VeccomG2 = G1;
#[cfg(not(unswitch_group))]
pub type VeccomG1Affine = G2Affine;
#[cfg(not(unswitch_group))]
pub type VeccomG2Affine = G1Affine;
#[cfg(not(unswitch_group))]
pub(crate) fn veccom_pairing(p1: VeccomG1Affine, q1: VeccomG2Affine) -> Fq12 {
    Bls12::pairing(q1, p1)
}
#[cfg(not(unswitch_group))]
pub(crate) fn veccom_pairing_product(
    p1: VeccomG1Affine,
    q1: VeccomG2Affine,
    p2: VeccomG1Affine,
    q2: VeccomG2Affine,
) -> Fq12 {
    Bls12::pairing_product(q1, p1, q2, p2)
}
#[cfg(not(unswitch_group))]
pub(crate) fn veccom_pairing_multi_product(
    g1_vec: &[VeccomG1Affine],
    g2_vec: &[VeccomG2Affine],
) -> Fq12 {
    Bls12::pairing_multi_product(g2_vec, g1_vec)
}

#[derive(Clone, Debug)]
pub struct ProverParams {
    pub(crate) ciphersuite: Ciphersuite,
    pub(crate) n: usize,
    generators: Vec<VeccomG1Affine>,
    pp_len: usize,
    precomp: Vec<VeccomG1Affine>,
}
// ciphersuite (1 byte) + n (8 bytes) + 2n * G2 (96 bytes) + pp_len (8 bytes)
pub const RAW_PP_LEN: usize = 196_625; // n = 1024

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
