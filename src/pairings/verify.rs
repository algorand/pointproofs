use pairing::{bls12_381::*, CurveProjective, Engine};
use ff::Field;
use super::VerifierParams;


pub fn verify(verifier_params : &VerifierParams, com : &G1, proof : &G1, value : &[u8], index : usize) -> bool {
    let hash = Fr::hash_to_fr(value);
    let hash_inverse = hash.inverse().unwrap(); // TODO: what if this unwrap fails? Should be very unlikely, but still...
    let mut com_mut = *com;
    com_mut.mul_assign(hash_inverse);
    let n = verifier_params.generators.len();
    let mut proof_mut = *proof;
    proof_mut.mul_assign(hash_inverse);
    proof_mut.negate();
    Bls12::pairing_product(com_mut, verifier_params.generators[n-index-1], proof_mut, G2::one())==verifier_params.gt_elt

}
  