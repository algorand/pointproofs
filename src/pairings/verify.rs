use pairing::{bls12_381::*, CurveProjective, Engine};
use ff::Field;
use super::VerifierParams;


pub fn verify(verifier_params : &VerifierParams, com : &G1, proof : &G1, value : &[u8], index : usize) -> bool {
    let hash = Fr::hash_to_fr(value);
    let hash_inverse = hash.inverse().unwrap(); // TODO: what if this unwrap fails? Should be very unlikely, but still...
    let mut com_mut = *com;
    com_mut.mul_assign(hash_inverse);
    let n = verifier_params.generators.len();
    let lhs = Bls12::pairing(com_mut, verifier_params.generators[n-index-1]);
    let mut rhs = verifier_params.gt_elt;
    let mut proof_mut = *proof;
    proof_mut.mul_assign(hash_inverse);
    rhs.mul_assign(&Bls12::pairing(proof_mut, G2::one()));
    lhs == rhs
}
  