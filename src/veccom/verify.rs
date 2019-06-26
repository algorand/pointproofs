use pairing::{bls12_381::*, CurveProjective, Engine};
use ff::Field;

pub fn verify(g2_vec: &[G2], gt_verifier_value: &Fq12, com : &G1, proof : &G1, value : &[u8], index : usize) -> bool {
    let hash = Fr::hash_to_fr(value);
    let hash_inverse = hash.inverse().unwrap();
    let mut com_mut = *com;
    com_mut.mul_assign(hash_inverse);
    let lhs = Bls12::pairing(com_mut, g2_vec[g2_vec.len()-index-1]);
    let mut rhs = *gt_verifier_value;
    let mut proof_mut = *proof;
    proof_mut.mul_assign(hash_inverse);
    rhs.mul_assign(&Bls12::pairing(proof_mut, G2::one()));
    lhs == rhs
}
  