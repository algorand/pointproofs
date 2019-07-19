use pairing::{bls12_381::*, CurveAffine, CurveProjective, EncodedPoint};
use ff::{Field,PrimeField};
use super::ProverParams;

pub fn commit(prover_params: &ProverParams, values: &[&[u8]]) -> G1 {
    // TODO: error handling if the prover params length is not double values length
    let n = values.len();
    let scalars_fr_repr:Vec<FrRepr> = values.iter().map(|s| Fr::hash_to_fr(s).into_repr()).collect();
    let scalars_u64:Vec<&[u64]> = scalars_fr_repr.iter().map(|s| s.as_ref()).collect();
    G1::sum_of_products(&prover_params.generators[0..n], &scalars_u64)
}


pub fn commit_update(prover_params: &ProverParams, com : &G1, changed_index : usize, value_before : &[u8], value_after : &[u8]) -> G1 {
    let mut multiplier = Fr::hash_to_fr(&value_before);
    multiplier.negate();
    multiplier.add_assign(&Fr::hash_to_fr(&value_after));

    let mut param_i = prover_params.generators[changed_index];
    param_i.mul_assign(multiplier);

    let mut new_com = *com;
    new_com.add_assign(&param_i);
    new_com
}

// convert a commitment (which is a projective G1 element) into a string of 48 bytes
// Copied from the bls library
pub fn convert_commitment_to_bytes (commitment: &G1) -> [u8; 48] {
    let s = pairing::bls12_381::G1Compressed::from_affine(commitment.into_affine());
    let mut out: [u8; 48] = [0; 48];
    out.copy_from_slice(s.as_ref());
    out
}
  
// take an array of 48 bytes and output a commitment
// Copied from the bls library
// In case bytes don't convert to a meaningful element of G1, defaults to the group generator
pub fn convert_bytes_to_commitment (input : &[u8; 48]) -> G1 {
    let mut commitment_compressed = G1Compressed::empty();
    commitment_compressed
        .as_mut()
        .copy_from_slice(input);
    match commitment_compressed.into_affine() {
        Ok(commitment_affine) => commitment_affine.into_projective(),
        Err(_) => G1::zero()
    }
}
