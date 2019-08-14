use pairing::{bls12_381::*, CurveAffine, CurveProjective, EncodedPoint};
use ff::{Field,PrimeField};
use super::ProverParams;

/**
 * Assumes prover_params are correctly generated for n = values.len
 */
pub fn commit(prover_params: &ProverParams, values: &[&[u8]]) -> G1 {
    let n = values.len();
    let scalars_fr_repr:Vec<FrRepr> = values.iter().map(|s| Fr::hash_to_fr(s).into_repr()).collect();
    let scalars_u64:Vec<&[u64]> = scalars_fr_repr.iter().map(|s| s.as_ref()).collect();
    if prover_params.precomp.len() == 512*n {
        G1Affine::sum_of_products_precomp_256(&prover_params.generators[0..n], &scalars_u64, &prover_params.precomp)
    }
    else {
        G1Affine::sum_of_products(&prover_params.generators[0..n], &scalars_u64)
    }
}


/**
 * Assumes prover_params are correctly generated for n such that changed_index<n
 */
pub fn commit_update(prover_params: &ProverParams, com : &G1, changed_index : usize, value_before : &[u8], value_after : &[u8]) -> G1 {
    let mut multiplier = Fr::hash_to_fr(&value_before);
    multiplier.negate();
    multiplier.add_assign(&Fr::hash_to_fr(&value_after));

    let res = 
    if prover_params.precomp.len() == 3*prover_params.generators.len() {
        prover_params.generators[changed_index].mul_precomp_3(multiplier, &prover_params.precomp[changed_index*3..(changed_index+1)*3])
    }
    else if prover_params.precomp.len() == 256*prover_params.generators.len() {
         prover_params.generators[changed_index].mul_precomp_256(multiplier, &prover_params.precomp[changed_index*256..(changed_index+1)*256])
    }
    else {
        prover_params.generators[changed_index].mul(multiplier)
    };

    let mut new_com = *com;
    new_com.add_assign(&res);
    new_com
}


/**
 * convert a commitment (which is a projective G1 element) into a string of 48 bytes
 * Copied from the bls library
 */
pub fn convert_commitment_to_bytes (commitment: &G1) -> [u8; 48] {
    let s = pairing::bls12_381::G1Compressed::from_affine(commitment.into_affine());
    let mut out: [u8; 48] = [0; 48];
    out.copy_from_slice(s.as_ref());
    out
}
  
/** 
 * Take an array of 48 bytes and output a commitment
 * Copied from the bls library
 * In case bytes don't convert to a meaningful element of G1, defaults to the group generator
 */
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

#[cfg(test)]
/**
 * Updates the commitment to commit to a value whose hash is 0 in changed_index
 * Needed for testing only (in order to test verify, which handles the case of hash ==  0 separately)
 * Assumes prover_params are correctly generated for n such that changed_index<n
 */
pub fn update_to_zero_hash(prover_params: &ProverParams, com : &G1, changed_index : usize, value_before : &[u8]) -> G1 {
    let mut multiplier = Fr::hash_to_fr(&value_before);
    multiplier.negate();

    let res = 
    if prover_params.precomp.len() == 3*prover_params.generators.len() {
        prover_params.generators[changed_index].mul_precomp_3(multiplier, &prover_params.precomp[changed_index*3..(changed_index+1)*3])
    }
    else if prover_params.precomp.len() == 256*prover_params.generators.len() {
         prover_params.generators[changed_index].mul_precomp_256(multiplier, &prover_params.precomp[changed_index*256..(changed_index+1)*256])
    }
    else {
        prover_params.generators[changed_index].mul(multiplier)
    };

    let mut new_com = *com;
    new_com.add_assign(&res);
    new_com
}
