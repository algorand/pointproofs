use pairing::{bls12_381::*, CurveAffine, CurveProjective, EncodedPoint};
use ff::{Field,PrimeField};
use super::ProverParams;

/**
 * Assumes prover_params are correctly generated for n = values.len and that index<n
 */
pub fn prove(prover_params: &ProverParams, values: &[&[u8]], index : usize) -> G1 {
    let n = values.len();
    let scalars_fr_repr:Vec<FrRepr> = values.iter().map(|s| Fr::hash_to_fr(s).into_repr()).collect();
    let scalars_u64:Vec<&[u64;4]> = scalars_fr_repr.iter().map(|s| &s.0).collect();
    if prover_params.precomp.len() == 512*n {
        G1Affine::sum_of_products_precomp_256(&prover_params.generators[n-index..2*n-index], &scalars_u64, &prover_params.precomp[(n-index)*256..(2*n-index)*256])
    }
    else {
        G1Affine::sum_of_products(&prover_params.generators[n-index..2*n-index], &scalars_u64)
    }
}
  

/**
 * For updating your proof when someone else's value changes
 * Not for updating your own proof when your value changes -- because then the proof does not change!
 * Assumes prover_params are correctly generated for n such that changed_index<n and proof_index<n
 */  
pub fn proof_update(prover_params: &ProverParams, proof : &G1, proof_index : usize, changed_index : usize, value_before : &[u8], value_after : &[u8]) -> G1 {
  
    let mut new_proof = *proof;
  
    if proof_index==changed_index {
        new_proof
    }

    else {
        let n = prover_params.generators.len()/2;

        let mut multiplier = Fr::hash_to_fr(&value_before);
        multiplier.negate();
        multiplier.add_assign(&Fr::hash_to_fr(&value_after));

        let param_index = changed_index+n-proof_index;

        let res = 
        if prover_params.precomp.len() == 6*n {
            prover_params.generators[param_index].mul_precomp_3(multiplier, &prover_params.precomp[param_index*3..(param_index+1)*3])
        }
        else if prover_params.precomp.len() == 512*n {
            prover_params.generators[param_index].mul_precomp_256(multiplier, &prover_params.precomp[param_index*256..(param_index+1)*256])
        }
        else {
            prover_params.generators[param_index].mul(multiplier)
        };

        new_proof.add_assign(&res);
        new_proof
    }
}

/**
 *  write a proof (which is a projective G1 element) into a 48-byte slice
 */
pub fn write_proof_into_slice(proof: &G1, out: &mut [u8]) {
    let s = pairing::bls12_381::G1Compressed::from_affine(proof.into_affine());
    out.copy_from_slice(s.as_ref());
}

/**
 * Write a proof (which is a projective G1 element) into a 48-byte slice
 * Copied from the bls library
 */
pub fn convert_proof_to_bytes (proof: &G1) -> [u8; 48] {
    let s = pairing::bls12_381::G1Compressed::from_affine(proof.into_affine());
    let mut out: [u8; 48] = [0; 48];
    out.copy_from_slice(s.as_ref());
    out
}
  
/**
 * take an array of 48 bytes and output a proof
 * Copied from the bls library
 * In case bytes don't convert to a meaningful element of G1, defaults to the group generator
 */
pub fn convert_bytes_to_proof (input : &[u8]) -> G1 {
    let mut proof_compressed = G1Compressed::empty();
    proof_compressed
        .as_mut()
        .copy_from_slice(input);
    match proof_compressed.into_affine() {
        Ok(proof_affine) => proof_affine.into_projective(),
        Err(_) => G1::zero()
    }

}

