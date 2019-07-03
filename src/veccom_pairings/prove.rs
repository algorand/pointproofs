use pairing::{bls12_381::*, CurveAffine, CurveProjective, EncodedPoint};
use ff::Field;
use super::ProverParams;

pub fn prove(prover_params: &ProverParams, values: &[&[u8]], index : usize) -> G1 {
    // TODO: error handling if the prover params length is not double values length
    // TODO: figure out if the input for values is the right one to use
    let n = values.len();
    let mut proof = G1::zero();

    // prover_params[n] is useless and we should never index it
    for i in 0..index {
        let mut param_i = prover_params.generators[i+n-index]; // note that i+n-index < n
        param_i.mul_assign(Fr::hash_to_fr(&values[i]));
        proof.add_assign(&param_i);
    }
    for i in index+1..n {
        let mut param_i = prover_params.generators[i+n-index]; // note that i+n-index > n
        param_i.mul_assign(Fr::hash_to_fr(&values[i]));
        proof.add_assign(&param_i);
    }
    proof
}
  

// For updating your proof when someone else's value changes
// Not for updating your own proof when your value changes -- because then the proof does not change!
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

        let mut changed_param = prover_params.generators[changed_index+n-proof_index];
        changed_param.mul_assign(multiplier);

        new_proof.add_assign(&changed_param);
        new_proof
    }
}

// write a proof (which is a projective G1 element) into a 48-byte slice
pub fn write_proof_into_slice(proof: &G1, out: &mut [u8]) {
    let s = pairing::bls12_381::G1Compressed::from_affine(proof.into_affine());
    out.copy_from_slice(s.as_ref());
}

// convert a proof (which is a projective G1 element) into a string of 48 bytes
// Copied from the bls library
pub fn convert_proof_to_bytes (proof: &G1) -> [u8; 48] {
    let s = pairing::bls12_381::G1Compressed::from_affine(proof.into_affine());
    let mut out: [u8; 48] = [0; 48];
    out.copy_from_slice(s.as_ref());
    out
}
  
// take an array of 48 bytes and output a proof
// Copied from the bls library
pub fn convert_bytes_to_proof (input : &[u8; 48]) -> G1 {
    let mut proof_compressed = G1Compressed::empty();
    proof_compressed
        .as_mut()
        .copy_from_slice(input);
    let proof_affine = proof_compressed.into_affine().unwrap();
    proof_affine.into_projective()
}

