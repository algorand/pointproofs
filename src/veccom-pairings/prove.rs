use pairing::{bls12_381::*, CurveProjective};

pub fn prove(prover_params: &[G1], values: &[Vec<u8>], index : usize) -> G1 {
    // TODO: error handling if the prover params length is not double values length
    // TODO: figure out if the input for values is the right one to use
    let n = values.len();
    let mut proof = G1::zero();

    // prover_params[n] is useless and we should never index it
    for i in 0..index {
        let mut param_i = prover_params[i+n-index]; // note that i+n-index < n
        param_i.mul_assign(Fr::hash_to_fr(&values[i]));
        proof.add_assign(&param_i);
    }
    for i in index+1..n {
        let mut param_i = prover_params[i+n-index]; // note that i+n-index > n
        param_i.mul_assign(Fr::hash_to_fr(&values[i]));
        proof.add_assign(&param_i);
    }
    proof
}
  