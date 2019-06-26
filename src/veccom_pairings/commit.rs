use pairing::{bls12_381::*, CurveProjective};

pub fn commit(prover_params: &[G1], values: &[Vec<u8>]) -> G1 {
    // TODO: error handling if the prover params length is not double values length
    // TODO: figure out if the input for values is the right one to use
    let mut com = G1::zero();
    let n = values.len();
    for i in 0..n {
        let mut param_i = prover_params[i];
        param_i.mul_assign(Fr::hash_to_fr(&values[i]));
        com.add_assign(&param_i);
    }
    com
}
  