use pairing::{bls12_381::*, CurveProjective, CurveAffine, Engine};
use ff::Field;
use super::VerifierParams;


// TODO: error handling if index is out of bounds?
pub fn verify(verifier_params : &VerifierParams, com : &G1, proof : &G1, value : &[u8], index : usize) -> bool {
    let n = verifier_params.generators.len();

    // verification formula: e(com, param[n-index-1]) = gt_elt ^ hash(value) * e(proof, generator_of_g2)
    // We modify the formula in order to avoid slow exponentation in the target group (which is Fq12)
    // and perform two scalar multiplication by to 1/hash(value) in G1 instead, which is considerably faster.
    // We also move the pairing from the right-hand-side to the left-hand-side in order
    // to take advantage of the pairing product computation, which is faster than two pairings.
    let hash = Fr::hash_to_fr(value);
    let hash_inverse = hash.inverse();

    let mut com_mut = *com;
    let mut proof_mut = *proof;
    proof_mut.negate();


    match hash_inverse {
        Some(h_inverse) => {
            com_mut.mul_assign(h_inverse);
            proof_mut.mul_assign(h_inverse);
            Bls12::pairing_product(com_mut, verifier_params.generators[n-index-1], proof_mut, G2Affine::one()) == verifier_params.gt_elt
        }
        None => { 
            // This branch will get exercised only with probability 1/r, i.e., never,
            // because the hash to Fr would have to produce a 0 in order for it to get invoked
            // TODO: how to write a test that automatically exercises this branch? (it was tested only manually)
            Bls12::pairing_product(com_mut, verifier_params.generators[n-index-1], proof_mut, G2Affine::one())
                == Fq12::one()
        }
    }
}
  