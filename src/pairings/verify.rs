use pairing::{bls12_381::*, CurveAffine, CurveProjective, Engine};
//use pairing::Wnaf;
use super::VerifierParams;
use ff::Field;
use pairing::hash_to_field::HashToField;

/**
 * Assumes verifier_params are correctly generated for n such that index<n
 */
pub fn verify(
    verifier_params: &VerifierParams,
    com: &G1,
    proof: &G1,
    value: &[u8],
    index: usize,
) -> bool {
    // verification formula: e(com, param[n-index-1]) = gt_elt ^ hash(value) * e(proof, generator_of_g2)
    // We modify the formula in order to avoid slow exponentation in the target group (which is Fq12)
    // and perform two scalar multiplication by to 1/hash(value) in G1 instead, which is considerably faster.
    // We also move the pairing from the right-hand-side to the left-hand-side in order
    // to take advantage of the pairing product computation, which is faster than two pairings.
    let hash = HashToField::<Fr>::new(&value, None).with_ctr(0);
    let hash_inverse = hash.inverse();
    // We separate this function so we can test the case of hash_inverse == None
    // (which will get exercised only with probability 1/r, i.e., never,
    // because the hash to Fr would have to produce a 0 in order for it to get invoked)
    verify_hash_inverse(verifier_params, com, proof, hash_inverse, index)
}

pub fn verify_hash_inverse(
    verifier_params: &VerifierParams,
    com: &G1,
    proof: &G1,
    hash_inverse: Option<Fr>,
    index: usize,
) -> bool {
    let n = verifier_params.generators.len();
    let mut com_mut = *com;
    let mut proof_mut = *proof;
    proof_mut.negate();

    match hash_inverse {
        Some(h_inverse) => {
            // The following may be a tiny bit faster -- not enough to show up on a benchmark
            /*let mut w = Wnaf::new();
            let mut wnaf = w.scalar(h_inverse.into());
            let com_mut = wnaf.base(com_mut);
            let proof_mut = wnaf.base(proof_mut);*/
            com_mut.mul_assign(h_inverse);
            proof_mut.mul_assign(h_inverse);
            Bls12::pairing_product(
                com_mut,
                verifier_params.generators[n - index - 1],
                proof_mut,
                G2Affine::one(),
            ) == verifier_params.gt_elt
        }
        None => {
            Bls12::pairing_product(
                com_mut,
                verifier_params.generators[n - index - 1],
                proof_mut,
                G2Affine::one(),
            ) == Fq12::one()
        }
    }
}
