use super::ciphersuite::*;
use super::err::*;
use super::{ProverParams, SystemParam, VerifierParams};
use ff::Field;
use pairing::hash_to_field::HashToField;
use pairing::serdes::SerDes;
use pairing::{bls12_381::*, CurveAffine, CurveProjective, Engine};

/// Generate a set of parameters from a seed and a ciphersuite ID.
/// Returns an error is the seed is not long enough; or ciphersuite is not valid; or n == 0
pub fn paramgen_from_seed<Blob: AsRef<[u8]>>(
    seed: Blob,
    ciphersuite: Ciphersuite,
) -> Result<(ProverParams, VerifierParams), String> {
    // check the length of the seed
    if seed.as_ref().len() < 32 {
        return Err(ERR_SEED_TOO_SHORT.to_owned());
    }

    // get the system parameters, which also implicitly
    // checks the validity of the inputs
    let sp = get_system_paramter(ciphersuite)?;

    // invoke the internal parameter generation function
    Ok(paramgen_from_alpha(
        &HashToField::<Fr>::new(&seed, None).with_ctr(0),
        sp,
    ))
}

/// Internal logic for parameter generation.
/// Will always succeed.
/// Will not be called outside this module.
fn paramgen_from_alpha(alpha: &Fr, sp: SystemParam) -> (ProverParams, VerifierParams) {
    let mut g1_vec = Vec::with_capacity(2 * sp.n);
    // prover vector at index i-1 contains g1^{alpha^i} for i ranging from 1 to 2n
    // except that at index i, prover vector contains nothing useful
    // (we'll use G1::one as a placeholder in order to maintain the indexing)
    let mut g2_vec = Vec::with_capacity(sp.n);
    // verifier vector at index i-1 contains g2^{alpha^i} for i ranging from 1 to n
    let mut alpha_power = Fr::one();
    for _ in 0..sp.n {
        alpha_power.mul_assign(&alpha); // compute alpha^i
        g1_vec.push(G1Affine::one().mul(alpha_power).into_affine());
        g2_vec.push(G2Affine::one().mul(alpha_power).into_affine());
    }

    // skip g1^{alpha^{n+1}}
    alpha_power.mul_assign(&alpha);
    g1_vec.push(G1::zero().into_affine()); // this 0 is important -- without it, prove will not work correctly

    // Now do the rest of the prover
    for _ in sp.n..2 * sp.n - 1 {
        alpha_power.mul_assign(&alpha); // compute alpha^i
        g1_vec.push(G1Affine::one().mul(alpha_power).into_affine());
    }

    // verifier also gets gt^{alpha^{n+1}} in the target group
    let gt = Bls12::pairing(g1_vec[0], g2_vec[sp.n - 1]);

    (
        ProverParams {
            ciphersuite: sp.ciphersuite,
            generators: g1_vec,
            precomp: Vec::with_capacity(0),
        },
        VerifierParams {
            ciphersuite: sp.ciphersuite,
            generators: g2_vec,
            gt_elt: gt,
        },
    )
}
