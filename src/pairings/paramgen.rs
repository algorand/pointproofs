use super::ciphersuite::*;
use super::err::*;
use super::{ProverParams, VerifierParams};
use ff::Field;
use pairing::serdes::SerDes;
use pairing::{bls12_381::*, CurveAffine, CurveProjective, Engine};
use pairings::hash_to_field_veccom::hash_to_field_veccom;
use pairings::*;
use veccom_paramgen::*;
// /// this function reads the default parameter
// /// it should not be used other than for testing/benchmarking purpose
// #[cfg(test)]
// pub fn read_default_param() -> (ProverParams, VerifierParams) {
//     println!("start");
//     //    let mut _f = std::fs::File::create("sample2.param").unwrap();
//     let mut f = match std::fs::File::open("sample.param") {
//         Err(e) => panic!("{}", e),
//         Ok(p) => p,
//     };
//     println!("opened");
//     //    let mut buf_reader = std::io::BufReader::new(f);
//     let (pp, vp) = match read_param(&mut f) {
//         Err(e) => panic!("{}", e),
//         Ok(p) => p,
//     };
//     println!("finished");
//     (pp, vp)
// }

// /// this function reads the default parameter with precomputation
// /// it should not be used other than for testing/benchmarking purpose
// #[cfg(test)]
// pub fn read_default_param_with_pre_computation(
// ) -> (ProverParams, ProverParams, ProverParams, VerifierParams) {
//     let mut f = std::fs::File::open("sample.param").unwrap();
//     println!("opened");
//     let (pp, vp) = read_param(&mut f).unwrap();
//     let mut pp3 = pp.clone();
//     pp3.precomp_3();
//     let mut pp256 = pp.clone();
//     pp256.precomp_256();
//     let mut f2 = std::fs::File::open("sample_pre.param").unwrap();
//     pp.serialize(&mut f2, true).unwrap();
//     //    pp3.serialize(&mut f2, true).unwrap();
//     //    pp256.serialize(&mut f2, true).unwrap();
//     (pp, pp3, pp256, vp)
// }
//
// // read a parameter pair
// #[allow(dead_code)]
// pub fn read_param<R: std::io::Read>(
//     reader: &mut R,
// ) -> Result<(ProverParams, VerifierParams), String> {
//     let param = match VeccomParams::deserialize(reader, true) {
//         Err(e) => return Err(format!("read_param:{}", e.to_string())),
//         Ok(p) => p,
//     };
//
//     if !consistent(&param) {
//         return Err("Input params are not consistent".to_owned());
//     };
//
//     let pp = ProverParams {
//         ciphersuite: param.ciphersuite,
//         n: param.n,
//         generators: [
//             param.g1_alpha_1_to_n,
//             vec![VeccomG1::zero().into_affine()],
//             param.g1_alpha_nplus2_to_2n,
//         ]
//         .concat(),
//         pp_len: 0,
//         precomp: vec![],
//     };
//     let vp = VerifierParams {
//         ciphersuite: param.ciphersuite,
//         n: param.n,
//         generators: param.g2_alpha_1_to_n,
//         gt_elt: param.gt_alpha_nplus1,
//     };
//     Ok((pp, vp))
// }

/// Generate a set of parameters from a seed and a ciphersuite ID.
/// Returns an error is the seed is not long enough; or ciphersuite is not valid; or n == 0
pub fn paramgen_from_seed<Blob: AsRef<[u8]>>(
    seed: Blob,
    ciphersuite: Ciphersuite,
    n: usize,
) -> Result<(ProverParams, VerifierParams), String> {
    // check the length of the seed
    if seed.as_ref().len() < 32 {
        return Err(ERR_SEED_TOO_SHORT.to_owned());
    }

    // get the system parameters, which also implicitly
    // checks the validity of the inputs
    // let sp = get_system_paramter(ciphersuite)?;
    if !check_ciphersuite(ciphersuite) {
        return Err(ERR_CIPHERSUITE.to_owned());
    }
    // invoke the internal parameter generation function
    Ok(paramgen_from_alpha(
        &hash_to_field_veccom(&seed),
        ciphersuite,
        n,
    ))
}

/// Internal logic for parameter generation.
/// Will always succeed.
/// Will not be called outside this module.
fn paramgen_from_alpha(
    alpha: &Fr,
    ciphersuite: Ciphersuite,
    n: usize,
) -> (ProverParams, VerifierParams) {
    let mut g1_vec = Vec::with_capacity(2 * n);
    // prover vector at index i-1 contains g1^{alpha^i} for i ranging from 1 to 2n
    // except that at index i, prover vector contains nothing useful
    // (we'll use G1::one as a placeholder in order to maintain the indexing)
    let mut g2_vec = Vec::with_capacity(n);
    // verifier vector at index i-1 contains g2^{alpha^i} for i ranging from 1 to n
    let mut alpha_power = Fr::one();
    for _ in 0..n {
        alpha_power.mul_assign(&alpha); // compute alpha^i
        g1_vec.push(VeccomG1Affine::one().mul(alpha_power).into_affine());
        g2_vec.push(VeccomG2Affine::one().mul(alpha_power).into_affine());
    }

    // skip g1^{alpha^{n+1}}
    alpha_power.mul_assign(&alpha);
    g1_vec.push(VeccomG1::zero().into_affine()); // this 0 is important -- without it, prove will not work correctly

    // Now do the rest of the prover
    for _ in n..2 * n - 1 {
        alpha_power.mul_assign(&alpha); // compute alpha^i
        g1_vec.push(VeccomG1Affine::one().mul(alpha_power).into_affine());
    }

    // verifier also gets gt^{alpha^{n+1}} in the target group
    let gt = Bls12::pairing(g2_vec[n - 1], g1_vec[0]);

    (
        ProverParams {
            ciphersuite,
            n,
            generators: g1_vec,
            pp_len: 0,
            precomp: Vec::with_capacity(0),
        },
        VerifierParams {
            ciphersuite,
            n,
            generators: g2_vec,
            gt_elt: gt,
        },
    )
}
