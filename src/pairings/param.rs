//! this file is part of the pointproofs.
//! It defines system parameters and functions to generate/validate them.

use ff::Field;
use pairing::serdes::SerDes;
use pairing::{bls12_381::*, CurveAffine, CurveProjective};
use pairings::err::*;
use pairings::hash_to_field_pointproofs::hash_to_field_pointproofs;
use pairings::*;

const VALID_CIPHERSUITE: [u8; 1] = [0u8];

/// Ciphersuite ID is a wrapper of u8.
pub type Ciphersuite = u8;

/// Checks if csid is supported. Currently only support csid = 0.
pub fn check_ciphersuite(csid: Ciphersuite) -> bool {
    VALID_CIPHERSUITE.contains(&csid)
}

/// Generate a set of parameters from a seed and a ciphersuite ID.
/// Returns an error is the seed is not long enough; or ciphersuite is not valid; or n == 0
/// This function shall only be used for testing purpose.
/// In deployment you should use `pointproofs-param` crate to ensure the
/// security of the public parameters.
pub fn paramgen_from_seed<Blob: AsRef<[u8]>>(
    seed: Blob,
    ciphersuite: Ciphersuite,
    n: usize,
) -> Result<(ProverParams, VerifierParams), String> {
    // check the length of the seed
    if seed.as_ref().len() < 32 {
        return Err(ERR_SEED_TOO_SHORT.to_owned());
    }

    // checks the validity of the inputs
    if !check_ciphersuite(ciphersuite) {
        return Err(ERR_CIPHERSUITE.to_owned());
    }
    if n > 65536 {
        return Err(ERR_MAX_N.to_owned());
    }

    // invoke the internal parameter generation function
    Ok(paramgen_from_alpha(
        &hash_to_field_pointproofs(&seed),
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
    #[cfg(not(debug_assertions))]
    println!(
        "\n\n\nWarning!!! \nWarning!!! \nWarning!!! \nWarning!!! \n\
        This function (paramgen_from_alpha) shall only be used for developing purpose.\n\
        In deployment you should use `pointproofs-paramgen` crate to ensure \
        the security of the public parameters.\n\
        End of warning.\n\n"
    );
    let mut g1_vec = Vec::with_capacity(2 * n);
    // prover vector at index i-1 contains g1^{alpha^i} for i ranging from 1 to 2n
    // except that at index i, prover vector contains nothing useful
    // (we'll use G1::one as a placeholder in order to maintain the indexing)
    let mut g2_vec = Vec::with_capacity(n);
    // verifier vector at index i-1 contains g2^{alpha^i} for i ranging from 1 to n
    let mut alpha_power = Fr::one();
    for _ in 0..n {
        alpha_power.mul_assign(&alpha); // compute alpha^i
        g1_vec.push(PointproofsG1Affine::one().mul(alpha_power).into_affine());
        g2_vec.push(PointproofsG2Affine::one().mul(alpha_power).into_affine());
    }

    // skip g1^{alpha^{n+1}}
    alpha_power.mul_assign(&alpha);
    g1_vec.push(PointproofsG1::zero().into_affine()); // this 0 is important -- without it, prove will not work correctly

    // Now do the rest of the prover
    for _ in n..2 * n - 1 {
        alpha_power.mul_assign(&alpha); // compute alpha^i
        g1_vec.push(PointproofsG1Affine::one().mul(alpha_power).into_affine());
    }

    // verifier also gets gt^{alpha^{n+1}} in the target group
    let gt = pointproofs_pairing(g1_vec[0], g2_vec[n - 1]);

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
            pp_len: 0,
            precomp: Vec::with_capacity(0),
            gt_elt: gt,
        },
    )
}

impl VerifierParams {
    /// pre-process the public parameters with precomputation value set to 3
    pub fn precomp_3(&mut self) {
        self.precomp = vec![PointproofsG2Affine::zero(); 3 * self.n];
        for i in 0..self.n {
            self.generators[i].precomp_3(&mut self.precomp[i * 3..(i + 1) * 3]);
        }
        self.pp_len = self.n * 3;
    }

    /// pre-process the public parameters with precomputation value set to 256
    pub fn precomp_256(&mut self) {
        self.precomp = vec![PointproofsG2Affine::zero(); 256 * self.n];
        for i in 0..self.n {
            self.generators[i].precomp_256(&mut self.precomp[i * 256..(i + 1) * 256]);
        }
        self.pp_len = self.n * 256;
    }
}

impl ProverParams {
    /// pre-process the public parameters with precomputation value set to 3
    pub fn precomp_3(&mut self) {
        let twice_n = self.generators.len();
        self.precomp = vec![PointproofsG1Affine::zero(); 3 * twice_n];
        for i in 0..twice_n {
            self.generators[i].precomp_3(&mut self.precomp[i * 3..(i + 1) * 3]);
        }
        self.pp_len = self.n * 6;
    }

    /// pre-process the public parameters with precomputation value set to 256
    pub fn precomp_256(&mut self) {
        let twice_n = self.generators.len();
        self.precomp = vec![PointproofsG1Affine::zero(); 256 * twice_n];
        for i in 0..twice_n {
            self.generators[i].precomp_256(&mut self.precomp[i * 256..(i + 1) * 256]);
        }
        self.pp_len = self.n * 512;
    }

    /// check if the parameters are correct -- should not be used other than testing
    #[cfg(test)]
    pub(crate) fn check_parameters(&self, vp: &VerifierParams) -> bool {
        if self.n != vp.n || self.ciphersuite != vp.ciphersuite {
            return false;
        }

        // prover_params.generators[i] should contain the generator of the G1 group raised to the power alpha^{i+1},
        // except prover_params.generators[n] will contain nothing useful.
        // verifier_params.generators[j] should contain the generator of the G2 group raised to the power alpha^{j+1}.
        // gt should contain the generator of the target group raised to the power alpha^{n+1}.

        let mut dh_values = Vec::with_capacity(3 * self.n);
        // If all is correct, then
        // dh_values[i] will contains the generator of the target group raised to the power alpha^{i+1}
        // We will test all possible pairing of the two arrays with each other and with the generators
        // of the two groups, and see if they all match as appropriate.

        for i in 0..self.n {
            dh_values.push(pointproofs_pairing(
                self.generators[i],
                PointproofsG2Affine::one(),
            ));
        }
        dh_values.push(vp.gt_elt);
        for i in self.n + 1..2 * self.n {
            dh_values.push(pointproofs_pairing(
                self.generators[i],
                PointproofsG2Affine::one(),
            ));
        }
        for i in 0..self.n {
            dh_values.push(pointproofs_pairing(
                self.generators[2 * self.n - 1],
                vp.generators[i],
            ));
        }

        for (i, e) in dh_values.iter().enumerate().take(self.n) {
            if e != &pointproofs_pairing(PointproofsG1Affine::one(), vp.generators[i]) {
                return false;
            };
        }

        for i in 0..2 * self.n {
            if i != self.n {
                for j in 0..self.n {
                    if dh_values[i + j + 1]
                        != pointproofs_pairing(self.generators[i], vp.generators[j])
                    {
                        return false;
                    };
                }
            }
        }
        true
    }
}

impl std::cmp::PartialEq for ProverParams {
    /// Convenient function to compare secret key objects
    fn eq(&self, other: &Self) -> bool {
        self.ciphersuite == other.ciphersuite
            && self.n == other.n
            && self.generators == other.generators
            && self.pp_len == other.pp_len
            && self.precomp == other.precomp
    }
}

impl std::cmp::PartialEq for VerifierParams {
    /// Convenient function to compare secret key objects
    fn eq(&self, other: &Self) -> bool {
        self.ciphersuite == other.ciphersuite
            && self.n == other.n
            && self.generators == other.generators
            && self.gt_elt == other.gt_elt
    }
}

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

// read a parameter pair
// the parameter is organized as
// pub struct PointproofsParams {
//     /// ciphersuite id
//     pub ciphersuite: u8,
//
//     /// parameter N
//     pub n: usize,
//
//     /// g1^{alpha}, ..., g1^{alpha^N}
//     pub g1_alpha_1_to_n: Vec<G1Affine>,
//
//     /// g1^{alpha^{N+2}}, g1^{alpha^{N+3}}, ..., g1^{alpha^{2N}}
//     pub g1_alpha_nplus2_to_2n: Vec<G1Affine>,
//
//     /// g2^{alpha}, g2^{alpha^2}, ..., g2^{alpha^N}
//     pub g2_alpha_1_to_n: Vec<G2Affine>,
//
//     /// g2^{alpha^{N+2}}, g2^{alpha^{N+3}}, ..., g2^{alpha^{2N}}
//     pub g2_alpha_nplus2_to_2n: Vec<G2Affine>,
//
//     /// e(g2,g1)^{alpha^{N+1}}
//     pub gt_alpha_nplus1: Fq12,
// }
pub fn read_param<R: std::io::Read>(
    reader: &mut R,
) -> Result<(ProverParams, VerifierParams), String> {
    let param = match pointproofs_paramgen::PointproofsParams::deserialize(reader, true) {
        Err(e) => return Err(format!("read_param: {}", e.to_string())),
        Ok(p) => p,
    };

    if !pointproofs_paramgen::consistent(&param) {
        return Err("Input params are not consistent".to_owned());
    };

    // groups are NOT switched
    #[cfg(not(feature = "group_switched"))]
    let pp = ProverParams {
        ciphersuite: 0,
        n: param.n,
        generators: [
            param.g1_alpha_1_to_n,
            vec![PointproofsG1::zero().into_affine()],
            param.g1_alpha_nplus2_to_2n,
        ]
        .concat(),
        pp_len: 0,
        precomp: vec![],
    };

    #[cfg(not(feature = "group_switched"))]
    let vp = VerifierParams {
        ciphersuite: 0,
        n: param.n,
        generators: param.g2_alpha_1_to_n,
        pp_len: 0,
        precomp: vec![],
        gt_elt: param.gt_alpha_nplus1,
    };

    // groups switched
    #[cfg(feature = "group_switched")]
    let pp = ProverParams {
        ciphersuite: 0,
        n: param.n,
        generators: [
            param.g2_alpha_1_to_n,
            vec![PointproofsG1::zero().into_affine()],
            param.g2_alpha_nplus2_to_2n,
        ]
        .concat(),
        pp_len: 0,
        precomp: vec![],
    };
    #[cfg(feature = "group_switched")]
    let vp = VerifierParams {
        ciphersuite: 0,
        n: param.n,
        generators: param.g1_alpha_1_to_n,
        pp_len: 0,
        precomp: vec![],
        gt_elt: param.gt_alpha_nplus1,
    };

    Ok((pp, vp))
}
