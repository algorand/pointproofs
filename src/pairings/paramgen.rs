use pairing::{bls12_381::*, CurveProjective, CurveAffine, Engine};
use ff::Field;
use super::{ProverParams, VerifierParams};


pub fn paramgen_from_seed(seed: &[u8], n: usize) -> (ProverParams, VerifierParams) {
    paramgen_from_alpha(&Fr::hash_to_fr(seed), n)
}

// TODO: error check for n==0 and/or handle the n==0 case?
pub fn paramgen_from_alpha(alpha: &Fr, n : usize) -> (ProverParams, VerifierParams) {
    let mut g1_vec = Vec::with_capacity(2*n);
    // prover vector at index i-1 contains g1^{alpha^i} for i ranging from 1 to 2n 
    // except that at index i, prover vector contains nothing useful
    // (we'll use G1::one as a placeholder in order to maintain the indexing)
    let mut g2_vec = Vec::with_capacity(n);
    // verifier vector at index i-1 contains g2^{alpha^i} for i ranging from 1 to n
    let mut alpha_power = Fr::one();
    for _ in 0..n {
        alpha_power.mul_assign(&alpha); // compute alpha^i
        g1_vec.push(G1Affine::one().mul(alpha_power).into_affine());
        g2_vec.push(G2Affine::one().mul(alpha_power).into_affine());
    }
    
    // skip g1^{alpha^{n+1}}
    alpha_power.mul_assign(&alpha);
    g1_vec.push(G1::zero().into_affine()); // this 0 is important -- without it, prove will not work correctly

    // Now do the rest of the prover
    for _ in n..2*n-1 {
        alpha_power.mul_assign(&alpha); // compute alpha^i
        g1_vec.push(G1Affine::one().mul(alpha_power).into_affine());
    }

    // verifier also gets gt^{alpha^{n+1}} in the target group
    let gt = Bls12::pairing(g1_vec[0], g2_vec[n-1]);

    (ProverParams{generators : g1_vec, precomp : Vec::with_capacity(0)}, VerifierParams{generators : g2_vec, gt_elt : gt})
}

impl ProverParams {
    pub fn precomp_3 (&mut self)  {
        let twice_n = self.generators.len();
        self.precomp = vec![G1Affine::zero(); 3*twice_n];  // TODO: is there a better way to inialize this? We need merely to allocate space, not to set it to 0
        for i in 0..twice_n {
            self.generators[i].precomp_3(&mut self.precomp[i*3..(i+1)*3]);
        }
    }
    pub fn precomp_256 (&mut self)  {
        let twice_n = self.generators.len();
        self.precomp = vec![G1Affine::zero(); 256*twice_n]; // TODO: is there a better way to inialize this? We need merely to allocate space, not to set it to 0
        for i in 0..twice_n {
            self.generators[i].precomp_256(&mut self.precomp[i*256..(i+1)*256]);
        }
    }
}
