use pairing::{bls12_381::*, CurveProjective, Engine};
use ff::Field;
use super::{ProverParams, VerifierParams};


pub fn paramgen_from_seed(seed: &[u8], n: usize) -> (ProverParams, VerifierParams) {
    paramgen_from_alpha(&Fr::hash_to_fr(seed), n)
}

pub fn paramgen_from_alpha(alpha: &Fr, n : usize) -> (ProverParams, VerifierParams) {
    let mut g1_vec = Vec::with_capacity(2*n);
    // prover vector at index i-1 contains g1^{alpha^i} for i ranging from 1 to 2n 
    // except that at index i, prover vector contains nothing useful
    // (we'll use G1::one as a placeholder in order to maintain the indexing)
    let mut g2_vec = Vec::with_capacity(n);
    // verifier vector at index i-1 contains g2^{alpha^i} for i ranging from 1 to n
    let mut alpha_power = Fr::one();
    for _ in 0..n {
        let mut g1 = G1::one();
        let mut g2 = G2::one();
        alpha_power.mul_assign(&alpha); // compute alpha^i
        g1.mul_assign(alpha_power);
        g2.mul_assign(alpha_power);
        g1_vec.push(g1);
        g2_vec.push(g2);
    }
    
    // skip g1^{alpha^{n+1}}
    alpha_power.mul_assign(&alpha);
    g1_vec.push(G1::zero()); // this 0 is important -- without it, prove will not work correctly

    // Now do the rest of the prover
    for _ in n..2*n {
        let mut g1 = G1::one();
        alpha_power.mul_assign(&alpha);
        g1.mul_assign(alpha_power);
        g1_vec.push(g1);
    }

    // verifier also gets gt^{alpha^{n+1}} in the target group
    let gt = Bls12::pairing(g1_vec[0], g2_vec[n-1]);

    (ProverParams{generators : g1_vec, precomp : None}, VerifierParams{generators : g2_vec, gt_elt : gt})
}

impl ProverParams {
    pub fn precomp (&mut self)  {
        let mut v:Vec<[G1;3]> = Vec::with_capacity(self.generators.len());
        // compute 2^64 * self.generators[i], 2^128 * self.generators[i], and 2^192 * self.generators[i]
        for i in 0..self.generators.len() {
            let mut pre1 = self.generators[i];
            for _ in 0..64 {
                pre1.double();
            }
            let mut pre2 = pre1;
            for _ in 0..64 {
                pre2.double();
            }
            let mut pre3 = pre2;
            for _ in 0..64 {
                pre3.double();
            }
            v.push([pre1, pre2, pre3]);    
        }
        self.precomp = Some(v);
    }
}