use pairing::{bls12_381::*, CurveProjective};
use ff::Field;

pub fn paramgen(alpha: &Fr, n : usize) -> (Vec<G1>, Vec<G2>) {
    let mut g1_vec = Vec::with_capacity(n);
    let mut g2_vec = Vec::with_capacity(n);
    let mut alpha_power = Fr::one();
    for _ in 0..n {
        let mut g1 = G1::one();
        let mut g2 = G2::one();
        alpha_power.mul_assign(&alpha);
        g1.mul_assign(alpha_power);
        g2.mul_assign(alpha_power);
        g1_vec.push(g1);
        g2_vec.push(g2);
    }
    (g1_vec, g2_vec)
}
  