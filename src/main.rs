extern crate pairing;
extern crate ff;
use pairing::{bls12_381::*, CurveProjective, Engine};
use ff::PrimeField;


pub mod veccom;

fn main() {
    test_paramgen();
}

fn test_paramgen() {
    let n = 10usize;
    let r = FrRepr([ // arbitrary alpha for now
        0x25ebe3a3ad3c0c6a,
        0x6990e39d092e817c,
        0x941f900d42f5658e,
        0x44f8a103b38a71e0]);
    let alpha = Fr::from_repr(r).unwrap();
    let (g1_vec, g2_vec) = veccom::paramgen::paramgen(&alpha, n);
    // g1_vec[i] should contain the generator of the G1 group raised to the power alpha^{i+1}
    // g2_vec[j] should contain the generator of the G2 group raised to the power alpha^{j+1}

    let mut dh_values = Vec::new();
    // dh_values[i] will contains the generator of the target group raised to the power alpha^{i+1}


    for i in 0..n {
        dh_values.push(Bls12::pairing(g1_vec[i], G2::one()));
    }
    for i in 0..n {
        dh_values.push(Bls12::pairing(g1_vec[n-1], g2_vec[i]));
    }
    for i in 0..n {
        assert_eq!(dh_values[i], Bls12::pairing(G1::one(), g2_vec[i]));
        //println!("{:?}", dh_values[i]==Bls12::pairing(G1::one(), g2_vec[i]));
    }
    for i in 0..n {
        for j in 0..n {
            assert_eq!(dh_values[i+j+1], Bls12::pairing(g1_vec[i], g2_vec[j]));
            //println!("{:?}", dh_values[i+j+1]==Bls12::pairing(g1_vec[i], g2_vec[j]));
        }
    }

}
