extern crate pairing;
extern crate ff;
use pairing::{bls12_381::*, CurveProjective, Engine};
use ff::PrimeField;


pub mod veccom;

fn main() {
    test_paramgen();
    test_com();
}

fn test_paramgen() {
    let n = 20usize;
    let r = FrRepr([ // arbitrary alpha for now
        0x25ebe3a3ad3c0c6a,
        0x6990e39d092e817c,
        0x941f900d42f5658e,
        0x44f8a103b38a71e0]);
    let alpha = Fr::from_repr(r).unwrap();
    let (g1_vec, g2_vec, gt_value) = veccom::paramgen::paramgen(&alpha, n);
    // g1_vec[i] should contain the generator of the G1 group raised to the power alpha^{i+1},
    // except g1_vec[n] will contain nothing useful.
    // g2_vec[j] should contain the generator of the G2 group raised to the power alpha^{j+1}.
    // gt should contain the generator of the target group raised to the power alpha^{n+1}.

    let mut dh_values = Vec::with_capacity(3*n);
    // If all is correct, then
    // dh_values[i] will contains the generator of the target group raised to the power alpha^{i+1}
    // We will test all possible pairing of the two arrays with each other and with the generators
    // of the two groups, and see if they all match as appropriate.


    for i in 0..n {
        dh_values.push(Bls12::pairing(g1_vec[i], G2::one()));
    }
    dh_values.push(gt_value);
    for i in n+1..2*n {
        dh_values.push(Bls12::pairing(g1_vec[i], G2::one()));
    }
    for i in 0..n {
        dh_values.push(Bls12::pairing(g1_vec[2*n-1], g2_vec[i]));
    }

    for i in 0..n {
        assert_eq!(dh_values[i], Bls12::pairing(G1::one(), g2_vec[i]));
    }
    for i in 0..2*n {
        if i!=n {
            for j in 0..n {
                assert_eq!(dh_values[i+j+1], Bls12::pairing(g1_vec[i], g2_vec[j]));
            }
        }
    }
}

fn test_com() {
    let n = 10usize;
    let r = FrRepr([ // arbitrary alpha for now
        0x25ebe3a3ad3c0c6a,
        0x6990e39d092e817c,
        0x941f900d42f5658e,
        0x44f8a103b38a71e0]);
    let alpha = Fr::from_repr(r).unwrap();
    let (g1_vec, g2_vec, gt_value) = veccom::paramgen::paramgen(&alpha, n);

    let mut values = Vec::with_capacity(n);
    for i in 0..n {
        let s = format!("this is message number {}", i);
        values.push(s.into_bytes());
    }
    let com = veccom::commit::commit(&g1_vec, &values);

    for i in 0..n {
        let proof = veccom::prove::prove(&g1_vec, &values, i);
        let wrong_string = format!("wrong string").into_bytes();
        print!("{} ", veccom::verify::verify(&g2_vec, &gt_value, &com, &proof, &values[i], i));
        println!("{} ", veccom::verify::verify(&g2_vec, &gt_value, &com, &proof, &wrong_string, i));
    }

}

