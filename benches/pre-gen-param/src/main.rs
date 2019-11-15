extern crate veccom;
extern crate veccom_paramgen;
use ff::PrimeField;
use pairing_plus::bls12_381::*;
use pairing_plus::serdes::SerDes;
use pairing_plus::CurveProjective;
use veccom::pairings::ProverParams;
fn main() {
    println!("WARNING!!!");
    println!("WARNING!!!");
    println!("WARNING!!!");
    println!("Parameters generated in this crate is INSECURE. Do NOT use it in production");

    let alpha = Fr::from_repr(FrRepr([5, 0, 0, 0])).unwrap();
    let test_dim = [256usize, 1024, 4096, 16384, 65536, 262144];

    for i in &test_dim {
        println!("generating testing parameters for {}", i);
        let file_name = format!("{}.param", i);
        let param = veccom_paramgen::generate(alpha, 0, *i);
        let mut f = std::fs::File::create(file_name).unwrap();
        param.serialize(&mut f, true).unwrap();

        let pp = ProverParams {
            ciphersuite: param.ciphersuite,
            n: param.n,
            generators: [
                param.g1_alpha_1_to_n,
                vec![G1::zero().into_affine()],
                param.g1_alpha_nplus2_to_2n,
            ]
            .concat(),
            pp_len: 0,
            precomp: vec![],
        };
        let mut pp3 = pp.clone();
        pp3.precomp_3();
        let file_name = format!("{}_pre3.param", i);
        let mut f = std::fs::File::create(file_name).unwrap();
        pp3.serialize(&mut f, true).unwrap();

        let mut pp256 = pp.clone();
        pp256.precomp_256();
        let file_name = format!("{}_pre256.param", i);
        let mut f = std::fs::File::create(file_name).unwrap();
        pp256.serialize(&mut f, true).unwrap();
    }

    println!("Hello, world!");
}
