extern crate veccom_paramgen;
use ff::PrimeField;
use pairing_plus::bls12_381::*;
use pairing_plus::serdes::SerDes;

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
        let pp = veccom_paramgen::generate(alpha, 0, *i);
        let mut f = std::fs::File::create(file_name).unwrap();
        pp.serialize(&mut f, true).unwrap();
    }

    println!("Hello, world!");
}
