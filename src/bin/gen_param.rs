extern crate ff;
extern crate pairing_plus as pairing;
extern crate veccom;

use pairing::serdes::SerDes;
use veccom::pairings::param::*;

fn main() {
    println!("WARNING!!!");
    println!("WARNING!!!");
    println!("WARNING!!!");
    println!("Parameters generated in this crate is INSECURE. Do NOT use it in production");

    let test_dim = [256usize]; //, 16384, 65536, 262144];

    for i in &test_dim {
        #[cfg(not(unswitch_group))]
        println!("generating testing parameters for {} with proof in G2", i);
        #[cfg(unswitch_group)]
        println!("generating testing parameters for {} with proof in G1", i);
        let seed = "this is a very very long seed for testing. Do not use in product";

        let (pp, vp) = paramgen_from_seed(seed, 0, *i).unwrap();

        #[cfg(not(unswitch_group))]
        let file_name = format!("{}_proof_in_g2.pp", i);
        #[cfg(unswitch_group)]
        let file_name = format!("{}_proof_in_g1.pp", i);

        let mut f = std::fs::File::create(file_name).unwrap();
        pp.serialize(&mut f, true).unwrap();

        #[cfg(not(unswitch_group))]
        let file_name = format!("{}_proof_in_g2.vp", i);
        #[cfg(unswitch_group)]
        let file_name = format!("{}_proof_in_g1.vp", i);

        let mut f = std::fs::File::create(file_name).unwrap();
        vp.serialize(&mut f, true).unwrap();
    }

    println!("Hello, world!");
}
