use super::pairings::paramgen::*;
use pairing::serdes::SerDes;
use std::io::BufReader;
use std::io::Read;
use veccom_paramgen::VeccomParams;
// #[test]
// fn test_pre_param() {
//     let (pp, vp) = read_default_param();
//     println!("{:?}", pp.generators[0]);
//     //    let (ppp, pp3, pp256, vp) = read_default_param_with_pre_computation();
//     //    println!("{:?}", ppp.generators[0]);
//     //    assert_ne!(pp,ppp)
//     assert!(false)
// }

#[test]
fn test_read_param() {
    let mut f = std::fs::File::open("default.param").unwrap();

    let _t = VeccomParams::deserialize(&mut f, true);
}
