use ff::{Field, PrimeField};
use pairing::bls12_381::*;
use pairings::hash_to_field_pointproofs::os2ip_mod_p;

// examples from
// https://crypto.stackexchange.com/questions/37537/what-are-i2osp-os2ip-in-rsa-pkcs1
//  0  ->  00:00
//  1  ->  00:01
// 255  ->  00:FF
// 256  ->  01:00
// 65535  ->  FF:FF
#[test]
fn test_os2ip() {
    assert_eq!(
        Fr::from_str("0").unwrap(),
        Fr::from_repr(os2ip_mod_p(&[0u8, 0u8])).unwrap()
    );
    assert_eq!(
        Fr::from_str("1").unwrap(),
        Fr::from_repr(os2ip_mod_p(&[0u8, 1u8])).unwrap()
    );
    assert_eq!(
        Fr::from_str("255").unwrap(),
        Fr::from_repr(os2ip_mod_p(&[0u8, 0xffu8])).unwrap()
    );
    assert_eq!(
        Fr::from_str("256").unwrap(),
        Fr::from_repr(os2ip_mod_p(&[1u8, 0u8])).unwrap()
    );
    assert_eq!(
        Fr::from_str("65535").unwrap(),
        Fr::from_repr(os2ip_mod_p(&[0xffu8, 0xffu8])).unwrap()
    );

    assert_eq!(Fr::from_repr(FrRepr([1, 0, 0, 0])).unwrap(), Fr::one());
}
