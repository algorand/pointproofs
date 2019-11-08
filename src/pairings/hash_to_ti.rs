/// this mod defines the hash_to_field functions that are more efficient than
/// simply using bls::hash_to_field
use super::ciphersuite::*;
use super::err::*;
use super::Commitment;
use bigint::U512;

use pairing::bls12_381::*;
use pairing::serdes::SerDes;
use sha2::{Digest, Sha512};
use std::ops::Rem;

// input: the commitment
// input: a list of indices, for which we need to generate t_i
// input: Value: the messages that is commited to
// output: a list of field elements
pub fn get_ti_new<Blob: AsRef<[u8]>>(
    commit: &Commitment,
    set: &[usize],
    value_sub_vector: &[Blob],
) -> Result<Vec<FrRepr>, String> {
    let sp = get_system_paramter(commit.ciphersuite)?;

    // tmp = C | S | m[S]
    let mut tmp: Vec<u8> = vec![];
    // serialize commitment
    match commit.serialize(&mut tmp, true) {
        Ok(_p) => _p,
        Err(e) => return Err(e.to_string()),
    };
    // add the set to tmp
    for index in set {
        let t = index.to_be_bytes();
        tmp.append(&mut t.to_vec());
    }

    if set.len() != value_sub_vector.len() {
        return Err(ERR_INDEX_PROOF_NOT_MATCH.to_owned());
    }

    // add values to set; returns an error if index is out of range
    for i in 0..set.len() {
        if set[i] >= sp.n {
            return Err(ERR_INVALID_INDEX.to_owned());
        }
        let t = value_sub_vector[i].as_ref();
        tmp.append(&mut t.to_vec());
    }

    let mut hasher = Sha512::new();
    hasher.input(tmp);
    let digest = hasher.result();

    // formulate the output
    let mut res: Vec<FrRepr> = vec![];
    for index in set {
        // each field element t_i is generated as
        // t_i = hash_to_field (i | C | S | m[S])
        let hash_input = [index.to_be_bytes().to_vec()[..].as_ref(), digest.as_ref()].concat();
        let mut hasher2 = Sha512::new();
        hasher2.input(hash_input);
        let hash_output = hasher2.result();
        res.push(os2ip_mod_p(&hash_output));
    }

    Ok(res)
}

/// this is pixel's Octect String to Integer Primitive (os2ip) function
/// https://tools.ietf.org/html/rfc8017#section-4
/// the input is a 64 bytes array, and the output is between 0 and p-1
/// i.e., it performs mod operation by default.
fn os2ip_mod_p(oct_str: &[u8]) -> FrRepr {
    // "For the purposes of this document, and consistent with ASN.1 syntax,
    // an octet string is an ordered sequence of octets (eight-bit bytes).
    // The sequence is indexed from first (conventionally, leftmost) to last
    // (rightmost).  For purposes of conversion to and from integers, the
    // first octet is considered the most significant in the following
    // conversion primitives.
    //
    // OS2IP converts an octet string to a nonnegative integer.
    // OS2IP (X)
    // Input:  X octet string to be converted
    // Output:  x corresponding nonnegative integer
    // Steps:
    // 1.  Let X_1 X_2 ... X_xLen be the octets of X from first to last,
    //  and let x_(xLen-i) be the integer value of the octet X_i for 1
    //  <= i <= xLen.
    // 2.  Let x = x_(xLen-1) 256^(xLen-1) + x_(xLen-2) 256^(xLen-2) +
    //  ...  + x_1 256 + x_0.
    // 3.  Output x. "

    // TODO: review and test this function.

    let r_sec = U512::from(oct_str);

    // hard coded modulus p
    let p = U512::from([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0x73, 0xED, 0xA7, 0x53, 0x29, 0x9D, 0x7D, 0x48, 0x33, 0x39, 0xD8, 0x08, 0x09, 0xA1,
        0xD8, 0x05, 0x53, 0xBD, 0xA4, 0x02, 0xFF, 0xFE, 0x5B, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0x00,
        0x00, 0x00, 0x01,
    ]);
    // t = r % p
    let t_sec = r_sec.rem(p);

    // convert t from a U512 into a primefield object s
    let mut tslide: [u8; 64] = [0; 64];
    let bytes: &mut [u8] = tslide.as_mut();
    t_sec.to_big_endian(bytes);

    let s = FrRepr([
        u64::from_be_bytes([
            bytes[56], bytes[57], bytes[58], bytes[59], bytes[60], bytes[61], bytes[62], bytes[63],
        ]),
        u64::from_be_bytes([
            bytes[48], bytes[49], bytes[50], bytes[51], bytes[52], bytes[53], bytes[54], bytes[55],
        ]),
        u64::from_be_bytes([
            bytes[40], bytes[41], bytes[42], bytes[43], bytes[44], bytes[45], bytes[46], bytes[47],
        ]),
        u64::from_be_bytes([
            bytes[32], bytes[33], bytes[34], bytes[35], bytes[36], bytes[37], bytes[38], bytes[39],
        ]),
    ]);
    s
    //Fr::from_repr(s).unwrap()
}

// examples from
// https://crypto.stackexchange.com/questions/37537/what-are-i2osp-os2ip-in-rsa-pkcs1
//  0  ->  00:00
//  1  ->  00:01
// 255  ->  00:FF
// 256  ->  01:00
// 65535  ->  FF:FF
#[test]
fn test_os2ip() {
    use ff::PrimeField;
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
}
