//! this file is part of the pointproofs.
//! It defines the hash_to_field functions that are more efficient than `bls::hash_to_field`
//! The algorithms are described here:
//! https://github.com/algorand/pointproofs/blob/master/SPEC.md#hashes
use bigint::U512;
use ff::PrimeField;
use pairing::bls12_381::*;
use pairing::serdes::SerDes;
use pairings::err::*;
use pairings::param::*;
use pairings::Commitment;
use sha2::{Digest, Sha512};
use std::ops::Rem;

// A wrapper of `hash_to_tj_repr` that outputs `Fr`s instead of `FrRepr`s.
/// * input: a list of k commitments
/// * input: a list of k * x indices, for which we need to generate t_j
/// * input: Value: a list of k * x messages that is commited to
/// * output: a list of k field elements
pub(crate) fn hash_to_tj_fr<Blob: AsRef<[u8]>>(
    commits: &[Commitment],
    set: &[Vec<usize>],
    value_sub_vector: &[Vec<Blob>],
    n: usize,
) -> Result<Vec<Fr>, String> {
    Ok(hash_to_tj_repr(commits, set, value_sub_vector, n)?
        .iter()
        // the hash_to_ti_repr should already produce valid Fr elements
        // so it is safe to unwrap here
        .map(|s| Fr::from_repr(*s).unwrap())
        .collect())
}

/// Hash a two dim array of bytes into non-zero scalars. An internal function for aggregation
/// and batch verification.
/// * input: a list of k commitments
/// * input: a list of k * x indices, for which we need to generate t_j
/// * input: Value: a list of k * x messages that is commited to
/// * output: a list of k field elements
pub(crate) fn hash_to_tj_repr<Blob: AsRef<[u8]>>(
    commits: &[Commitment],
    set: &[Vec<usize>],
    value_sub_vector: &[Vec<Blob>],
    n: usize,
) -> Result<Vec<FrRepr>, String> {
    // check the length are correct
    if commits.len() != set.len() || commits.len() != value_sub_vector.len() {
        return Err(ERR_X_COM_SIZE.to_owned());
    };

    // check the ciphersuite is supported
    for e in commits {
        if !check_ciphersuite(e.ciphersuite) {
            return Err(ERR_CIPHERSUITE.to_owned());
        }
    }

    // handle the case where there is only one input
    // in this case, simply return FrRepr::one()
    if commits.len() == 1 {
        return Ok(vec![FrRepr([1, 0, 0, 0])]);
    }

    // tmp = {C | S | m[S]} for i \in [0 .. commit.len-1]
    let mut tmp: Vec<u8> = vec![];
    for i in 0..commits.len() {
        // serialize commitment
        match commits[i].serialize(&mut tmp, true) {
            Ok(_p) => _p,
            Err(e) => return Err(e.to_string()),
        };
        // add the set to tmp
        for j in 0..set[i].len() {
            let t = set[i][j].to_be_bytes();
            tmp.append(&mut t.to_vec());
        }

        // if the set leng does not mathc values, return an error
        if set[i].len() != value_sub_vector[i].len() {
            return Err(ERR_INDEX_PROOF_NOT_MATCH.to_owned());
        }

        // add values to set; returns an error if index is out of range
        for j in 0..set[i].len() {
            if set[i][j] >= n {
                return Err(ERR_INVALID_INDEX.to_owned());
            }
            let t = value_sub_vector[i][j].as_ref();
            tmp.append(&mut t.to_vec());
        }
    }

    let mut hasher = Sha512::new();
    hasher.input(tmp);
    let digest = hasher.result();

    // formulate the output
    Ok((0..commits.len())
        .map(|i| {
            // each field element t_i is generated as
            // t_i = hash_to_field (i | C | S | m[S])
            hash_to_field_repr_pointproofs([&i.to_be_bytes()[..], digest.as_ref()].concat())
        })
        .collect::<Vec<FrRepr>>())
}

// A wrapper of `hash_to_ti` that outputs `Fr`s instead of `FrRepr`s.
// * input: the commitment
// * input: a list of indices, for which we need to generate t_i
// * input: Value: the messages that is commited to
// * output: a list of field elements
pub(crate) fn hash_to_ti_fr<Blob: AsRef<[u8]>>(
    commit: &Commitment,
    set: &[usize],
    value_sub_vector: &[Blob],
    n: usize,
) -> Result<Vec<Fr>, String> {
    Ok(hash_to_ti_repr(commit, set, value_sub_vector, n)?
        .iter()
        // the hash_to_ti_repr should already produce valid Fr elements
        // so it is safe to unwrap here
        .map(|s| Fr::from_repr(*s).unwrap())
        .collect())
}

/// Hash a array of bytes into non-zero scalars. An internal function for aggregation
/// and batch verification.
/// * input: the commitment
/// * input: a list of indices, for which we need to generate t_i
/// * input: Value: the messages that is commited to
/// * output: a list of field elements
pub(crate) fn hash_to_ti_repr<Blob: AsRef<[u8]>>(
    commit: &Commitment,
    set: &[usize],
    value_sub_vector: &[Blob],
    n: usize,
) -> Result<Vec<FrRepr>, String> {
    if !check_ciphersuite(commit.ciphersuite) {
        return Err(ERR_CIPHERSUITE.to_owned());
    }
    // if the set leng does not mathc values, return an error
    if set.len() != value_sub_vector.len() {
        return Err(ERR_INVALID_INDEX.to_owned());
    }

    // handle the case where there is only one input
    // in this case, simply return FrRepr::one()
    if set.len() == 1 {
        return Ok(vec![FrRepr([1, 0, 0, 0])]);
    }

    // add values to set; returns an error if index is out of range
    for e in set {
        if *e >= n {
            return Err(ERR_INVALID_INDEX.to_owned());
        }
    }

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
    // add values to set; returns an error if index is out of range
    for e in value_sub_vector {
        let t = e.as_ref();
        tmp.append(&mut t.to_vec());
    }

    let mut hasher = Sha512::new();
    hasher.input(tmp);
    let digest = hasher.result();

    // formulate the output
    Ok(set
        .iter()
        .map(|index| {
            hash_to_field_repr_pointproofs([&index.to_be_bytes()[..], digest.as_ref()].concat())
        })
        .collect())
}

/// A wrapper of `hash_to_field` that outputs `Fr`s instead of `FrRepr`s.
/// hash_to_field_pointproofs use SHA 512 to hash a blob into a non-zero field element
pub(crate) fn hash_to_field_pointproofs<Blob: AsRef<[u8]>>(input: Blob) -> Fr {
    // the hash_to_field_repr_pointproofs should already produce a valid Fr element
    // so it is safe to unwrap here
    Fr::from_repr(hash_to_field_repr_pointproofs(input.as_ref())).unwrap()
}

/// Hashes a blob into a non-zero field element.
/// hash_to_field_pointproofs use SHA 512 to hash a blob into a non-zero field element.
pub(crate) fn hash_to_field_repr_pointproofs<Blob: AsRef<[u8]>>(input: Blob) -> FrRepr {
    let mut hasher = Sha512::new();
    hasher.input(input);
    let hash_output = hasher.result();
    let mut t = os2ip_mod_p(&hash_output);

    // if we get 0, return 1
    // this should not happen in practise
    if t == FrRepr([0, 0, 0, 0]) {
        t = FrRepr([1, 0, 0, 0]);
    }
    t
}

/// this is Pointproofs's Octect String to Integer Primitive (os2ip) function
/// https://tools.ietf.org/html/rfc8017#section-4
/// the input is a 64 bytes array, and the output is between 0 and p-1
/// i.e., it performs mod operation by default.
pub(crate) fn os2ip_mod_p(oct_str: &[u8]) -> FrRepr {
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

    FrRepr([
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
    ])
}
