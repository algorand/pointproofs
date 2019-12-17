//! This file is part of the veccom crate.
//! It exposes Rust APIs to C.

extern crate libc;
use pairing::serdes::SerDes;
use pairings::*;
use std::ffi;
use std::slice;

/// non-serialized
#[repr(C)]
pub struct vcp_params {
    prover: vcp_pp,
    verifier: vcp_vp,
}

/// values
#[repr(C)]
pub struct vcp_value {
    data: *const u8,
    len: libc::size_t,
}

/// serialized prover parameter struct
#[repr(C)]
pub struct vcp_pp_bytes {
    data: [u8; RAW_PP_LEN],
}

/// serialized verifer parameter struct
#[repr(C)]
pub struct vcp_vp_bytes {
    data: [u8; VP_LEN],
}

/// deserialized prover parameter struct
#[repr(C)]
pub struct vcp_pp {
    data: *mut ffi::c_void,
}

/// deserialized verifier parameter struct
#[repr(C)]
pub struct vcp_vp {
    data: *mut ffi::c_void,
}

/// serialized commitment struct
#[repr(C)]
pub struct vcp_commitment_bytes {
    data: [u8; COMMIT_LEN],
}

/// deserialized commitment struct
#[repr(C)]
pub struct vcp_commitment {
    data: *mut ffi::c_void,
}

/// serialized proof struct
#[repr(C)]
pub struct vcp_proof_bytes {
    data: [u8; PROOF_LEN],
}

/// deserialized proof struct
#[repr(C)]
pub struct vcp_proof {
    data: *mut ffi::c_void,
}

/// Serializing a prove parameter into bytes
#[no_mangle]
pub unsafe extern "C" fn vcp_pp_serial(pprover: vcp_pp) -> vcp_pp_bytes {
    let pprover = &*(pprover.data as *const ProverParams);
    let mut buf: Vec<u8> = vec![];
    assert!(
        pprover.serialize(&mut buf, true).is_ok(),
        "prover parameter serialization failed"
    );
    buf.shrink_to_fit();
    let mut data = [0u8; RAW_PP_LEN];
    data.copy_from_slice(&buf);
    vcp_pp_bytes { data }
}

/// Deserializing bytes into prover parameters
#[no_mangle]
pub unsafe extern "C" fn vcp_pp_deserial(mut pprover: vcp_pp_bytes) -> vcp_pp {
    let pp = match ProverParams::deserialize(&mut pprover.data[..].as_ref(), true) {
        Ok(p) => p,
        Err(e) => panic!("prover parameter deserialization failed {}", e),
    };
    let buf_box = Box::new(pp);
    let pp_ptr = Box::into_raw(buf_box) as *mut ffi::c_void;
    vcp_pp { data: pp_ptr }
}

/// Serializing a verifier parameter into bytes
#[no_mangle]
pub unsafe extern "C" fn vcp_vp_serial(pverifier: vcp_vp) -> vcp_vp_bytes {
    let pverifier = &*(pverifier.data as *const VerifierParams);
    let mut buf: Vec<u8> = vec![];
    assert!(
        pverifier.serialize(&mut buf, true).is_ok(),
        "verifier parameter serialization failed"
    );
    buf.shrink_to_fit();
    let mut data = [0u8; VP_LEN];
    data.copy_from_slice(&buf);
    vcp_vp_bytes { data }
}

/// Deserializing bytes into verifier parameters
#[no_mangle]
pub unsafe extern "C" fn vcp_vp_deserial(mut pverifier: vcp_vp_bytes) -> vcp_vp {
    let vp = match VerifierParams::deserialize(&mut pverifier.data[..].as_ref(), true) {
        Ok(p) => p,
        Err(e) => panic!("verifier parameter deserialization failed {}", e),
    };
    let buf_box = Box::new(vp);
    let vp_ptr = Box::into_raw(buf_box) as *mut ffi::c_void;
    vcp_vp { data: vp_ptr }
}

/// Serializing commitments into bytes
#[no_mangle]
pub unsafe extern "C" fn vcp_commit_serial(commit: vcp_commitment) -> vcp_commitment_bytes {
    let com = &*(commit.data as *const Commitment);
    let mut buf: Vec<u8> = vec![];
    assert!(
        com.serialize(&mut buf, true).is_ok(),
        "commitment serialization failed"
    );
    buf.shrink_to_fit();
    let mut data = [0u8; COMMIT_LEN];
    data.copy_from_slice(&buf);
    vcp_commitment_bytes { data }
}

/// Deserializeing bytes into commitments
#[no_mangle]
pub unsafe extern "C" fn vcp_commit_deserial(mut commit: vcp_commitment_bytes) -> vcp_commitment {
    let com = match Commitment::deserialize(&mut commit.data[..].as_ref(), true) {
        Ok(p) => p,
        Err(e) => panic!("Commitment deserialization failed {}", e),
    };
    let buf_box = Box::new(com);

    vcp_commitment {
        data: Box::into_raw(buf_box) as *mut ffi::c_void,
    }
}

/// Serializing proofs into bytes
#[no_mangle]
pub unsafe extern "C" fn vcp_proof_serial(proof: vcp_proof) -> vcp_proof_bytes {
    let proof = &*(proof.data as *const Proof);
    let mut buf: Vec<u8> = vec![];
    assert!(
        proof.serialize(&mut buf, true).is_ok(),
        "proof serialization failed"
    );
    buf.shrink_to_fit();
    let mut data = [0u8; PROOF_LEN];
    data.copy_from_slice(&buf);
    vcp_proof_bytes { data }
}

/// Deserializeing bytes into proofs
#[no_mangle]
pub unsafe extern "C" fn vcp_proof_deserial(mut proof: vcp_proof_bytes) -> vcp_proof {
    let proof = match Proof::deserialize(&mut proof.data[..].as_ref(), true) {
        Ok(p) => p,
        Err(e) => panic!("Proof deserialization failed {}", e),
    };
    let buf_box = Box::new(proof);

    vcp_proof {
        data: Box::into_raw(buf_box) as *mut ffi::c_void,
    }
}

/// Generating a pair of parameters
#[no_mangle]
pub unsafe extern "C" fn vcp_paramgen(
    seedbuf: *const u8,
    seedlen: libc::size_t,
    ciphersuite: u8,
    n: libc::size_t,
) -> vcp_params {
    let seed = slice::from_raw_parts(seedbuf, seedlen);
    let (pp, vp) = param::paramgen_from_seed(seed, ciphersuite, n).unwrap();

    let buf_box = Box::new(pp);
    let pp_ptr = Box::into_raw(buf_box) as *mut ffi::c_void;
    let buf_box = Box::new(vp);
    let vp_ptr = Box::into_raw(buf_box) as *mut ffi::c_void;

    vcp_params {
        prover: vcp_pp { data: pp_ptr },
        verifier: vcp_vp { data: vp_ptr },
    }
}

/// Free prover parameter
#[no_mangle]
pub unsafe extern "C" fn vcp_free_prover_params(pp: vcp_pp) {
    Box::from_raw(pp.data);
}

/// Free verifier parameter
#[no_mangle]
pub unsafe extern "C" fn vcp_free_verifier_params(vp: vcp_vp) {
    Box::from_raw(vp.data);
}

/// Free commitment
#[no_mangle]
pub unsafe extern "C" fn vcp_free_commit(commit: vcp_commitment) {
    Box::from_raw(commit.data);
}

/// Free proof
#[no_mangle]
pub unsafe extern "C" fn vcp_free_proof(proof: vcp_proof) {
    Box::from_raw(proof.data);
}

fn vcp_value_slice<'a>(vv: &vcp_value) -> &'a [u8] {
    unsafe { slice::from_raw_parts(vv.data, vv.len) }
}

/// Generate a commitment
#[no_mangle]
pub unsafe extern "C" fn vcp_commit(
    prover: vcp_pp,
    values: *const vcp_value,
    n: usize,
) -> vcp_commitment {
    let pprover = &*(prover.data as *const ProverParams);
    let tmp = slice::from_raw_parts::<vcp_value>(values, n);
    let mut vvalues: Vec<Vec<u8>> = vec![];
    for e in tmp {
        vvalues.push(vcp_value_slice(&e).to_vec());
    }

    let com = Commitment::new(pprover, &vvalues).unwrap();
    let buf_box = Box::new(com);

    vcp_commitment {
        data: Box::into_raw(buf_box) as *mut ffi::c_void,
    }
}

/// Generate a proof
#[no_mangle]
pub unsafe extern "C" fn vcp_prove(
    prover: vcp_pp,
    values: *const vcp_value,
    n: usize,
    idx: libc::size_t,
) -> vcp_proof {
    let pprover = &*(prover.data as *const ProverParams);
    let tmp = slice::from_raw_parts::<vcp_value>(values, n);
    let mut vvalues: Vec<Vec<u8>> = vec![];
    for e in tmp {
        vvalues.push(vcp_value_slice(&e).to_vec());
    }

    let proof = Proof::new(pprover, &vvalues, idx).unwrap();
    let buf_box = Box::new(proof);

    vcp_proof {
        data: Box::into_raw(buf_box) as *mut ffi::c_void,
    }
}

/// update an existing proof
#[no_mangle]
pub unsafe extern "C" fn vcp_proof_update(
    prover: vcp_pp,
    proof: vcp_proof,
    idx: libc::size_t,
    changed_idx: libc::size_t,
    val_old: vcp_value,
    val_new: vcp_value,
) -> vcp_proof {
    let pprover = &*(prover.data as *const ProverParams);
    let pproof = &*(proof.data as *const Proof);
    let value_before = vcp_value_slice(&val_old);
    let value_after = vcp_value_slice(&val_new);

    let mut new_proof = pproof.clone();

    new_proof
        .update(pprover, idx, changed_idx, value_before, value_after)
        .unwrap();
    let buf_box = Box::new(new_proof);
    vcp_proof {
        data: Box::into_raw(buf_box) as *mut ffi::c_void,
    }
}

/// update an existing commitment
#[no_mangle]
pub unsafe extern "C" fn vcp_commit_update(
    prover: vcp_pp,
    com: vcp_commitment,
    changed_idx: libc::size_t,
    val_old: vcp_value,
    val_new: vcp_value,
) -> vcp_commitment {
    let pprover = &*(prover.data as *const ProverParams);
    let pcom = &*(com.data as *const Commitment);
    let value_before = vcp_value_slice(&val_old);
    let value_after = vcp_value_slice(&val_new);
    let mut new_com = pcom.clone();
    new_com
        .update(pprover, changed_idx, value_before, value_after)
        .unwrap();
    let buf_box = Box::new(new_com);
    vcp_commitment {
        data: Box::into_raw(buf_box) as *mut ffi::c_void,
    }
}

/// verify the proof against the value and commitment
#[no_mangle]
pub unsafe extern "C" fn vcp_verify(
    verifier: vcp_vp,
    com: vcp_commitment,
    proof: vcp_proof,
    value: vcp_value,
    idx: libc::size_t,
) -> bool {
    let pverifier = &*(verifier.data as *const VerifierParams);
    let pcom = &*(com.data as *const Commitment);
    let pproof = &*(proof.data as *const Proof);
    let val = vcp_value_slice(&value);

    pproof.verify(pverifier, pcom, val, idx)
}

/// aggregate proofs within a same commitment
#[no_mangle]
pub unsafe extern "C" fn vcp_same_commit_aggregate(
    com: vcp_commitment,
    proofs: *const vcp_proof,
    set: *const libc::size_t,
    values: *const vcp_value,
    nvalues: libc::size_t,
    param_n: libc::size_t,
) -> vcp_proof {
    // parse commit
    let pcom = &*(com.data as *const Commitment);

    // parse proofs
    let tmp = slice::from_raw_parts::<vcp_proof>(proofs, nvalues);
    let mut proof_list: Vec<Proof> = vec![];
    for e in tmp {
        proof_list.push((*(e.data as *const Proof)).clone());
    }

    // parse indices
    let tmp = slice::from_raw_parts::<libc::size_t>(set, nvalues);
    let mut set_list: Vec<usize> = vec![];
    for e in tmp {
        set_list.push(*e);
    }

    // parse values
    let tmp = slice::from_raw_parts::<vcp_value>(values, nvalues);
    let mut vvalues: Vec<Vec<u8>> = vec![];
    for e in tmp {
        vvalues.push(vcp_value_slice(&e).to_vec());
    }

    let agg_proof =
        match Proof::same_commit_aggregate(&pcom, &proof_list, &set_list, &vvalues, param_n) {
            Ok(p) => p,
            Err(e) => panic!("C wrapper, same commit aggregation failed: {}", e),
        };
    let buf_box = Box::new(agg_proof);
    vcp_proof {
        data: Box::into_raw(buf_box) as *mut ffi::c_void,
    }
}

/// verify an aggregated proof within a same commitment
#[no_mangle]
pub unsafe extern "C" fn vcp_same_commit_batch_verify(
    verifier: vcp_vp,
    com: vcp_commitment,
    proof: vcp_proof,
    set: *const libc::size_t,
    values: *const vcp_value,
    nvalues: libc::size_t,
) -> bool {
    let pverifier = &*(verifier.data as *const VerifierParams);
    let pcom = &*(com.data as *const Commitment);
    let pproof = &*(proof.data as *const Proof);

    // parse indices
    let tmp = slice::from_raw_parts::<libc::size_t>(set, nvalues);
    let mut set_list: Vec<usize> = vec![];
    for e in tmp {
        set_list.push(*e);
    }

    // parse values
    let tmp = slice::from_raw_parts::<vcp_value>(values, nvalues);
    let mut vvalues: Vec<Vec<u8>> = vec![];
    for e in tmp {
        vvalues.push(vcp_value_slice(&e).to_vec());
    }

    pproof.same_commit_batch_verify(pverifier, pcom, &set_list, &vvalues)
}
