//! this file is part of the pointproofs.
//! it exposes Rust APIs to C.

extern crate libc;
use pairing::serdes::SerDes;
use pairings::*;
use std::ffi;
use std::slice;

/// non-serialized
#[repr(C)]
pub struct pointproofs_params {
    pub(crate) prover: pointproofs_pp,
    pub(crate) verifier: pointproofs_vp,
}

/// values
#[repr(C)]
#[derive(Clone)]
pub struct pointproofs_value {
    pub(crate) data: *const u8,
    pub(crate) len: libc::size_t,
}

/// serialized prover parameter struct
#[repr(C)]
pub struct pointproofs_pp_bytes {
    data: [u8; PP_LEN],
}

/// serialized verifer parameter struct
#[repr(C)]
pub struct pointproofs_vp_bytes {
    data: [u8; VP_LEN],
}

/// deserialized prover parameter struct
#[repr(C)]
#[derive(Clone)]
pub struct pointproofs_pp {
    data: *mut ffi::c_void,
}

/// deserialized verifier parameter struct
#[repr(C)]
#[derive(Clone)]
pub struct pointproofs_vp {
    data: *mut ffi::c_void,
}

/// serialized commitment struct
#[repr(C)]
#[derive(Clone)]
pub struct pointproofs_commitment_bytes {
    pub(crate) data: [u8; COMMIT_LEN],
}

/// deserialized commitment struct
#[repr(C)]
#[derive(Clone)]
pub struct pointproofs_commitment {
    data: *mut ffi::c_void,
}

/// serialized proof struct
#[repr(C)]
#[derive(Clone)]
pub struct pointproofs_proof_bytes {
    pub(crate) data: [u8; PROOF_LEN],
}

/// deserialized proof struct
#[repr(C)]
#[derive(Clone)]
pub struct pointproofs_proof {
    data: *mut ffi::c_void,
}

/// Serializing a prove parameter into bytes
#[no_mangle]
pub unsafe extern "C" fn pointproofs_pp_serial(pprover: pointproofs_pp) -> pointproofs_pp_bytes {
    let pprover = &*(pprover.data as *const ProverParams);
    let mut buf: Vec<u8> = vec![];
    assert!(
        pprover.serialize(&mut buf, true).is_ok(),
        "prover parameter serialization failed"
    );
    buf.shrink_to_fit();
    let mut data = [0u8; PP_LEN];
    data.copy_from_slice(&buf);
    pointproofs_pp_bytes { data }
}

/// Deserializing bytes into prover parameters
#[no_mangle]
pub unsafe extern "C" fn pointproofs_pp_deserial(
    mut pprover: pointproofs_pp_bytes,
) -> pointproofs_pp {
    let pp = match ProverParams::deserialize(&mut pprover.data[..].as_ref(), true) {
        Ok(p) => p,
        Err(e) => panic!("prover parameter deserialization failed {}", e),
    };
    let buf_box = Box::new(pp);
    let pp_ptr = Box::into_raw(buf_box) as *mut ffi::c_void;
    pointproofs_pp { data: pp_ptr }
}

/// Serializing a verifier parameter into bytes
#[no_mangle]
pub unsafe extern "C" fn pointproofs_vp_serial(pverifier: pointproofs_vp) -> pointproofs_vp_bytes {
    let pverifier = &*(pverifier.data as *const VerifierParams);
    let mut buf: Vec<u8> = vec![];
    assert!(
        pverifier.serialize(&mut buf, true).is_ok(),
        "verifier parameter serialization failed"
    );
    buf.shrink_to_fit();
    let mut data = [0u8; VP_LEN];
    data.copy_from_slice(&buf);
    pointproofs_vp_bytes { data }
}

/// Deserializing bytes into verifier parameters
#[no_mangle]
pub unsafe extern "C" fn pointproofs_vp_deserial(
    mut pverifier: pointproofs_vp_bytes,
) -> pointproofs_vp {
    let vp = match VerifierParams::deserialize(&mut pverifier.data[..].as_ref(), true) {
        Ok(p) => p,
        Err(e) => panic!("verifier parameter deserialization failed {}", e),
    };
    let buf_box = Box::new(vp);
    let vp_ptr = Box::into_raw(buf_box) as *mut ffi::c_void;
    pointproofs_vp { data: vp_ptr }
}

/// Serializing commitments into bytes
#[no_mangle]
pub unsafe extern "C" fn pointproofs_commit_serial(
    commit: pointproofs_commitment,
) -> pointproofs_commitment_bytes {
    let com = &*(commit.data as *const Commitment);
    let mut buf: Vec<u8> = vec![];
    assert!(
        com.serialize(&mut buf, true).is_ok(),
        "commitment serialization failed"
    );
    buf.shrink_to_fit();
    let mut data = [0u8; COMMIT_LEN];
    data.copy_from_slice(&buf);
    pointproofs_commitment_bytes { data }
}

/// Deserializeing bytes into commitments
#[no_mangle]
pub unsafe extern "C" fn pointproofs_commit_deserial(
    mut commit: pointproofs_commitment_bytes,
) -> pointproofs_commitment {
    let com = match Commitment::deserialize(&mut commit.data[..].as_ref(), true) {
        Ok(p) => p,
        Err(e) => panic!("Commitment deserialization failed {}", e),
    };
    let buf_box = Box::new(com);

    pointproofs_commitment {
        data: Box::into_raw(buf_box) as *mut ffi::c_void,
    }
}

/// Serializing proofs into bytes
#[no_mangle]
pub unsafe extern "C" fn pointproofs_proof_serial(
    proof: pointproofs_proof,
) -> pointproofs_proof_bytes {
    let proof = &*(proof.data as *const Proof);
    let mut buf: Vec<u8> = vec![];
    assert!(
        proof.serialize(&mut buf, true).is_ok(),
        "proof serialization failed"
    );
    buf.shrink_to_fit();
    let mut data = [0u8; PROOF_LEN];
    data.copy_from_slice(&buf);
    pointproofs_proof_bytes { data }
}

/// Deserializeing bytes into proofs
#[no_mangle]
pub unsafe extern "C" fn pointproofs_proof_deserial(
    mut proof: pointproofs_proof_bytes,
) -> pointproofs_proof {
    let proof = match Proof::deserialize(&mut proof.data[..].as_ref(), true) {
        Ok(p) => p,
        Err(e) => panic!("Proof deserialization failed {}", e),
    };
    let buf_box = Box::new(proof);

    pointproofs_proof {
        data: Box::into_raw(buf_box) as *mut ffi::c_void,
    }
}

/// Generating a pair of parameters
#[no_mangle]
pub unsafe extern "C" fn pointproofs_paramgen(
    seedbuf: *const u8,
    seedlen: libc::size_t,
    ciphersuite: u8,
    n: libc::size_t,
) -> pointproofs_params {
    let seed = slice::from_raw_parts(seedbuf, seedlen);
    let (pp, vp) = param::paramgen_from_seed(seed, ciphersuite, n).unwrap();

    let buf_box = Box::new(pp);
    let pp_ptr = Box::into_raw(buf_box) as *mut ffi::c_void;
    let buf_box = Box::new(vp);
    let vp_ptr = Box::into_raw(buf_box) as *mut ffi::c_void;

    pointproofs_params {
        prover: pointproofs_pp { data: pp_ptr },
        verifier: pointproofs_vp { data: vp_ptr },
    }
}

/// Free prover parameter
#[no_mangle]
pub unsafe extern "C" fn pointproofs_free_prover_params(pp: pointproofs_pp) {
    Box::from_raw(pp.data);
}

/// Free verifier parameter
#[no_mangle]
pub unsafe extern "C" fn pointproofs_free_verifier_params(vp: pointproofs_vp) {
    Box::from_raw(vp.data);
}

/// Free commitment
#[no_mangle]
pub unsafe extern "C" fn pointproofs_free_commit(commit: pointproofs_commitment) {
    Box::from_raw(commit.data);
}

/// Free proof
#[no_mangle]
pub unsafe extern "C" fn pointproofs_free_proof(proof: pointproofs_proof) {
    Box::from_raw(proof.data);
}

fn pointproofs_value_slice<'a>(vv: &pointproofs_value) -> &'a [u8] {
    unsafe { slice::from_raw_parts(vv.data, vv.len) }
}

/// Generate a commitment
#[no_mangle]
pub unsafe extern "C" fn pointproofs_commit(
    prover: pointproofs_pp,
    values: *const pointproofs_value,
    n: usize,
) -> pointproofs_commitment {
    let pprover = &*(prover.data as *const ProverParams);
    let tmp = slice::from_raw_parts::<pointproofs_value>(values, n);
    let mut vvalues: Vec<Vec<u8>> = vec![];
    for e in tmp {
        vvalues.push(pointproofs_value_slice(&e).to_vec());
    }

    let com = Commitment::new(pprover, &vvalues).unwrap();
    let buf_box = Box::new(com);

    pointproofs_commitment {
        data: Box::into_raw(buf_box) as *mut ffi::c_void,
    }
}

/// Generate a proof
#[no_mangle]
pub unsafe extern "C" fn pointproofs_prove(
    prover: pointproofs_pp,
    values: *const pointproofs_value,
    n: usize,
    idx: libc::size_t,
) -> pointproofs_proof {
    let pprover = &*(prover.data as *const ProverParams);
    let tmp = slice::from_raw_parts::<pointproofs_value>(values, n);
    let mut vvalues: Vec<Vec<u8>> = vec![];
    for e in tmp {
        vvalues.push(pointproofs_value_slice(&e).to_vec());
    }

    let proof = Proof::new(pprover, &vvalues, idx).unwrap();
    let buf_box = Box::new(proof);

    pointproofs_proof {
        data: Box::into_raw(buf_box) as *mut ffi::c_void,
    }
}

/// Generate a proof
#[no_mangle]
pub unsafe extern "C" fn pointproofs_prove_batch_aggregated(
    prover: pointproofs_pp,
    commit: pointproofs_commitment,
    values: *const pointproofs_value,
    n: usize,
    idx: &[libc::size_t],
) -> pointproofs_proof {
    let pprover = &*(prover.data as *const ProverParams);
    let tmp = slice::from_raw_parts::<pointproofs_value>(values, n);
    let mut vvalues: Vec<Vec<u8>> = vec![];
    for e in tmp {
        vvalues.push(pointproofs_value_slice(&e).to_vec());
    }
    let pcom = &*(commit.data as *const Commitment);
    let proof = Proof::batch_new_aggregated(pprover, pcom, &vvalues, idx).unwrap();
    let buf_box = Box::new(proof);

    pointproofs_proof {
        data: Box::into_raw(buf_box) as *mut ffi::c_void,
    }
}

/// update an existing proof
#[no_mangle]
pub unsafe extern "C" fn pointproofs_proof_update(
    prover: pointproofs_pp,
    proof: pointproofs_proof,
    idx: libc::size_t,
    changed_idx: libc::size_t,
    val_old: pointproofs_value,
    val_new: pointproofs_value,
) -> pointproofs_proof {
    let pprover = &*(prover.data as *const ProverParams);
    let pproof = &*(proof.data as *const Proof);
    let value_before = pointproofs_value_slice(&val_old);
    let value_after = pointproofs_value_slice(&val_new);

    let mut new_proof = pproof.clone();

    new_proof
        .update(pprover, idx, changed_idx, value_before, value_after)
        .unwrap();
    let buf_box = Box::new(new_proof);
    pointproofs_proof {
        data: Box::into_raw(buf_box) as *mut ffi::c_void,
    }
}

/// update an existing commitment
#[no_mangle]
pub unsafe extern "C" fn pointproofs_commit_update(
    prover: pointproofs_pp,
    com: pointproofs_commitment,
    changed_idx: libc::size_t,
    val_old: pointproofs_value,
    val_new: pointproofs_value,
) -> pointproofs_commitment {
    let pprover = &*(prover.data as *const ProverParams);
    let pcom = &*(com.data as *const Commitment);
    let value_before = pointproofs_value_slice(&val_old);
    let value_after = pointproofs_value_slice(&val_new);
    let mut new_com = pcom.clone();
    new_com
        .update(pprover, changed_idx, value_before, value_after)
        .unwrap();
    let buf_box = Box::new(new_com);
    pointproofs_commitment {
        data: Box::into_raw(buf_box) as *mut ffi::c_void,
    }
}

/// verify the proof against the value and commitment
#[no_mangle]
pub unsafe extern "C" fn pointproofs_verify(
    verifier: pointproofs_vp,
    com: pointproofs_commitment,
    proof: pointproofs_proof,
    value: pointproofs_value,
    idx: libc::size_t,
) -> bool {
    let pverifier = &*(verifier.data as *const VerifierParams);
    let pcom = &*(com.data as *const Commitment);
    let pproof = &*(proof.data as *const Proof);
    let val = pointproofs_value_slice(&value);

    pproof.verify(pverifier, pcom, val, idx)
}

/// aggregate proofs within a same commitment
#[no_mangle]
pub unsafe extern "C" fn pointproofs_same_commit_aggregate(
    com: pointproofs_commitment,
    proofs: *const pointproofs_proof,
    set: *const libc::size_t,
    values: *const pointproofs_value,
    nvalues: libc::size_t,
    param_n: libc::size_t,
) -> pointproofs_proof {
    // parse commit
    let pcom = &*(com.data as *const Commitment);

    // parse proofs
    let tmp = slice::from_raw_parts::<pointproofs_proof>(proofs, nvalues);
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
    let tmp = slice::from_raw_parts::<pointproofs_value>(values, nvalues);
    let mut vvalues: Vec<Vec<u8>> = vec![];
    for e in tmp {
        vvalues.push(pointproofs_value_slice(&e).to_vec());
    }

    let agg_proof =
        match Proof::same_commit_aggregate(&pcom, &proof_list, &set_list, &vvalues, param_n) {
            Ok(p) => p,
            Err(e) => panic!("C wrapper, same commit aggregation failed: {}", e),
        };
    let buf_box = Box::new(agg_proof);
    pointproofs_proof {
        data: Box::into_raw(buf_box) as *mut ffi::c_void,
    }
}

/// verify an aggregated proof within a same commitment
#[no_mangle]
pub unsafe extern "C" fn pointproofs_same_commit_batch_verify(
    verifier: pointproofs_vp,
    com: pointproofs_commitment,
    proof: pointproofs_proof,
    set: *const libc::size_t,
    values: *const pointproofs_value,
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
    let tmp = slice::from_raw_parts::<pointproofs_value>(values, nvalues);
    let mut vvalues: Vec<Vec<u8>> = vec![];
    for e in tmp {
        vvalues.push(pointproofs_value_slice(&e).to_vec());
    }

    pproof.same_commit_batch_verify(pverifier, pcom, &set_list, &vvalues)
}

/// aggregated proofs cross commitments
#[no_mangle]
pub unsafe extern "C" fn pointproofs_x_commit_aggregate_full(
    com: *const pointproofs_commitment,
    proof: *const pointproofs_proof,
    set: *const libc::size_t,
    values: *const pointproofs_value,
    commit_indices: *const libc::size_t,
    no_commits: libc::size_t,
    param_n: libc::size_t,
) -> pointproofs_proof {
    // parse commits
    let tmp = slice::from_raw_parts::<pointproofs_commitment>(com, no_commits);
    let mut com_list: Vec<Commitment> = vec![];
    for e in tmp {
        com_list.push((*(e.data as *const Commitment)).clone());
    }

    // parse index counters
    let mut total = 0;
    let tmp = slice::from_raw_parts::<usize>(commit_indices, no_commits);
    let mut commit_indices_vec: Vec<usize> = vec![];
    for e in tmp {
        total += *e;
        commit_indices_vec.push(*e);
    }

    // parse indices, values and proofs as a 1-dim arrays
    let set_tmp = slice::from_raw_parts::<libc::size_t>(set, total);
    let value_tmp = slice::from_raw_parts::<pointproofs_value>(values, total);
    let proof_tmp = slice::from_raw_parts::<pointproofs_proof>(proof, total);

    // convert them into 2-dim arrays
    let mut set_list: Vec<Vec<usize>> = vec![];
    let mut value_list: Vec<Vec<Vec<u8>>> = vec![];
    let mut proof_list: Vec<Vec<Proof>> = vec![];
    let mut counter = 0;
    for e in commit_indices_vec {
        let mut set_list_within_com: Vec<usize> = vec![];
        let mut value_list_within_com: Vec<Vec<u8>> = vec![];
        let mut proof_list_within_com: Vec<Proof> = vec![];
        for _j in 0..e {
            set_list_within_com.push(set_tmp[counter]);
            value_list_within_com.push(pointproofs_value_slice(&value_tmp[counter]).to_vec());
            proof_list_within_com.push((*(proof_tmp[counter].data as *const Proof)).clone());
            counter += 1;
        }
        set_list.push(set_list_within_com);
        value_list.push(value_list_within_com);
        proof_list.push(proof_list_within_com);
    }

    let agg_proof = match Proof::cross_commit_aggregate_full(
        &com_list,
        &proof_list,
        &set_list,
        &value_list,
        param_n,
    ) {
        Ok(p) => p,
        Err(e) => panic!("C wrapper, x-commit aggregation failed: {}", e),
    };
    let buf_box = Box::new(agg_proof);
    pointproofs_proof {
        data: Box::into_raw(buf_box) as *mut ffi::c_void,
    }
}

/// aggregated proofs cross commitments
#[no_mangle]
pub unsafe extern "C" fn pointproofs_x_commit_aggregate_partial(
    com: *const pointproofs_commitment,
    agg_proof: *const pointproofs_proof,
    set: *const libc::size_t,
    values: *const pointproofs_value,
    commit_indices: *const libc::size_t,
    no_commits: libc::size_t,
    param_n: libc::size_t,
) -> pointproofs_proof {
    // parse commits
    let tmp = slice::from_raw_parts::<pointproofs_commitment>(com, no_commits);
    let mut com_list: Vec<Commitment> = vec![];
    for e in tmp {
        com_list.push((*(e.data as *const Commitment)).clone());
    }

    // parse index counters
    let mut total = 0;
    let tmp = slice::from_raw_parts::<usize>(commit_indices, no_commits);
    let mut commit_indices_vec: Vec<usize> = vec![];
    for e in tmp {
        total += *e;
        commit_indices_vec.push(*e);
    }

    // parse indices, values and proofs as a 1-dim arrays
    let set_tmp = slice::from_raw_parts::<libc::size_t>(set, total);
    let value_tmp = slice::from_raw_parts::<pointproofs_value>(values, total);
    let agg_proof_tmp = slice::from_raw_parts::<pointproofs_proof>(agg_proof, no_commits);

    // convert them into 2-dim arrays
    let mut set_list: Vec<Vec<usize>> = vec![];
    let mut value_list: Vec<Vec<Vec<u8>>> = vec![];
    let mut agg_proof_list: Vec<Proof> = vec![];
    let mut counter = 0;
    for i in 0..no_commits {
        let mut set_list_within_com: Vec<usize> = vec![];
        let mut value_list_within_com: Vec<Vec<u8>> = vec![];
        for _j in 0..commit_indices_vec[i] {
            set_list_within_com.push(set_tmp[counter]);
            value_list_within_com.push(pointproofs_value_slice(&value_tmp[counter]).to_vec());
            counter += 1;
        }
        set_list.push(set_list_within_com);
        value_list.push(value_list_within_com);
        agg_proof_list.push((*(agg_proof_tmp[i].data as *const Proof)).clone());
    }

    let agg_proof = match Proof::cross_commit_aggregate_partial(
        &com_list,
        &agg_proof_list,
        &set_list,
        &value_list,
        param_n,
    ) {
        Ok(p) => p,
        Err(e) => panic!("C wrapper, x-commit aggregation failed: {}", e),
    };
    let buf_box = Box::new(agg_proof);
    pointproofs_proof {
        data: Box::into_raw(buf_box) as *mut ffi::c_void,
    }
}

/// verify an aggregated proof across commitments
#[no_mangle]
pub unsafe extern "C" fn pointproofs_x_commit_batch_verify(
    verifier: pointproofs_vp,
    com: *const pointproofs_commitment,
    proof: pointproofs_proof,
    set: *const libc::size_t,
    values: *const pointproofs_value,
    commit_indices: *const libc::size_t,
    no_commits: libc::size_t,
) -> bool {
    // parse commits
    let tmp = slice::from_raw_parts::<pointproofs_commitment>(com, no_commits);
    let mut com_list: Vec<Commitment> = vec![];
    for e in tmp {
        com_list.push((*(e.data as *const Commitment)).clone());
    }

    // parse index counters
    let mut total = 0;
    let tmp = slice::from_raw_parts::<usize>(commit_indices, no_commits);
    let mut commit_indices_vec: Vec<usize> = vec![];
    for e in tmp {
        total += *e;
        commit_indices_vec.push(*e);
    }

    // parse indices, values and proofs as a 1-dim arrays
    let set_tmp = slice::from_raw_parts::<libc::size_t>(set, total);
    let value_tmp = slice::from_raw_parts::<pointproofs_value>(values, total);

    // convert them into 2-dim arrays
    let mut set_list: Vec<Vec<usize>> = vec![];
    let mut value_list: Vec<Vec<Vec<u8>>> = vec![];
    let mut counter = 0;
    for e in commit_indices_vec {
        let mut set_list_within_com: Vec<usize> = vec![];
        let mut value_list_within_com: Vec<Vec<u8>> = vec![];
        for _j in 0..e {
            set_list_within_com.push(set_tmp[counter]);
            value_list_within_com.push(pointproofs_value_slice(&value_tmp[counter]).to_vec());
            counter += 1;
        }
        set_list.push(set_list_within_com);
        value_list.push(value_list_within_com);
    }

    // parse the proof and prover parameter
    let pverifier = &*(verifier.data as *const VerifierParams);
    let pproof = &*(proof.data as *const Proof);

    pproof.cross_commit_batch_verify(pverifier, &com_list, &set_list, &value_list)
}
