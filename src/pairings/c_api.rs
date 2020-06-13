//! this file is part of the pointproofs.
//! it exposes Rust APIs to C.

extern crate libc;
use pairing::serdes::SerDes;
use pairings::*;
use std::ffi;
use std::slice;

/// non-serialized
#[repr(C)]
#[derive(Default)]
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
    data: *mut u8,
    len: usize,
}

/// serialized verifer parameter struct
#[repr(C)]
pub struct pointproofs_vp_bytes {
    data: *mut u8,
    len: usize,
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
    pub(crate) data: *mut u8,
    pub(crate) len: usize,
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
    pub(crate) data: *mut u8,
    pub(crate) len: usize,
}

/// deserialized proof struct
#[repr(C)]
#[derive(Clone)]
pub struct pointproofs_proof {
    data: *mut ffi::c_void,
}

/// Serializing a prove parameter into bytes
#[no_mangle]
pub unsafe extern "C" fn pointproofs_pp_serial(
    pprover: pointproofs_pp,
    bytes: *mut pointproofs_pp_bytes,
) -> i32 {
    let pprover = &*(pprover.data as *const ProverParams);
    let mut buf: Vec<u8> = vec![];

    match pprover.serialize(&mut buf, true) {
        Ok(p) => p,
        Err(_e) => {
            println!("C wrapper, prover parameter serialization failed");
            return -1;
        }
    };

    buf.shrink_to_fit();
    let mut boxed_buf = buf.into_boxed_slice();
    let data = boxed_buf.as_mut_ptr();
    let len = boxed_buf.len();
    std::mem::forget(boxed_buf);
    *bytes = pointproofs_pp_bytes { data, len };
    0
}

#[no_mangle]
pub unsafe extern "C" fn pointproofs_free_pp_string(buf: pointproofs_pp_bytes) {
    let s = std::slice::from_raw_parts_mut(buf.data as *mut u8, buf.len);
    Box::from_raw(s as *mut [u8]);
}

#[no_mangle]
pub unsafe extern "C" fn pointproofs_pp_deserial(
    pprover: pointproofs_pp_bytes,
    prover: *mut pointproofs_pp,
) -> i32 {
    let s: &mut [u8] = std::slice::from_raw_parts_mut(pprover.data as *mut u8, pprover.len);
    let pp = match ProverParams::deserialize(&mut &s[..], true) {
        Ok(p) => p,
        Err(_e) => {
            println!("C wrapper, prover parameter deserialization failed");
            return -1;
        }
    };
    let buf_box = Box::new(pp);
    let pp_ptr = Box::into_raw(buf_box) as *mut ffi::c_void;
    *prover = pointproofs_pp { data: pp_ptr };
    0
}

/// Serializing a prove parameter into bytes
#[no_mangle]
pub unsafe extern "C" fn pointproofs_vp_serial(
    pverifier: pointproofs_vp,
    bytes: *mut pointproofs_vp_bytes,
) -> i32 {
    let pverifier = &*(pverifier.data as *const VerifierParams);
    let mut buf: Vec<u8> = vec![];

    match pverifier.serialize(&mut buf, true) {
        Ok(p) => p,
        Err(_e) => {
            println!("C wrapper, verifier parameter serialization failed");
            return -1;
        }
    };

    buf.shrink_to_fit();
    let mut boxed_buf = buf.into_boxed_slice();
    let data = boxed_buf.as_mut_ptr();
    let len = boxed_buf.len();
    std::mem::forget(boxed_buf);
    *bytes = pointproofs_vp_bytes { data, len };
    0
}

#[no_mangle]
pub unsafe extern "C" fn pointproofs_free_vp_string(buf: pointproofs_vp_bytes) {
    let s = std::slice::from_raw_parts_mut(buf.data as *mut u8, buf.len);
    Box::from_raw(s as *mut [u8]);
}

#[no_mangle]
pub unsafe extern "C" fn pointproofs_vp_deserial(
    pverifier: pointproofs_vp_bytes,
    verifier: *mut pointproofs_vp,
) -> i32 {
    let s: &mut [u8] = std::slice::from_raw_parts_mut(pverifier.data as *mut u8, pverifier.len);
    let pp = match VerifierParams::deserialize(&mut &s[..], true) {
        Ok(p) => p,
        Err(_e) => {
            println!("C wrapper, verifier parameter deserialization failed");
            return -1;
        }
    };
    let buf_box = Box::new(pp);
    let vp_ptr = Box::into_raw(buf_box) as *mut ffi::c_void;
    *verifier = pointproofs_vp { data: vp_ptr };
    0
}

/// Serializing commitments into bytes
#[no_mangle]
pub unsafe extern "C" fn pointproofs_commit_serial(
    commit: pointproofs_commitment,
    bytes: *mut pointproofs_commitment_bytes,
) -> i32 {
    let com = &*(commit.data as *const Commitment);
    let mut buf: Vec<u8> = vec![];
    match com.serialize(&mut buf, true) {
        Ok(p) => p,
        Err(_e) => {
            println!("C wrapper, commitment serialization failed");
            return -1;
        }
    };
    buf.shrink_to_fit();
    let mut boxed_buf = buf.into_boxed_slice();
    let data = boxed_buf.as_mut_ptr();
    let len = boxed_buf.len();
    std::mem::forget(boxed_buf);
    *bytes = pointproofs_commitment_bytes { data, len };
    0
}

#[no_mangle]
pub unsafe extern "C" fn pointproofs_free_commit_string(buf: pointproofs_commitment_bytes) {
    let s = std::slice::from_raw_parts_mut(buf.data as *mut u8, buf.len);
    Box::from_raw(s as *mut [u8]);
}

/// Deserializeing bytes into commitments
#[no_mangle]
pub unsafe extern "C" fn pointproofs_commit_deserial(
    commit_bytes: pointproofs_commitment_bytes,
    commit: *mut pointproofs_commitment,
) -> i32 {
    let s: &mut [u8] = std::slice::from_raw_parts_mut(commit_bytes.data as *mut u8, commit_bytes.len);
    let com = match Commitment::deserialize(&mut &s[..], true) {
        Ok(p) => p,
        Err(_e) => {
            println!("C wrapper, commitment deserialization failed");
            return -1;
        }
    };
    let buf_box = Box::new(com);

    *commit = pointproofs_commitment {
        data: Box::into_raw(buf_box) as *mut ffi::c_void,
    };
    0
}

/// Serializing proofs into bytes
#[no_mangle]
pub unsafe extern "C" fn pointproofs_proof_serial(
    proof: pointproofs_proof,
    bytes: *mut pointproofs_proof_bytes,
) -> i32 {
    let proof = &*(proof.data as *const Proof);
    let mut buf: Vec<u8> = vec![];
    match proof.serialize(&mut buf, true) {
        Ok(p) => p,
        Err(_e) => {
            println!("C wrapper, proof serialization failed");
            return -1;
        }
    };
    buf.shrink_to_fit();
    let mut boxed_buf = buf.into_boxed_slice();
    let data = boxed_buf.as_mut_ptr();
    let len = boxed_buf.len();
    std::mem::forget(boxed_buf);
    *bytes = pointproofs_proof_bytes { data, len };
    0
}

#[no_mangle]
pub unsafe extern "C" fn pointproofs_free_proof_string(buf: pointproofs_proof_bytes) {
    let s = std::slice::from_raw_parts_mut(buf.data as *mut u8, buf.len);
    Box::from_raw(s as *mut [u8]);
}

/// Deserializeing bytes into proofs
#[no_mangle]
pub unsafe extern "C" fn pointproofs_proof_deserial(
    proof_bytes: pointproofs_proof_bytes,
    proof: *mut pointproofs_proof,
) -> i32 {
    let s: &mut [u8] = std::slice::from_raw_parts_mut(proof_bytes.data as *mut u8, proof_bytes.len);
    let pr = match Proof::deserialize(&mut &s[..], true) {
        Ok(p) => p,
        Err(_e) => {
            println!("C wrapper, proof deserialization failed");
            return -1;
        }
    };
    let buf_box = Box::new(pr);

    *proof = pointproofs_proof {
        data: Box::into_raw(buf_box) as *mut ffi::c_void,
    };
    0
}

/// Generating a pair of parameters
#[no_mangle]
pub unsafe extern "C" fn pointproofs_paramgen(
    seedbuf: *const u8,
    seedlen: libc::size_t,
    ciphersuite: u8,
    n: libc::size_t,
    param: *mut pointproofs_params,
) -> i32 {
    let seed = slice::from_raw_parts(seedbuf, seedlen);
    let (pp, vp) = param::paramgen_from_seed(seed, ciphersuite, n).unwrap();

    let buf_box = Box::new(pp);
    let pp_ptr = Box::into_raw(buf_box) as *mut ffi::c_void;
    let buf_box = Box::new(vp);
    let vp_ptr = Box::into_raw(buf_box) as *mut ffi::c_void;

    *param = pointproofs_params {
        prover: pointproofs_pp { data: pp_ptr },
        verifier: pointproofs_vp { data: vp_ptr },
    };
    0
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
    commit: *mut pointproofs_commitment,
) -> i32 {
    let pprover = &*(prover.data as *const ProverParams);
    let tmp = slice::from_raw_parts::<pointproofs_value>(values, n);
    let mut vvalues: Vec<Vec<u8>> = vec![];
    for e in tmp {
        vvalues.push(pointproofs_value_slice(&e).to_vec());
    }

    let com = Commitment::new(pprover, &vvalues).unwrap();
    let buf_box = Box::new(com);

    *commit = pointproofs_commitment {
        data: Box::into_raw(buf_box) as *mut ffi::c_void,
    };
    0
}

/// Generate a proof
#[no_mangle]
pub unsafe extern "C" fn pointproofs_prove(
    prover: pointproofs_pp,
    values: *const pointproofs_value,
    n: usize,
    idx: libc::size_t,
    proof: *mut pointproofs_proof,
) -> i32 {
    let pprover = &*(prover.data as *const ProverParams);
    let tmp = slice::from_raw_parts::<pointproofs_value>(values, n);
    let mut vvalues: Vec<Vec<u8>> = vec![];
    for e in tmp {
        vvalues.push(pointproofs_value_slice(&e).to_vec());
    }

    let pr = Proof::new(pprover, &vvalues, idx).unwrap();
    let buf_box = Box::new(pr);

    *proof = pointproofs_proof {
        data: Box::into_raw(buf_box) as *mut ffi::c_void,
    };
    0
}

/// Generate a proof
#[no_mangle]
pub unsafe extern "C" fn pointproofs_prove_batch_aggregated(
    prover: pointproofs_pp,
    commit: pointproofs_commitment,
    values: *const pointproofs_value,
    n: usize,
    idx: &[libc::size_t],
    proof: *mut pointproofs_proof,
) -> i32 {
    let pprover = &*(prover.data as *const ProverParams);
    let tmp = slice::from_raw_parts::<pointproofs_value>(values, n);
    let mut vvalues: Vec<Vec<u8>> = vec![];
    for e in tmp {
        vvalues.push(pointproofs_value_slice(&e).to_vec());
    }
    let pcom = &*(commit.data as *const Commitment);
    let pr = Proof::batch_new_aggregated(pprover, pcom, &vvalues, idx).unwrap();
    let buf_box = Box::new(pr);

    *proof = pointproofs_proof {
        data: Box::into_raw(buf_box) as *mut ffi::c_void,
    };
    0
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
    new_proof: &mut pointproofs_proof,
) -> i32 {
    let pprover = &*(prover.data as *const ProverParams);
    let pproof = &*(proof.data as *const Proof);
    let value_before = pointproofs_value_slice(&val_old);
    let value_after = pointproofs_value_slice(&val_new);

    let mut new_pr = pproof.clone();

    new_pr
        .update(pprover, idx, changed_idx, value_before, value_after)
        .unwrap();
    let buf_box = Box::new(new_pr);
    *new_proof = pointproofs_proof {
        data: Box::into_raw(buf_box) as *mut ffi::c_void,
    };
    0
}

/// update an existing commitment
#[no_mangle]
pub unsafe extern "C" fn pointproofs_commit_update(
    prover: pointproofs_pp,
    com: pointproofs_commitment,
    changed_idx: libc::size_t,
    val_old: pointproofs_value,
    val_new: pointproofs_value,
    new_com: *mut pointproofs_commitment,
) -> i32 {
    let pprover = &*(prover.data as *const ProverParams);
    let pcom = &*(com.data as *const Commitment);
    let value_before = pointproofs_value_slice(&val_old);
    let value_after = pointproofs_value_slice(&val_new);
    let mut new_commit = pcom.clone();
    new_commit
        .update(pprover, changed_idx, value_before, value_after)
        .unwrap();
    let buf_box = Box::new(new_commit);
    *new_com = pointproofs_commitment {
        data: Box::into_raw(buf_box) as *mut ffi::c_void,
    };
    0
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
    agg_proof: *mut pointproofs_proof,
) -> i32 {
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

    let agg_pr =
        match Proof::same_commit_aggregate(&pcom, &proof_list, &set_list, &vvalues, param_n) {
            Ok(p) => p,
            Err(e) => {
                println!("C wrapper, same commit aggregation failed: {}", e);
                return -1;
            }
        };
    let buf_box = Box::new(agg_pr);
    *agg_proof = pointproofs_proof {
        data: Box::into_raw(buf_box) as *mut ffi::c_void,
    };
    0
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
    x_proof: *mut pointproofs_proof,
) -> i32 {
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
        Err(e) => {
            println!("C wrapper, x-commit aggregation failed: {}", e);
            return -1;
        }
    };
    let buf_box = Box::new(agg_proof);
    *x_proof = pointproofs_proof {
        data: Box::into_raw(buf_box) as *mut ffi::c_void,
    };
    0
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
    x_proof: *mut pointproofs_proof,
) -> i32 {
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
        Err(e) => {
            println!("C wrapper, x-commit aggregation failed: {}", e);
            return -1;
        }
    };
    let buf_box = Box::new(agg_proof);
    *x_proof = pointproofs_proof {
        data: Box::into_raw(buf_box) as *mut ffi::c_void,
    };
    0
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

impl Default for pointproofs_vp {
    fn default() -> Self {
        pointproofs_vp {
            data: std::ptr::null_mut(),
        }
    }
}

impl Default for pointproofs_pp {
    fn default() -> Self {
        pointproofs_pp {
            data: std::ptr::null_mut(),
        }
    }
}

impl Default for pointproofs_pp_bytes {
    fn default() -> Self {
        pointproofs_pp_bytes { data: std::ptr::null_mut(), len: 0 }
    }
}

impl Default for pointproofs_vp_bytes {
    fn default() -> Self {
        pointproofs_vp_bytes { data: std::ptr::null_mut(), len: 0 }
    }
}

impl Default for pointproofs_commitment {
    fn default() -> Self {
        pointproofs_commitment {
            data: std::ptr::null_mut(),
        }
    }
}

impl Default for pointproofs_commitment_bytes {
    fn default() -> Self {
        pointproofs_commitment_bytes {
            data: std::ptr::null_mut(), len: 0
        }
    }
}

impl Default for pointproofs_proof {
    fn default() -> Self {
        pointproofs_proof {
            data: std::ptr::null_mut(),
        }
    }
}

impl Default for pointproofs_proof_bytes {
    fn default() -> Self {
        pointproofs_proof_bytes {
            data: std::ptr::null_mut(), len: 0
        }
    }
}
