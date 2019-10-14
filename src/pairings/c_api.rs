extern crate libc;

use std::ffi;
use std::slice;

#[repr(C)]
pub struct vcp_params {
    prover: *mut ffi::c_void,
    verifier: *mut ffi::c_void,
}

#[repr(C)]
pub struct vcp_value {
    buf: *const u8,
    buflen: libc::size_t,
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn vcp_paramgen(
    seedbuf: *const u8,
    seedlen: libc::size_t,
    ciphersuite: u8,
) -> vcp_params {
    let seed = slice::from_raw_parts(seedbuf, seedlen);
    let (pp, vp) = super::paramgen::paramgen_from_seed(seed, ciphersuite).unwrap();
    let boxpp = Box::new(pp);
    let boxvp = Box::new(vp);
    vcp_params {
        prover: Box::into_raw(boxpp) as *mut ffi::c_void,
        verifier: Box::into_raw(boxvp) as *mut ffi::c_void,
    }
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn vcp_free_prover_params(pp: *mut ffi::c_void) {
    Box::from_raw(pp);
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn vcp_free_verifier_params(vp: *mut ffi::c_void) {
    Box::from_raw(vp);
}

/// # Safety
#[no_mangle]
fn return_commit(commit: &super::Commitment) -> *mut ffi::c_void {
    let buf_box = Box::new(commit);
    Box::into_raw(buf_box) as *mut ffi::c_void
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn vcp_free_commit(commit: *mut ffi::c_void) {
    Box::from_raw(commit);
}

/// # Safety
#[no_mangle]
fn return_proof(proof: &super::Proof) -> *mut ffi::c_void {
    let buf_box = Box::new(proof);
    Box::into_raw(buf_box) as *mut ffi::c_void
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn vcp_free_proof(proof: *mut ffi::c_void) {
    Box::from_raw(proof);
}

// /// # Safety
// #[no_mangle]
// pub unsafe extern "C" fn vcp_free_g1(g1: *mut ffi::c_void) {
//     Box::from_raw(g1);
// }

// /// # Safety
// #[no_mangle]
// pub unsafe extern "C" fn vcp_g1_to_bytes(g1: *const ffi::c_void, pout: *mut u8) {
//     let pg1 = &*(g1 as *const super::G1);
//     let mut out = slice::from_raw_parts_mut(pout, 48);
//     super::prove::write_proof_into_slice(pg1, &mut out);
// }
//
// /// # Safety
// #[no_mangle]
// pub unsafe extern "C" fn vcp_g1_from_bytes(buf: *const u8) -> *mut ffi::c_void {
//     let g1buf = slice::from_raw_parts(buf, 48);
//     match super::prove::convert_bytes_to_proof_err(&g1buf) {
//         Ok(g1) => return_g1(&g1),
//         Err(_) => std::ptr::null_mut(),
//     }
// }
//
// fn return_g1(g1: &super::G1) -> *mut ffi::c_void {
//     let g1box = Box::new(*g1);
//     Box::into_raw(g1box) as *mut ffi::c_void
// }
//
fn vcp_value_slice<'a>(vv: &vcp_value) -> &'a [u8] {
    unsafe { slice::from_raw_parts(vv.buf, vv.buflen) }
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn vcp_commit(
    prover: *const ffi::c_void,
    values: *const vcp_value,
    nvalues: libc::size_t,
) -> *mut ffi::c_void {
    let pprover = &*(prover as *const super::ProverParams);
    let pvalues = slice::from_raw_parts(values, nvalues);
    let vvalues: Vec<_> = pvalues.iter().map(vcp_value_slice).collect();

    let com = super::Commitment::new(pprover, &vvalues).unwrap();
    return_commit(&com)
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn vcp_prove(
    prover: *const ffi::c_void,
    values: *const vcp_value,
    nvalues: libc::size_t,
    idx: libc::size_t,
) -> *mut ffi::c_void {
    let pprover = &*(prover as *const super::ProverParams);
    let pvalues = slice::from_raw_parts(values, nvalues);
    let vvalues: Vec<_> = pvalues.iter().map(vcp_value_slice).collect();

    let proof = super::Proof::new(pprover, &vvalues, idx).unwrap();
    return_proof(&proof)
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn vcp_proof_update(
    prover: *const ffi::c_void,
    proof: *const ffi::c_void,
    idx: libc::size_t,
    changed_idx: libc::size_t,
    val_old: vcp_value,
    val_new: vcp_value,
) -> *mut ffi::c_void {
    let pprover = &*(prover as *const super::ProverParams);
    let pproof = &*(proof as *const super::Proof);
    let value_before = vcp_value_slice(&val_old);
    let value_after = vcp_value_slice(&val_new);

    let mut new_proof = pproof.clone();

    new_proof
        .update(pprover, idx, changed_idx, value_before, value_after)
        .unwrap();
    return_proof(&new_proof)
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn vcp_commit_update(
    prover: *const ffi::c_void,
    com: *const ffi::c_void,
    changed_idx: libc::size_t,
    val_old: vcp_value,
    val_new: vcp_value,
) -> *mut ffi::c_void {
    let pprover = &*(prover as *const super::ProverParams);
    let pcom = &*(com as *const super::Commitment);
    let value_before = vcp_value_slice(&val_old);
    let value_after = vcp_value_slice(&val_new);
    let mut new_com = pcom.clone();
    new_com
        .update(pprover, changed_idx, value_before, value_after)
        .unwrap();
    return_commit(&new_com)
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn vcp_verify(
    verifier: *const ffi::c_void,
    com: *const ffi::c_void,
    proof: *const ffi::c_void,
    val: vcp_value,
    idx: libc::size_t,
) -> bool {
    let pverifier = &*(verifier as *const super::VerifierParams);
    let pcom = &*(com as *const super::Commitment);
    let pproof = &*(proof as *const super::Proof);
    let val = vcp_value_slice(&val);

    pproof.verify(pverifier, pcom, val, idx)
}
