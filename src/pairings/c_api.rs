extern crate libc;
use pairing::serdes::SerDes;
use pairings::*;
use std::ffi;
use std::slice;
// non-serialized
#[repr(C)]
pub struct vcp_params {
    prover: vcp_pp,
    verifier: vcp_vp,
}

#[repr(C)]
pub struct vcp_value {
    data: *const u8,
    len: libc::size_t,
}

#[repr(C)]
pub struct vcp_commitment {
    data: [u8; COMMIT_LEN],
}

#[repr(C)]
pub struct vcp_proof {
    data: [u8; PROOF_LEN]
}

/// serelized prover parameter struct
#[repr(C)]
pub struct vcp_pp {
    data: [u8;RAW_PP_LEN],
}

/// serelized verifer parameter struct
#[repr(C)]
pub struct vcp_vp {
    data: [u8;VP_LEN],
}

/// deserelized prover parameter struct
#[repr(C)]
pub struct vcp_pp_deserialized {
    data: *const u8,
    len: libc::size_t,
}

/// deserelized verifier parameter struct
#[repr(C)]
pub struct vcp_vp_deserialized {
    data: *const u8,
    len: libc::size_t,
}

//
// // #[repr(C)]
// // pub struct vcp_commit {
// //     commit: *mut ffi::c_void,
// // }
// //
// // #[repr(C)]
// // pub struct vcp_proof {
// //     proof: *mut ffi::c_void,
// // }
//
// /// # Safety
// #[no_mangle]
// pub unsafe extern "C" fn vcp_pp_serial(prover: VcpDeserializedPp) -> vcp_serialized_pp {
//     let pprover = &*(prover as *const super::ProverParams);
//     let mut buf: Vec<u8> = vec![];
//     assert!(
//         pprover.serialize(&mut buf, true).is_ok(),
//         "prover parameter serialization failed"
//     );
//     buf.shrink_to_fit();
//     vcp_serialized_pp {
//         data: buf.as_mut_ptr(),
//         len: buf.len(),
//     }
// }
//
// /// # Safety
// #[no_mangle]
// pub unsafe extern "C" fn vcp_pp_deserial(prover: vcp_serialized_pp) -> VcpDeserializedPp {
//     let mut buf = slice::from_raw_parts(prover.data, prover.len);
//     let prover = match ProverParams::deserialize(&mut buf, true) {
//         Ok(p) => p,
//         Err(e) => panic!("C wrapper: pp deserialization: {}", e),
//     };
//     Box::into_raw(Box::new(prover)) as VcpDeserializedPp
// }
//
// /// # Safety
// #[no_mangle]
// pub unsafe extern "C" fn vcp_vp_serial(pverifier: VcpDeserializedPp) -> vcp_serialized_vp {
//     let pverifier = &*(pverifier as *const super::VerifierParams);
//     let mut buf: Vec<u8> = vec![];
//     assert!(
//         pverifier.serialize(&mut buf, true).is_ok(),
//         "prover parameter serialization failed"
//     );
//     buf.shrink_to_fit();
//     vcp_serialized_vp {
//         data: buf.as_mut_ptr(),
//         len: buf.len(),
//     }
// }
//
// /// # Safety
// #[no_mangle]
// pub unsafe extern "C" fn vcp_vp_deserial(verifier: vcp_serialized_pp) -> VcpDeserializedPp {
//     let mut buf = slice::from_raw_parts(verifier.data, verifier.len);
//     let verifier = match VerifierParams::deserialize(&mut buf, true) {
//         Ok(p) => p,
//         Err(e) => panic!("C wrapper: pp deserialization: {}", e),
//     };
//     Box::into_raw(Box::new(verifier)) as VcpDeserializedPp
// }

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn vcp_paramgen(
    seedbuf: *const u8,
    seedlen: libc::size_t,
    ciphersuite: u8,
    n: libc::size_t,
) -> vcp_params {
    let seed = slice::from_raw_parts(seedbuf, seedlen);
    let (pp, vp) = super::param::paramgen_from_seed(seed, ciphersuite, n).unwrap();

    let mut pp_buf: Vec<u8> = vec![];
    assert!(vp.serialize(&mut pp_buf, true).is_ok());
    let mut pp_array = [0u8; RAW_PP_LEN];
    pp_array.copy_from_slice(&pp_buf);

    let mut vp_buf: Vec<u8> = vec![];
    assert!(vp.serialize(&mut vp_buf, true).is_ok());
    let mut vp_array = [0u8; VP_LEN];
    vp_array.copy_from_slice(&vp_buf);

    vcp_params {
        prover: vcp_pp {
            data: pp_array
        },
        verifier: vcp_vp {
            data: vp_array
        },
    }
}
//
// /// # Safety
// #[no_mangle]
// pub unsafe extern "C" fn vcp_free_prover_params(pp: *mut ffi::c_void) {
//     Box::from_raw(pp);
// }
//
// /// # Safety
// #[no_mangle]
// pub unsafe extern "C" fn vcp_free_verifier_params(vp: *mut ffi::c_void) {
//     Box::from_raw(vp);
// }
//
// /// # Safety
// #[no_mangle]
// fn return_commit(commit: &super::Commitment) -> *mut ffi::c_void {
//     let buf_box = Box::new(commit);
//     Box::into_raw(buf_box) as *mut ffi::c_void
// }
//
// /// # Safety
// #[no_mangle]
// pub unsafe extern "C" fn vcp_free_commit(commit: *mut ffi::c_void) {
//     Box::from_raw(commit);
// }
//
// /// # Safety
// #[no_mangle]
// fn return_proof(proof: &super::Proof) -> *mut ffi::c_void {
//     let buf_box = Box::new(proof);
//     Box::into_raw(buf_box) as *mut ffi::c_void
// }
//
// /// # Safety
// #[no_mangle]
// pub unsafe extern "C" fn vcp_free_proof(proof: *mut ffi::c_void) {
//     Box::from_raw(proof);
// }

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
    unsafe { slice::from_raw_parts(vv.data, vv.len) }
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn vcp_commit(
    prover: vcp_pp_deserialized,
    values: *const vcp_value,
    nvalues: libc::size_t,
) -> vcp_commitment {
    let pprover = &*(prover.data as *const super::ProverParams);
    let pvalues = slice::from_raw_parts(values, nvalues);
    let vvalues: Vec<_> = pvalues.iter().map(vcp_value_slice).collect();

    let com = super::Commitment::new(pprover, &vvalues).unwrap();

    let mut buf: Vec<u8> = vec![];
    assert!(com.serialize(&mut buf, true).is_ok());
    let mut commit_array = [0u8; COMMIT_LEN];
    commit_array.copy_from_slice(&buf);

    vcp_commitment {
        data: commit_array
    }
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn vcp_prove(
    prover: vcp_pp_deserialized,
    values: *const vcp_value,
    nvalues: libc::size_t,
    idx: libc::size_t,
) -> vcp_proof {
    let pprover = &*(prover.data as *const super::ProverParams);
    let pvalues = slice::from_raw_parts(values, nvalues);
    let vvalues: Vec<_> = pvalues.iter().map(vcp_value_slice).collect();

    let proof = super::Proof::new(pprover, &vvalues, idx).unwrap();

    let mut buf: Vec<u8> = vec![];
    assert!(proof.serialize(&mut buf, true).is_ok());
    let mut proof_array = [0u8; PROOF_LEN];
    proof_array.copy_from_slice(&buf);

    vcp_proof {
        data: proof_array
    }
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
