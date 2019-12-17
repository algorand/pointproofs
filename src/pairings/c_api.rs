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
//
// #[repr(C)]
// pub struct vcp_proof {
//     data: [u8; PROOF_LEN],
// }

/// serelized prover parameter struct
#[repr(C)]
pub struct vcp_pp_bytes {
    data: [u8; RAW_PP_LEN],
}

/// serelized verifer parameter struct
#[repr(C)]
pub struct vcp_vp_bytes {
    data: [u8; VP_LEN],
}

/// deserelized prover parameter struct
#[repr(C)]
pub struct vcp_pp {
    data: *mut ffi::c_void,
}

/// deserelized verifier parameter struct
#[repr(C)]
pub struct vcp_vp {
    data: *mut ffi::c_void,
}

#[repr(C)]
pub struct vcp_commitment_bytes {
    data: [u8; COMMIT_LEN],
}

#[repr(C)]
pub struct vcp_commitment {
    data: *mut ffi::c_void,
}

#[repr(C)]
pub struct vcp_proof_bytes {
    data: [u8; PROOF_LEN],
}

#[repr(C)]
pub struct vcp_proof {
    data: *mut ffi::c_void,
}

// #[repr(C)]
// pub struct vcp_commit {
//     data: *mut ffi::c_void,
// }
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
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn vcp_pp_serial(pprover: vcp_pp) -> vcp_pp_bytes {
    let pprover = &*(pprover.data as *const super::ProverParams);
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
/// # Safety
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

#[no_mangle]
pub unsafe extern "C" fn vcp_vp_serial(pverifier: vcp_vp) -> vcp_vp_bytes {
    let pverifier = &*(pverifier.data as *const super::VerifierParams);
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
/// # Safety
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
/// # Safety
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
/// # Safety
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

    let buf_box = Box::new(pp);
    let pp_ptr = Box::into_raw(buf_box) as *mut ffi::c_void;
    let buf_box = Box::new(vp);
    let vp_ptr = Box::into_raw(buf_box) as *mut ffi::c_void;

    vcp_params {
        prover: vcp_pp { data: pp_ptr },
        verifier: vcp_vp { data: vp_ptr },
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
    prover: vcp_pp,
    values: *const vcp_value,
    n: usize,
) -> vcp_commitment {
    let pprover = &*(prover.data as *const super::ProverParams);
    let tmp = slice::from_raw_parts::<vcp_value>(values, n);
    let mut vvalues: Vec<Vec<u8>> = vec![];
    for e in tmp {
        vvalues.push(vcp_value_slice(&e).to_vec());
    }

    let com = super::Commitment::new(pprover, &vvalues).unwrap();
    let buf_box = Box::new(com);

    vcp_commitment {
        data: Box::into_raw(buf_box) as *mut ffi::c_void,
    }
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn vcp_prove(
    prover: vcp_pp,
    values: *const vcp_value,
    n: usize,
    idx: libc::size_t,
) -> vcp_proof {
    let pprover = &*(prover.data as *const super::ProverParams);
    let tmp = slice::from_raw_parts::<vcp_value>(values, n);
    let mut vvalues: Vec<Vec<u8>> = vec![];
    for e in tmp {
        vvalues.push(vcp_value_slice(&e).to_vec());
    }

    let proof = super::Proof::new(pprover, &vvalues, idx).unwrap();
    let buf_box = Box::new(proof);

    vcp_proof {
        data: Box::into_raw(buf_box) as *mut ffi::c_void,
    }
}

/// # Safety
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

/// # Safety
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

/// # Safety
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
