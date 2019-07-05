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

#[no_mangle]
pub extern fn vcp_paramgen(seedbuf: *const u8, seedlen: libc::size_t, n: usize) -> vcp_params {
  let seed = unsafe { slice::from_raw_parts(seedbuf, seedlen) };
  let (pp, vp) = super::paramgen::paramgen_from_seed(seed, n);
  let boxpp = Box::new(pp);
  let boxvp = Box::new(vp);
  vcp_params {
    prover: Box::into_raw(boxpp) as *mut ffi::c_void,
    verifier: Box::into_raw(boxvp) as *mut ffi::c_void,
  }
}

#[no_mangle]
pub extern fn vcp_free_prover_params(pp: *mut ffi::c_void) {
  unsafe {
    Box::from_raw(pp);
  }
}

#[no_mangle]
pub extern fn vcp_free_verifier_params(vp: *mut ffi::c_void) {
  unsafe {
    Box::from_raw(vp);
  }
}

#[no_mangle]
pub extern fn vcp_commit(prover: *const ffi::c_void, values: *const vcp_value, nvalues: libc::size_t, pout: *mut u8) {
  let pprover = unsafe { &*(prover as *const super::ProverParams) };
  let pvalues = unsafe { slice::from_raw_parts(values, nvalues) };
  let mut vvalues = Vec::new();
  for i in 0..nvalues {
    let v = unsafe { slice::from_raw_parts(pvalues[i].buf, pvalues[i].buflen) };
    vvalues.push(v);
  }

  let com = super::commit::commit(pprover, &vvalues);
  let mut out = unsafe { slice::from_raw_parts_mut(pout, 48) };
  super::prove::write_proof_into_slice(&com, &mut out);
}

#[no_mangle]
pub extern fn vcp_prove(prover: *const ffi::c_void, values: *const vcp_value, nvalues: libc::size_t, idx: libc::size_t, pout: *mut u8) {
  let pprover = unsafe { &*(prover as *const super::ProverParams) };
  let pvalues = unsafe { slice::from_raw_parts(values, nvalues) };
  let mut vvalues = Vec::new();
  for i in 0..nvalues {
    let v = unsafe { slice::from_raw_parts(pvalues[i].buf, pvalues[i].buflen) };
    vvalues.push(v);
  }

  let proof = super::prove::prove(pprover, &vvalues, idx);
  let mut out = unsafe { slice::from_raw_parts_mut(pout, 48) };
  super::prove::write_proof_into_slice(&proof, &mut out);
}

#[no_mangle]
pub extern fn vcp_proof_update(prover: *const ffi::c_void, proof: *const u8, idx: libc::size_t, changed_idx: libc::size_t, val_old: vcp_value, val_new: vcp_value, pout: *mut u8) {
  let pprover = unsafe { &*(prover as *const super::ProverParams) };
  let proofbuf = unsafe { slice::from_raw_parts(proof, 48) };
  let value_before = unsafe { slice::from_raw_parts(val_old.buf, val_old.buflen) };
  let value_after = unsafe { slice::from_raw_parts(val_new.buf, val_new.buflen) };

  let proof = super::prove::convert_bytes_to_proof(&proofbuf);

  let newproof = super::prove::proof_update(pprover, &proof, idx, changed_idx, value_before, value_after);
  let mut out = unsafe { slice::from_raw_parts_mut(pout, 48) };
  super::prove::write_proof_into_slice(&newproof, &mut out);
}

#[no_mangle]
pub extern fn vcp_commit_update(prover: *const ffi::c_void, comptr: *const u8, changed_idx: libc::size_t, val_old: vcp_value, val_new: vcp_value, pout: *mut u8) {
  let pprover = unsafe { &*(prover as *const super::ProverParams) };
  let combuf = unsafe { slice::from_raw_parts(comptr, 48) };
  let value_before = unsafe { slice::from_raw_parts(val_old.buf, val_old.buflen) };
  let value_after = unsafe { slice::from_raw_parts(val_new.buf, val_new.buflen) };

  let com = super::prove::convert_bytes_to_proof(&combuf);

  let newcom = super::commit::commit_update(pprover, &com, changed_idx, value_before, value_after);
  let mut out = unsafe { slice::from_raw_parts_mut(pout, 48) };
  super::prove::write_proof_into_slice(&newcom, &mut out);
}

#[no_mangle]
pub extern fn vcp_verify(verifier: *const ffi::c_void, comptr: *const u8, proofptr: *const u8, val: vcp_value, idx: libc::size_t) -> bool {
  let pverifier = unsafe { &*(verifier as *const super::VerifierParams) };
  let combuf = unsafe { slice::from_raw_parts(comptr, 48) };
  let proofbuf = unsafe { slice::from_raw_parts(proofptr, 48) };
  let val = unsafe { slice::from_raw_parts(val.buf, val.buflen) };

  let com = super::prove::convert_bytes_to_proof(&combuf);
  let proof = super::prove::convert_bytes_to_proof(&proofbuf);

  super::verify::verify(pverifier, &com, &proof, val, idx)
}

#[no_mangle]
pub extern fn vcp_bench_bytes_to_g1_to_bytes(comptr: *const u8, pout: *mut u8) {
  let combuf = unsafe { slice::from_raw_parts(comptr, 48) };
  let com = super::prove::convert_bytes_to_proof(&combuf);
  let mut out = unsafe { slice::from_raw_parts_mut(pout, 48) };
  super::prove::write_proof_into_slice(&com, &mut out);
}
