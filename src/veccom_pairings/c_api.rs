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
pub extern fn vcp_commit(prover: *const ffi::c_void, values: *const vcp_value, nvalues: libc::size_t, pout: *mut u8, outlen: libc::size_t) {
  let pprover = unsafe { &*(prover as *const super::ProverParams) };
  let pvalues = unsafe { slice::from_raw_parts(values, nvalues) };
  let mut vvalues = Vec::new();
  for i in 0..nvalues {
    let v = unsafe { slice::from_raw_parts(pvalues[i].buf, pvalues[i].buflen) };
    vvalues.push(v);
  }

  let com = super::commit::commit(pprover, &vvalues);
  let mut out = unsafe { slice::from_raw_parts_mut(pout, outlen) };
  assert_eq!(out.len(), 48);
  super::prove::write_proof_into_slice(&com, &mut out);
}
