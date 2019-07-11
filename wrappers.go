package veccom

// #cgo LDFLAGS: ${SRCDIR}/target/release/libveccom.a -ldl
// #include "target/veccom.h"
import "C"

import (
	"math"
	"runtime"
	"unsafe"
)

// Prover is veccom::pairings::ProverParams
type Prover struct {
	ptr unsafe.Pointer
}

// Verifier is veccom::pairings::VerifierParams
type Verifier struct {
	ptr unsafe.Pointer
}

type Commitment [48]byte
type Proof struct {
	Index int
	Proof [48]byte
}

func ParamGen(seed []uint8, n int) (p *Prover, v *Verifier) {
	params := C.vcp_paramgen((*C.uchar)(&seed[0]), C.size_t(len(seed)), C.size_t(n))

	p = &Prover{params.prover}
	runtime.SetFinalizer(p, release_prover)

	v = &Verifier{params.verifier}
	runtime.SetFinalizer(v, release_verifier)

	return
}

func release_prover(p *Prover) {
	C.vcp_free_prover_params(p.ptr)
}

func release_verifier(v *Verifier) {
	C.vcp_free_verifier_params(v.ptr)
}

func vcp_value(buf []byte) C.vcp_value {
	return C.vcp_value{
		buf:    (*C.uchar)(&buf[0]),
		buflen: C.size_t(len(buf)),
	}
}

func vcp_values(vals [][]byte) *C.vcp_value {
	p := (*C.vcp_value)(C.malloc(C.size_t(len(vals)) * C.sizeof_vcp_value))
	arr := (*[math.MaxUint32]C.vcp_value)(unsafe.Pointer(p))
	for i, v := range vals {
		arr[i] = vcp_value(v)
	}
	return p
}

func (p *Prover) Commit(vals [][]byte) (out Commitment) {
	valbufs := vcp_values(vals)
	defer C.free(unsafe.Pointer(valbufs))

	C.vcp_commit(p.ptr, valbufs, C.size_t(len(vals)), (*C.uchar)(&out[0]))
	return
}

func (p *Prover) Prove(vals [][]byte, idx int) (out Proof) {
	valbufs := vcp_values(vals)
	defer C.free(unsafe.Pointer(valbufs))

	C.vcp_prove(p.ptr, valbufs, C.size_t(len(vals)), C.size_t(idx), (*C.uchar)(&out.Proof[0]))
	out.Index = idx
	return
}

func (v *Verifier) Verify(com Commitment, proof Proof, val []byte) bool {
	r := C.vcp_verify(v.ptr, (*C.uchar)(&com[0]), (*C.uchar)(&proof.Proof[0]),
		vcp_value(val), C.size_t(proof.Index))
	return bool(r)
}

func (p *Prover) ProofUpdate(proof Proof, changedidx int, oldval []byte, newval []byte) (out Proof) {
	C.vcp_proof_update(p.ptr, (*C.uchar)(&proof.Proof[0]), C.size_t(proof.Index), C.size_t(changedidx),
		vcp_value(oldval), vcp_value(newval), (*C.uchar)(&out.Proof[0]))
	out.Index = proof.Index
	return
}

func (p *Prover) CommitUpdate(com Commitment, changedidx int, oldval []byte, newval []byte) (out Commitment) {
	C.vcp_commit_update(p.ptr, (*C.uchar)(&com[0]), C.size_t(changedidx),
		vcp_value(oldval), vcp_value(newval), (*C.uchar)(&out[0]))
	return
}

func benchBytesToG1ToBytes(com Commitment) (out Commitment) {
	C.vcp_bench_bytes_to_g1_to_bytes((*C.uchar)(&com[0]), (*C.uchar)(&out[0]))
	return
}

func benchBytesToG1(com Commitment) {
	C.vcp_bench_bytes_to_g1((*C.uchar)(&com[0]))
	return
}
