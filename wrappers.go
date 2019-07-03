package veccom

// #cgo LDFLAGS: ${SRCDIR}/target/release/libveccom.a -ldl
// #include "target/veccom.h"
import "C"

import (
	"runtime"
	"unsafe"
)

// Prover is veccom_pairings::ProverParams
type Prover struct {
	ptr unsafe.Pointer
}

// Verifier is veccom_pairings::VerifierParams
type Verifier struct {
	ptr unsafe.Pointer
}

type Commitment [48]byte
type Proof [48]byte

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

func (p *Prover) Commit(vals [][]byte) (out Commitment) {
	var valbufs []C.vcp_value
	for _, val := range vals {
		valbufs = append(valbufs, C.vcp_value{
			buf: (*C.uchar)(&val[0]),
			buflen: C.size_t(len(val)),
		})
	}

	C.vcp_commit(p.ptr, (*C.vcp_value)(&valbufs[0]), C.size_t(len(valbufs)), (*C.uchar)(&out[0]))
	return
}

func (p *Prover) Prove(vals [][]byte, idx int) (out Proof) {
	var valbufs []C.vcp_value
	for _, val := range vals {
		valbufs = append(valbufs, C.vcp_value{
			buf: (*C.uchar)(&val[0]),
			buflen: C.size_t(len(val)),
		})
	}

	C.vcp_prove(p.ptr, (*C.vcp_value)(&valbufs[0]), C.size_t(len(valbufs)), C.size_t(idx), (*C.uchar)(&out[0]))
	return
}

func (v *Verifier) Verify(com Commitment, proof Proof, val []byte, idx int) bool {
	r := C.vcp_verify(v.ptr, (*C.uchar)(&com[0]), (*C.uchar)(&proof[0]),
		C.vcp_value{
			buf: (*C.uchar)(&val[0]),
			buflen: C.size_t(len(val)),
		},
		C.size_t(idx))

	return bool(r)
}

func (p *Prover) ProofUpdate(proof Proof, idx int, changedidx int, oldval []byte, newval []byte) (out Proof) {
	C.vcp_proof_update(p.ptr, (*C.uchar)(&proof[0]), C.size_t(idx), C.size_t(changedidx),
		C.vcp_value{
			buf: (*C.uchar)(&oldval[0]),
			buflen: C.size_t(len(oldval)),
		},
		C.vcp_value{
			buf: (*C.uchar)(&newval[0]),
			buflen: C.size_t(len(newval)),
		},
		(*C.uchar)(&out[0]))
	return
}

func (p *Prover) CommitUpdate(com Commitment, changedidx int, oldval []byte, newval []byte) (out Commitment) {
	C.vcp_commit_update(p.ptr, (*C.uchar)(&com[0]), C.size_t(changedidx),
		C.vcp_value{
			buf: (*C.uchar)(&oldval[0]),
			buflen: C.size_t(len(oldval)),
		},
		C.vcp_value{
			buf: (*C.uchar)(&newval[0]),
			buflen: C.size_t(len(newval)),
		},
		(*C.uchar)(&out[0]))
	return
}
