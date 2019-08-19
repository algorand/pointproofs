package veccom

// #cgo LDFLAGS: ${SRCDIR}/target/release/libveccom.a -ldl
// #include "target/release/veccom.h"
import "C"

import (
	"errors"
	"math"
	"runtime"
	"unsafe"
)

// noCopy makes "go vet" catch copying of any types that embed noCopy;
// see https://github.com/golang/go/issues/8005#issuecomment-190753527
// We want to make sure our wrappers around Rust Box aren't copied because
// we use runtime.SetFinalizer() to free the underlying Rust Box allocation.
type noCopy struct{}

func (*noCopy) Lock()   {}
func (*noCopy) Unlock() {}

var ErrBadEncoding = errors.New("cannot decode bytes to G1")

// Prover is veccom::pairings::ProverParams
type Prover struct {
	noCopy
	ptr unsafe.Pointer
}

// Verifier is veccom::pairings::VerifierParams
type Verifier struct {
	noCopy
	ptr unsafe.Pointer
}

// G1 is veccom::pairings::G1
type G1 struct {
	noCopy
	ptr unsafe.Pointer
}

type Commitment struct {
	G1 *G1
}

type Proof struct {
	Index int
	G1    *G1
}

func ParamGen(seed []uint8, n int) (p *Prover, v *Verifier) {
	params := C.vcp_paramgen((*C.uchar)(&seed[0]), C.size_t(len(seed)), C.size_t(n))

	p = &Prover{ptr: params.prover}
	runtime.SetFinalizer(p, release_prover)

	v = &Verifier{ptr: params.verifier}
	runtime.SetFinalizer(v, release_verifier)

	return
}

func release_prover(p *Prover) {
	C.vcp_free_prover_params(p.ptr)
}

func release_verifier(v *Verifier) {
	C.vcp_free_verifier_params(v.ptr)
}

func release_g1(g1 *G1) {
	C.vcp_free_g1(g1.ptr)
}

func vcp_value(buf []byte) C.vcp_value {
	p := (*C.uchar)(C.malloc(C.size_t(len(buf))))
	arr := (*[math.MaxUint32]byte)(unsafe.Pointer(p))
	copy(arr[:], buf)
	return C.vcp_value{
		buf:    p,
		buflen: C.size_t(len(buf)),
	}
}

func release_vcp_value(v C.vcp_value) {
	C.free(unsafe.Pointer(v.buf))
}

func vcp_values(vals [][]byte) *C.vcp_value {
	p := (*C.vcp_value)(C.malloc(C.size_t(len(vals)) * C.sizeof_vcp_value))
	arr := (*[math.MaxUint32]C.vcp_value)(unsafe.Pointer(p))
	for i, v := range vals {
		arr[i] = vcp_value(v)
	}
	return p
}

func release_vcp_values(vp *C.vcp_value, n int) {
	arr := (*[math.MaxUint32]C.vcp_value)(unsafe.Pointer(vp))
	for i := 0; i < n; i++ {
		release_vcp_value(arr[i])
	}
	C.free(unsafe.Pointer(vp))
}

func (p *Prover) Commit(vals [][]byte) Commitment {
	valbufs := vcp_values(vals)
	defer release_vcp_values(valbufs, len(vals))

	res := C.vcp_commit(p.ptr, valbufs, C.size_t(len(vals)))
	g1 := &G1{ptr: res}
	runtime.SetFinalizer(g1, release_g1)
	return Commitment{g1}
}

func (p *Prover) Prove(vals [][]byte, idx int) Proof {
	valbufs := vcp_values(vals)
	defer release_vcp_values(valbufs, len(vals))

	res := C.vcp_prove(p.ptr, valbufs, C.size_t(len(vals)), C.size_t(idx))
	g1 := &G1{ptr: res}
	runtime.SetFinalizer(g1, release_g1)
	return Proof{Index: idx, G1: g1}
}

func (v *Verifier) Verify(com Commitment, proof Proof, val []byte) bool {
	r := C.vcp_verify(v.ptr, com.G1.ptr, proof.G1.ptr,
		vcp_value(val), C.size_t(proof.Index))
	return bool(r)
}

func (p *Prover) ProofUpdate(proof Proof, changedidx int, oldval []byte, newval []byte) Proof {
	res := C.vcp_proof_update(p.ptr, proof.G1.ptr, C.size_t(proof.Index), C.size_t(changedidx),
		vcp_value(oldval), vcp_value(newval))
	g1 := &G1{ptr: res}
	runtime.SetFinalizer(g1, release_g1)
	return Proof{Index: proof.Index, G1: g1}
}

func (p *Prover) CommitUpdate(com Commitment, changedidx int, oldval []byte, newval []byte) Commitment {
	res := C.vcp_commit_update(p.ptr, com.G1.ptr, C.size_t(changedidx),
		vcp_value(oldval), vcp_value(newval))
	g1 := &G1{ptr: res}
	runtime.SetFinalizer(g1, release_g1)
	return Commitment{g1}
}

func BytesToG1(buf [48]byte) (*G1, error) {
	res := C.vcp_g1_from_bytes((*C.uchar)(&buf[0]))
	if res == nil {
		return nil, ErrBadEncoding
	}

	g1 := &G1{ptr: res}
	runtime.SetFinalizer(g1, release_g1)
	return g1, nil
}

func (g1 *G1) ToBytes() (out [48]byte) {
	C.vcp_g1_to_bytes(g1.ptr, (*C.uchar)(&out[0]))
	return
}
