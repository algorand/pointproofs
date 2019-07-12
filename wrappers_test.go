package veccom

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"testing"
)

func TestCommit(t *testing.T) {
	n := 10
	seed := "This is Leo's Favourite Seed"
	p, v := ParamGen([]byte(seed), n)

	var values [][]byte
	for i := 0; i < n; i++ {
		msg := fmt.Sprintf("this is message number %d", i)
		values = append(values, []byte(msg))
	}

	com := p.Commit(values)
	combuf := com.G1.ToBytes()
	fmt.Printf("Commitment:  %s\n", hex.EncodeToString(combuf[:]))

	var proofs []Proof
	for i := 0; i < n; i++ {
		pf := p.Prove(values, i)
		proofs = append(proofs, pf)
		pfbuf := pf.G1.ToBytes()
		fmt.Printf("Old Proof %d: %s\n", i, hex.EncodeToString(pfbuf[:]))
	}

	for i := 0; i < n; i++ {
		if !v.Verify(com, proofs[i], values[i]) {
			t.Errorf("Could not verify proof %d\n", i)
		}
	}

	update_idx := n / 2
	newmsg := fmt.Sprintf("\"this is new message number %d\"", update_idx)
	newval := []byte(newmsg)

	fmt.Printf("Updating string %d to \"%s\"\n", update_idx, newmsg)

	newcom := p.CommitUpdate(com, update_idx, values[update_idx], newval)
	newcombuf := newcom.G1.ToBytes()
	fmt.Printf("New Commitment:  %s\n", hex.EncodeToString(newcombuf[:]))

	var newproofs []Proof
	for i := 0; i < n; i++ {
		npf := p.ProofUpdate(proofs[i], update_idx, values[update_idx], newval)
		newproofs = append(newproofs, npf)
		npfbuf := npf.G1.ToBytes()
		fmt.Printf("New Proof %d: %s\n", i, hex.EncodeToString(npfbuf[:]))
	}

	values[update_idx] = newval

	for i := 0; i < n; i++ {
		if v.Verify(com, newproofs[i], values[i]) {
			t.Errorf("Verified new proof %d against old commitment", i)
		}
		if !v.Verify(newcom, newproofs[i], values[i]) {
			t.Errorf("Could not verify new proof %d", i)
		}
	}
}

func BenchmarkOps(b *testing.B) {
	seed := []byte("This is Leo's Favourite Seed")
	N := 1000

	b.Run("ParamGen", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ParamGen(seed, N)
		}
	})

	p, v := ParamGen(seed, N)

	var values [][]byte
	for i := 0; i < N; i++ {
		values = append(values, []byte(fmt.Sprintf("this is old message number %d", i)))
	}

	b.Run("Commit", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			p.Commit(values)
		}
	})

	com := p.Commit(values)
	combuf := com.G1.ToBytes()

	com2 := BytesToG1(combuf)
	com2buf := com2.ToBytes()
	if combuf != com2buf {
		b.Errorf("com2buf mismatch")
	}

	b.Run("BytesToG1", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			BytesToG1(combuf)
		}
	})

	b.Run("G1ToBytes", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			buf := com.G1.ToBytes()
			if buf != combuf {
				b.Errorf("G1ToBytes mismatch")
			}
		}
	})

	b.Run("Prove", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			p.Prove(values, i%N)
		}
	})

	Np := 10
	var proofs []Proof
	for i := 0; i < N; i += N / Np {
		proofs = append(proofs, p.Prove(values, i))
	}

	b.Run("Verify", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			x := i % Np
			if !v.Verify(com, proofs[x], values[x*N/Np]) {
				b.Errorf("Could not verify proof %d", x)
			}
		}
	})

	b.Run("CommitUpdate", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			x := i % N
			newval := []byte(fmt.Sprintf("this is new message number %d", x))
			p.CommitUpdate(com, x, values[x], newval)
		}
	})

	b.Run("ProofUpdate", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			x := i % Np
			v := rand.Int() % N
			newval := []byte(fmt.Sprintf("this is new message number %d", v))
			p.ProofUpdate(proofs[x], v, values[v], newval)
		}
	})
}
