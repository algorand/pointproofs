package veccom

import (
	"encoding/hex"
	"fmt"
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
	fmt.Printf("Commitment:  %s\n", hex.EncodeToString(com[:]))

	var proofs []Proof
	for i := 0; i < n; i++ {
		pf := p.Prove(values, i)
		proofs = append(proofs, pf)
		fmt.Printf("Old Proof %d: %s\n", i, hex.EncodeToString(pf.Proof[:]))
	}

	for i := 0; i < n; i++ {
		if !v.Verify(com, proofs[i], values[i]) {
			t.Errorf("Could not verify proof %d\n", i)
		}
	}

	update_idx := n/2
	newmsg := fmt.Sprintf("\"this is new message number %d\"", update_idx)
	newval := []byte(newmsg)

	fmt.Printf("Updating string %d to \"%s\"\n", update_idx, newmsg)

	newcom := p.CommitUpdate(com, update_idx, values[update_idx], newval)
	fmt.Printf("New Commitment:  %s\n", hex.EncodeToString(newcom[:]))

	var newproofs []Proof
	for i := 0; i < n; i++ {
		npf := p.ProofUpdate(proofs[i], update_idx, values[update_idx], newval)
		newproofs = append(newproofs, npf)
		fmt.Printf("New Proof %d: %s\n", i, hex.EncodeToString(npf.Proof[:]))
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
