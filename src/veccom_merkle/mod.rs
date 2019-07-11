

pub struct Params {
    n : usize,
    n_bytes : [u8; 8],
    max_depth : usize,
    hash_len : usize
}



pub mod paramgen;
pub mod commit;
pub mod prove;
pub mod verify;

#[cfg(test)]
mod tests {
    use super::paramgen::*;
    use super::commit::*;
    use super::verify::*;
    use super::prove::*;
    use test::Bencher;

    
    fn print_bytes(b : &[u8])->String {
        let mut ret = "".to_string();
        for i in 0..b.len() {
            ret = ret + &format!("{:02x}", b[i]);
        }
        ret
    }


    #[test]
    fn test_com() {
        let n = 10usize;
        let params = paramgen(n);

        let mut values = Vec::with_capacity(n);
        for i in 0..n {
            let s = format!("this is message number {}", i);
            values.push(s.into_bytes());
        }
        
        let mut com = commit_no_tree(&params, &values);
        let mut proofs = Vec::with_capacity(n);

        for i in 0..n {
            proofs.push (prove_from_scratch(&params, &values, i));
            let wrong_string = format!("wrong string {}", i).into_bytes();
            assert!(verify(&params, &com, &proofs[i], &values[i], i));
            assert!(!verify(&params, &com, &proofs[i], &wrong_string, i));
        }

        // update values
        let mut new_values = Vec::with_capacity(n);
        for i in 0..n {
            new_values.push (format!("new string {}", i).into_bytes());
        }
        for i in 0..n {
            com = commit_update(&params, i, &proofs[i], &new_values[i]);
            // Old value should not verify, but new one should
            assert!(!verify(&params, &com, &proofs[i], &values[i], i));
            assert!(verify(&params, &com, &proofs[i], &new_values[i], i));
            // Copy over the proof of the updated value in order to avoid mutable borrow isues in the proof_update
            let mut proof_of_updated_value = Vec::new();
            for k in 0..proofs[i].len() {
                proof_of_updated_value.push(proofs[i][k]);
            }
            // update proofs of other values
            for j in 0..n {
                // Old proofs should not verify when i!=j, regardless of whether they are for the old or the new value
                if i!=j {
                    assert!(!verify(&params, &com, &proofs[j], &values[j], j));
                    assert!(!verify(&params,  &com, &proofs[j], &new_values[j], j));
                }
                proof_update(&params, &mut proofs[j], j, i, &proof_of_updated_value, &new_values[i], None);
                if j<=i {
                    assert!(verify(&params, &com, &proofs[j], &new_values[j], j));
                    assert!(!verify(&params, &com, &proofs[j], &values[j], j));
                } else {
                    assert!(!verify(&params, &com, &proofs[j], &new_values[j], j));
                    assert!(verify(&params, &com, &proofs[j], &values[j], j));
                }
            }
        }
    }

    
    #[bench]
    fn bench_com(b: &mut Bencher) {
        let n = 1000usize;

        let params = paramgen(n);

        let mut values = Vec::with_capacity(n);
        for i in 0..n {
            let s = format!("this is message number {}", i);
            values.push(s.into_bytes());
        }
        
        b.iter(|| { 
            commit_no_tree(&params, &values)
        });
    }

    #[bench]
    fn bench_prove(b: &mut Bencher) {
        let n = 1000usize;

        let params = paramgen(n);

        let mut values = Vec::with_capacity(n);
        for i in 0..n {
            let s = format!("this is message number {}", i);
            values.push(s.into_bytes());
        }        
        let mut i : usize = 0;
        b.iter(|| {
            let p = prove_from_scratch(&params, &values, i);
            i = (i+1)%n;
            p
        });
    }

    #[bench]
    fn bench_verify(b: &mut Bencher) {
        let n = 1000usize;

        let params =  paramgen(n);

        let mut values = Vec::with_capacity(n);
        for i in 0..n {
            let s = format!("this is message number {}", i);
            values.push(s.into_bytes());
        }
        let com = commit_no_tree(&params, &values);
        let mut proofs = Vec::with_capacity(n);
        for i in 0..n {
            proofs.push(prove_from_scratch(&params, &values, i));
        }

        let mut i : usize = 0;
        b.iter(|| {
            assert!(verify(&params, &com, &proofs[i], &values[i], i));
            i = (i+1)%n;
        });
    }

    #[bench]
    fn bench_commit_update(b: &mut Bencher) {
        let n = 1000usize;

        let params = paramgen(n);

        let mut old_values = Vec::with_capacity(n);
        let mut new_values = Vec::with_capacity(n);
        for i in 0..n {
            let s = format!("this is old message number {}", i);
            old_values.push(s.into_bytes());
            let t = format!("this is new message number {}", i);
            new_values.push(t.into_bytes());
        }
        let mut i : usize = 0;
        let mut proofs = Vec::with_capacity(n);
        for i in 0..n {
            proofs.push (prove_from_scratch(&params, &old_values, i));
        }

        b.iter(|| {
            commit_update(&params, i, &proofs[i], &new_values[i]);
            i = (i+1)%n;
        });
    }

    #[bench]
    fn bench_proof_update(b: &mut Bencher) {
        let n = 1000usize;
        let update_index = n/2;  // We will update message number n/2 and then benchmark changing proofs for others


        let params = paramgen(n);

        let mut old_values = Vec::with_capacity(n);
        
        for i in 0..n {
            let s = format!("this is old message number {}", i);
            old_values.push(s.into_bytes());
        }

        let mut proofs = Vec::with_capacity(n);
        for i in 0..n {
            proofs.push(prove_from_scratch(&params, &old_values, i));
        }
        // Copy over the proof of the updated value in order to avoid mutable borrow isues in the proof_update
        let mut proof_of_updated_value = Vec::new();
        for i in 0..proofs[update_index].len() {
            proof_of_updated_value.push(proofs[update_index][i]);
        }

        let new_value = format!("this is new message number {}", update_index).into_bytes();
        
        let mut i : usize = 0;
        b.iter(|| {
            proof_update(&params, &mut proofs[i], i, update_index, &proof_of_updated_value, &new_value, None);
            i = (i+1)%n;
            if i==update_index { // skip update_index
                i = (i+1)%n;
            }
            proofs[i].len();
        });
    }

}
