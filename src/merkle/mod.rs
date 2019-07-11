

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

#[cfg(test_broken)]
mod tests {
    use super::paramgen::*;
    use super::commit::*;
    use super::verify::*;
    use super::prove::*;

    
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
        
        let mut com = commit(&params, &values);
        let mut proofs = Vec::with_capacity(n);

        for i in 0..n {
            proofs.push (prove(&params, &values, i));
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
                proof_update(&params, &mut proofs[j], j, i, &proof_of_updated_value, &new_values[i]);
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
}
