

const HASH_LEN : usize = 32;

pub struct Params {
    n : usize,
    n_bytes : [u8; 8],
    max_depth : usize,
}


mod paramgen;
mod commit;
mod prove;
mod verify;

#[cfg(test)]
mod tests {
    use super::paramgen::*;
    use super::commit::*;
    use super::verify::*;
    use super::prove::*;


/*    fn print_bytes(b : &[u8])->String {
        let mut ret = "".to_string();
        for i in 0..b.len() {
            ret = ret + &format!("{:02x}", b[i]);
        }
        ret
    }
*/

    #[test]
    fn test_com_merkle() {
        for n in 2..18 {
            let params = paramgen(n);

            let mut init_values = Vec::with_capacity(n);
            for i in 0..n {
                let s = format!("this is message number {}", i);
                init_values.push(s.into_bytes());
            }

            let mut values: Vec<&[u8]> = Vec::with_capacity(n);
            for i in 0..n {
                values.push(&init_values[i]);
            }            

            let com = commit_no_tree(&params, &values);
            let mut proofs = Vec::with_capacity(n);
            let mut tree = commit_with_tree(&params, &values);
            assert_eq!(com, tree[32..64].to_vec());

            for i in 0..n {
                proofs.push (prove_from_scratch(&params, &values, i));
                let p = prove_from_tree(&params, &tree, i);
                assert_eq!(proofs[i], p);
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
                let (com, fast_update_info) = commit_update(&params, i, &proofs[i], &new_values[i]);
                tree_update(&params, i, &new_values[i], &mut tree);
                assert_eq!(com, tree[32..64].to_vec());
                // Old value should not verify, but new one should
                assert!(!verify(&params, &com, &proofs[i], &values[i], i));
                assert!(verify(&params, &com, &proofs[i], &new_values[i], i));
                // Copy over the proof of the updated value in order to avoid mutable borrow isues in the proof_update
                let mut proof_of_updated_value = vec![0u8; proofs[i].len()];
                proof_of_updated_value.copy_from_slice(&proofs[i]);
                
                // update proofs of other values
                for j in 0..n {
                    // Old proofs should not verify when i!=j, regardless of whether they are for the old or the new value
                    if i!=j {
                        assert!(!verify(&params, &com, &proofs[j], &values[j], j));
                        assert!(!verify(&params,  &com, &proofs[j], &new_values[j], j));
                    }
                    let mut copy_of_proof = vec![0u8; proofs[j].len()];
                    copy_of_proof.copy_from_slice(&proofs[j]);
                    // Test proof update with and without the helper info
                    proof_update(&params, &mut proofs[j], j, i, &proof_of_updated_value, &new_values[i], None);
                    proof_update(&params, &mut copy_of_proof, j, i, &proof_of_updated_value, &new_values[i], Some(&fast_update_info));
                    assert_eq!(proofs[j], copy_of_proof);
                    // test that the proof you get is the same as from the update tree
                    let p = prove_from_tree(&params, &tree, j);
                    assert_eq!(proofs[j], p);


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
}
