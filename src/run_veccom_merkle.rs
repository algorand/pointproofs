extern crate veccom;

use veccom::veccom_merkle::paramgen::*;
use veccom::veccom_merkle::commit::*;
use veccom::veccom_merkle::verify::*;
use veccom::veccom_merkle::prove::*;

fn print_bytes(b : &[u8])->String {
    let mut ret = "".to_string();
    for i in 0..b.len() {
        ret = ret + &format!("{:02x}", b[i]);
    }
    ret
}

pub fn main() {
    let n = 10usize;
    let update_index = n/2;

    let params = paramgen(n);

    let mut old_values = Vec::with_capacity(n);
    println!("Commiting to the following {} strings", n);
    for i in 0..n {
        let s = format!("this is message number {}", i);
        println!("{}", s);
        old_values.push(s.into_bytes());
    }

    let old_com = commit_no_tree(&params, &old_values);
    println!("\nCommitment:  {}", print_bytes(&old_com));

    let mut proofs = Vec::with_capacity(n);
    for i in 0..n {
        proofs.push(prove_from_scratch(&params, &old_values, i));
        println!("Proof {}: {}", i, print_bytes(&proofs[i]));
    }

    for i in 0..n {
        assert!(verify(&params, &old_com, &proofs[i], &old_values[i], i));
    }

    let s = format!("\"this is new message number {}\"", update_index);
    println!("\nUpdating string {} to {}", update_index, s);
    let new_value = s.into_bytes();

    let new_com = commit_update(&params, update_index, &proofs[update_index], &new_value);
    println!("New Commitment:  {}", print_bytes(&new_com));

    assert!(verify(&params, &new_com, &proofs[update_index], &new_value, update_index));
    assert!(!verify(&params, &new_com, &proofs[update_index], &old_values[update_index], update_index));

    // Copy over the proof of the updated value in order to avoid mutable borrow isues in the proof_update
    let mut proof_of_updated_value = Vec::new();
    for k in 0..proofs[update_index].len() {
        proof_of_updated_value.push(proofs[update_index][k]);
    }


    for i in 0..n {
        if i!=update_index {
            assert!(!verify(&params, &new_com, &proofs[i], &old_values[i], i));
        }
        proof_update(&params, &mut proofs[i], i, update_index, &proof_of_updated_value, &new_value, None);
        println!("New Proof {}: {}", i, print_bytes(&proofs[i]));
        if i!=update_index {
            assert!(verify(&params, &new_com, &proofs[i], &old_values[i], i));
        }
    }
}


