
use veccom_merkle::paramgen::*;
use veccom_merkle::commit::*;
//use veccom_merkle::verify::*;
//use veccom_merkle::prove::*;

fn print_bytes(b : &[u8])->String {
    let mut ret = "".to_string();
    for i in 0..b.len() {
        ret = ret + &format!("{:02x}", b[i]);
    }
    ret
}

pub fn run_veccom_merkle() {
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

    let old_com = commit(&params, &old_values);
    println!("\nCommitment:  {}", print_bytes(&old_com));
/*
    let mut proofs = Vec::with_capacity(n);
    for i in 0..n {
        proofs.push(prove(&prover_params, &old_values, i));
        let proof_bytes = convert_proof_to_bytes(&proofs[i]);
        println!("Old Proof {}: {}", i, print_48_bytes(proof_bytes));
    }

    for i in 0..n {
        assert!(verify(&verifier_params, &old_com, &proofs[i], &old_values[i], i));
    }

    let s = format!("\"this is new message number {}\"", update_index);
    println!("\nUpdating string {} to {}", update_index, s);
    let new_value = s.into_bytes();

    let new_com = commit_update(&prover_params, &old_com, update_index, &old_values[update_index], &new_value);
    println!("New Commitment:  {}", print_48_bytes(old_commitment_bytes));

    assert!(verify(&verifier_params, &new_com, &proofs[update_index], &new_value, update_index));
    assert!(!verify(&verifier_params, &new_com, &proofs[update_index], &old_values[update_index], update_index));

    for i in 0..n {
        if i!=update_index {
            assert!(!verify(&verifier_params, &new_com, &proofs[i], &old_values[i], i));
        }
        proofs[i]=proof_update(&prover_params, &proofs[i], i, update_index, &old_values[update_index], &new_value);
        let proof_bytes = convert_proof_to_bytes(&proofs[i]);
        println!("New Proof {}: {}", i, print_48_bytes(proof_bytes));
        if i!=update_index {
            assert!(verify(&verifier_params, &new_com, &proofs[i], &old_values[i], i));
        }
    }

*/
}


