extern crate pairing;
extern crate veccom;
use pairing::serdes::SerDes;
use veccom::pairings::*;
fn print_48_bytes(b: [u8; 48]) -> String {
    let mut ret = "".to_string();
    for e in b.iter() {
        ret = ret + &format!("{:02x}", e);
    }
    ret
}

pub fn main() {
    let n = 32usize;
    let update_index = n / 2;

    let (mut prover_params, verifier_params) =
        paramgen_from_seed("This is Leo's Favourite very very long Seed", 0).unwrap();
    prover_params.precomp_256(); // precomp_256, or nothing, as you wish
    println!(
        "{:?} {:?}",
        prover_params.precomp.len(),
        prover_params.generators.len()
    );

    let mut init_values: Vec<Vec<u8>> = Vec::with_capacity(n);
    println!("Commiting to the following {} strings", n);
    for i in 0..n {
        let s = format!("this is message number {}", i);
        println!("{}", s);
        init_values.push(s.into_bytes());
    }

    let mut old_values: Vec<&[u8]> = Vec::with_capacity(n);
    for e in init_values.iter().take(n) {
        old_values.push(&e);
    }

    let old_com = Commitment::new(&prover_params, &old_values).unwrap();
    let mut old_commitment_bytes: Vec<u8> = vec![];
    assert!(old_com.serialize(&mut old_commitment_bytes, true).is_ok());
    println!("\nCommitment:  {:02x?}", old_commitment_bytes);

    let mut proofs: Vec<Proof> = Vec::with_capacity(n);
    for i in 0..n {
        proofs.push(Proof::new(&prover_params, &old_values, i).unwrap());
        let mut proof_bytes: Vec<u8> = vec![];
        assert!(proofs[i].serialize(&mut proof_bytes, true).is_ok());
        //let proof_bytes = convert_proof_to_bytes(&proofs[i]);
        println!("Old Proof {}: {:02x?}", i, proof_bytes);
    }

    for i in 0..n {
        println!("{}", i);
        assert!(proofs[i].verify(&verifier_params, &old_com, &old_values[i], i));
    }
    //
    // let s = format!("\"this is new message number {}\"", update_index);
    // println!("\nUpdating string {} to {}", update_index, s);
    // let new_value = s.into_bytes();
    //
    // let new_com = commit_update(
    //     &prover_params,
    //     &old_com,
    //     update_index,
    //     &old_values[update_index],
    //     &new_value,
    // );
    // let new_commitment_bytes = convert_commitment_to_bytes(&new_com);
    // println!("New Commitment:  {}", print_48_bytes(new_commitment_bytes));
    //
    // assert!(verify(
    //     &verifier_params,
    //     &new_com,
    //     &proofs[update_index],
    //     &new_value,
    //     update_index
    // ));
    // assert!(!verify(
    //     &verifier_params,
    //     &new_com,
    //     &proofs[update_index],
    //     &old_values[update_index],
    //     update_index
    // ));
    //
    // for i in 0..n {
    //     if i != update_index {
    //         assert!(!verify(
    //             &verifier_params,
    //             &new_com,
    //             &proofs[i],
    //             &old_values[i],
    //             i
    //         ));
    //     }
    //     proofs[i] = proof_update(
    //         &prover_params,
    //         &proofs[i],
    //         i,
    //         update_index,
    //         &old_values[update_index],
    //         &new_value,
    //     );
    //     let proof_bytes = convert_proof_to_bytes(&proofs[i]);
    //     println!("New Proof {}: {}", i, print_48_bytes(proof_bytes));
    //     if i != update_index {
    //         assert!(verify(
    //             &verifier_params,
    //             &new_com,
    //             &proofs[i],
    //             &old_values[i],
    //             i
    //         ));
    //     }
    // }
}
