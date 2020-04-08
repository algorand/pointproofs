extern crate pairing_plus as pairing;
extern crate pointproofs;
use pairing::serdes::SerDes;
use pointproofs::pairings::param::paramgen_from_seed;
use pointproofs::pairings::*;

fn main() {
    let n = 16usize;
    let update_index = n / 2;

    // generate the parameters, and performs pre_computation
    let (mut prover_params, verifier_params) =
        paramgen_from_seed("This is Leo's Favourite very very long Seed", 0, n).unwrap();
    prover_params.precomp_256(); // precomp_256, or nothing, as you wish

    // initiate the data to commit
    let mut init_values: Vec<Vec<u8>> = Vec::with_capacity(n);
    println!("Commiting to the following {} strings", n);
    for i in 0..n {
        let s = format!("this is message number {}", i);
        println!("{}", s);
        init_values.push(s.into_bytes());
    }

    // generate the commitment, and (de)serialize it
    let old_com = Commitment::new(&prover_params, &init_values).unwrap();
    let mut old_commitment_bytes: Vec<u8> = vec![];
    assert!(old_com.serialize(&mut old_commitment_bytes, true).is_ok());
    assert_eq!(
        old_com,
        Commitment::deserialize(&mut old_commitment_bytes[..].as_ref(), true).unwrap()
    );

    println!("\nCommitment:  {:02x?}\n", old_commitment_bytes);

    // generate the proof, (de)serialize it, and verify it
    let mut proofs: Vec<Proof> = Vec::with_capacity(n);
    for i in 0..n {
        proofs.push(Proof::new(&prover_params, &init_values, i).unwrap());
        let mut proof_bytes: Vec<u8> = vec![];
        assert!(proofs[i].serialize(&mut proof_bytes, true).is_ok());
        println!("Old Proof {}: {:02x?}", i, proof_bytes);
        assert_eq!(
            proofs[i],
            Proof::deserialize(&mut proof_bytes[..].as_ref(), true).unwrap()
        );
        assert!(proofs[i].verify(&verifier_params, &old_com, &init_values[i], i));
    }

    let new_value = format!("\"this is new message number {}\"", update_index);
    println!("\nUpdating string {} to {}\n", update_index, new_value);

    // update the commitment to the new value, and (de)serialize it
    let mut new_com = old_com;
    new_com
        .update(
            &prover_params,
            update_index,
            &init_values[update_index][..].as_ref(),
            &new_value.as_ref(),
        )
        .unwrap();
    let mut new_commitment_bytes: Vec<u8> = vec![];
    assert!(new_com.serialize(&mut new_commitment_bytes, true).is_ok());
    assert_eq!(
        new_com,
        Commitment::deserialize(&mut new_commitment_bytes[..].as_ref(), true).unwrap()
    );

    // verifies new proof against new commitment and new value
    assert!(proofs[update_index].verify(&verifier_params, &new_com, &new_value, update_index));

    // verifies new proof against new commitment and old value -- must fail
    assert!(!proofs[update_index].verify(
        &verifier_params,
        &new_com,
        &init_values[update_index],
        update_index
    ));

    for i in 0..n {
        // verifies the old proofs against new commitment -- must fail
        if i != update_index {
            assert!(!proofs[i].verify(&verifier_params, &new_com, &init_values[i], i));
        }

        // update the proofs to the new value
        assert!(proofs[i]
            .update(
                &prover_params,
                i,
                update_index,
                &init_values[update_index][..].as_ref(),
                &new_value.as_ref(),
            )
            .is_ok());
        // the updated proof should pass verification against the new commitment
        if i != update_index {
            assert!(proofs[i].verify(&verifier_params, &new_com, &init_values[i], i));
        }

        // (de)serialization
        let mut proof_bytes: Vec<u8> = vec![];
        assert!(proofs[i].serialize(&mut proof_bytes, true).is_ok());
        println!("New Proof {}: {:02x?}", i, proof_bytes);
        assert_eq!(
            proofs[i],
            Proof::deserialize(&mut proof_bytes[..].as_ref(), true).unwrap()
        );
    }

    // finished
    println!("\nNi hao, Algorand");
}
