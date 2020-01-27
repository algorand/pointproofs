use pairing::CurveProjective;
use pairings::param::paramgen_from_seed;
use pairings::*;

#[test]
fn negative_test_batch_new_proof() {
    let n = 8usize;
    let (prover_params, _verifier_params) =
        paramgen_from_seed("This is Leo's Favourite very very very long Seed", 0, n).unwrap();

    let mut pp2 = prover_params.clone();
    pp2.ciphersuite = 1;
    let mut pp3 = prover_params.clone();
    pp3.n = 2;

    let mut values: Vec<String> = vec![];
    for i in 0..n {
        let s = format!("this is message number {}", i);
        values.push(s);
    }
    let indices = [5usize, 3, 1];
    let indices2 = [1; 9];
    let indices3 = [1, 8];
    let mut value_sub_vector: Vec<String> = vec![];
    for e in indices.iter() {
        value_sub_vector.push(values[*e].clone());
    }

    let com = Commitment::new(&prover_params, &values).unwrap();

    assert!(Proof::batch_new(&pp2, &values, &indices).is_err());
    assert!(Proof::batch_new(&pp3, &values, &indices).is_err());
    assert!(Proof::batch_new(&prover_params, &values, &indices2).is_err());
    assert!(Proof::batch_new(&prover_params, &values, &indices3).is_err());

    assert!(Proof::batch_new_aggregated(&pp2, &com, &values, &indices).is_err());
    assert!(Proof::batch_new_aggregated(&pp3, &com, &values, &indices).is_err());
    assert!(Proof::batch_new_aggregated(&prover_params, &com, &values, &indices2).is_err());
    assert!(Proof::batch_new_aggregated(&prover_params, &com, &values, &indices3).is_err());
}

#[test]
fn negative_test_proof() {
    let n = 8usize;
    let (prover_params, verifier_params) =
        paramgen_from_seed("This is Leo's Favourite very very very long Seed", 0, n).unwrap();
    let mut prover_params2 = prover_params.clone();
    prover_params2.ciphersuite = 1;
    let mut verifier_params2 = verifier_params.clone();
    verifier_params2.ciphersuite = 1;

    let mut prover_params256 = prover_params.clone();
    prover_params256.precomp_256();

    let mut init_values = Vec::with_capacity(n);
    for i in 0..n {
        let s = format!("this is message number {}", i);
        init_values.push(s.into_bytes());
    }

    let mut values: Vec<&[u8]> = Vec::with_capacity(n);
    for e in init_values.iter().take(n) {
        values.push(&e);
    }
    let mut values2 = Vec::with_capacity(n + 1);
    for i in 0..=n {
        values2.push(format!("new string {}", i).into_bytes());
    }

    assert!(Proof::new(&prover_params, &values, 9).is_err());
    assert!(Proof::new(&prover_params2, &values, 0).is_err());
    assert!(Proof::new(&prover_params, &values2, 0).is_err());

    let mut proof = Proof::new(&prover_params, &values, 0).unwrap();

    assert!(proof
        .update(&prover_params2, 0, 1, &values2[1], &values2[2])
        .is_err());
    assert!(proof
        .update(&prover_params2, 0, 9, &values2[1], &values2[2])
        .is_err());

    let mut proof2 = proof.clone();
    proof2.ciphersuite = 1;
    assert!(proof2
        .update(&prover_params, 0, 1, &values2[1], &values2[2])
        .is_err());

    let com = Commitment::new(&prover_params, &values).unwrap();
    let mut com2 = com.clone();
    com2.ciphersuite = 1;
    assert!(!proof.verify(&verifier_params2, &com, &values[0], 0));
    assert!(!proof.verify(&verifier_params, &com, &values[0], 9));
    assert!(!proof.verify(&verifier_params, &com2, &values[0], 0));
}

#[test]
fn test_batch_new_proof() {
    let n = 8usize;
    let (prover_params, verifier_params) =
        paramgen_from_seed("This is Leo's Favourite very very very long Seed", 0, n).unwrap();

    let mut values: Vec<String> = vec![];
    for i in 0..n {
        let s = format!("this is message number {}", i);
        values.push(s);
    }
    let indices = [5usize, 3, 1];
    let mut value_sub_vector: Vec<String> = vec![];
    for e in indices.iter() {
        value_sub_vector.push(values[*e].clone());
    }

    let com = Commitment::new(&prover_params, &values).unwrap();

    let mut proofs = Vec::with_capacity(n);

    // Check all proofs, together with conversion to/from bytes
    for i in 0..n {
        proofs.push(Proof::new(&prover_params, &values, i).unwrap());
    }
    let proof_list = Proof::batch_new(&prover_params, &values, &indices).unwrap();

    assert_eq!(proof_list[0], proofs[5]);
    assert_eq!(proof_list[1], proofs[3]);
    assert_eq!(proof_list[2], proofs[1]);

    let agg_proof =
        Proof::same_commit_aggregate(&com, &proof_list, &indices, &value_sub_vector, n).unwrap();

    let agg_proof2 = Proof::batch_new_aggregated(&prover_params, &com, &values, &indices).unwrap();

    assert_eq!(
        agg_proof.proof.into_affine(),
        agg_proof2.proof.into_affine()
    );
    assert!(agg_proof.same_commit_batch_verify(
        &verifier_params,
        &com,
        &indices,
        &value_sub_vector
    ));
}
