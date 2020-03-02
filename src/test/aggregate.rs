use pairings::param::paramgen_from_seed;
use pairings::{Commitment, Proof};

#[test]
fn negative_test_same_commit_aggregation() {
    let n = 8usize;
    let (prover_params, verifier_params) =
        paramgen_from_seed("This is Leo's Favourite very very very long Seed", 0, n).unwrap();
    let mut verifier_params2 = verifier_params.clone();
    verifier_params2.ciphersuite = 1;

    let mut init_values = Vec::with_capacity(n);
    for i in 0..n {
        let s = format!("this is message number {}", i);
        init_values.push(s.into_bytes());
    }

    let mut values: Vec<&[u8]> = Vec::with_capacity(n);
    for e in init_values.iter().take(n) {
        values.push(&e);
    }

    let com = Commitment::new(&prover_params, &values).unwrap();
    let mut com2 = com.clone();
    com2.ciphersuite = 1;

    let set = vec![1usize, 4, 7];
    let set2 = vec![1usize, 4, 6, 7];
    let mut proofs: Vec<Proof> = vec![];
    let mut value_sub_vector: Vec<&[u8]> = vec![];

    for index in &set {
        let proof = Proof::new(&prover_params, &values, *index).unwrap();
        proofs.push(proof);
        value_sub_vector.push(values[*index]);
    }
    let mut proofs2 = proofs.clone();
    proofs2[0].ciphersuite = 1;

    assert!(
        Proof::same_commit_aggregate(&com2, &proofs, &set, &value_sub_vector, prover_params.n)
            .is_err()
    );
    assert!(
        Proof::same_commit_aggregate(&com, &proofs2, &set, &value_sub_vector, prover_params.n)
            .is_err()
    );
    assert!(
        Proof::same_commit_aggregate(&com, &proofs, &set2, &value_sub_vector, prover_params.n)
            .is_err()
    );
    let agg_proof =
        Proof::same_commit_aggregate(&com, &proofs, &set, &value_sub_vector, prover_params.n)
            .unwrap();

    assert!(!agg_proof.same_commit_batch_verify(&verifier_params, &com2, &set, &value_sub_vector));
    assert!(!agg_proof.same_commit_batch_verify(&verifier_params2, &com, &set, &value_sub_vector));

    let new_set = vec![1usize, 4, 8];
    assert!(!agg_proof.same_commit_batch_verify(
        &verifier_params,
        &com,
        &new_set,
        &value_sub_vector
    ));
}

#[test]
fn test_same_commit_aggregation_small() {
    let n = 8usize;
    let (prover_params, verifier_params) =
        paramgen_from_seed("This is Leo's Favourite very very very long Seed", 0, n).unwrap();
    let mut verifier_params3 = verifier_params.clone();
    verifier_params3.precomp_3();
    let mut verifier_params256 = verifier_params.clone();
    verifier_params256.precomp_256();
    let mut init_values = Vec::with_capacity(n);
    for i in 0..n {
        let s = format!("this is message number {}", i);
        init_values.push(s.into_bytes());
    }

    let mut values: Vec<&[u8]> = Vec::with_capacity(n);
    for e in init_values.iter().take(n) {
        values.push(&e);
    }
    let com = Commitment::new(&prover_params, &values).unwrap();

    let set = vec![1usize, 4, 7];
    let mut proofs: Vec<Proof> = vec![];
    let mut value_sub_vector: Vec<&[u8]> = vec![];

    for index in &set {
        let proof = Proof::new(&prover_params, &values, *index).unwrap();
        proofs.push(proof);
        value_sub_vector.push(values[*index]);
    }
    let agg_proof =
        Proof::same_commit_aggregate(&com, &proofs, &set, &value_sub_vector, prover_params.n)
            .unwrap();
    let agg_proof2 = Proof::cross_commit_aggregate_full(
        &[com.clone()],
        &[proofs.clone()],
        &[set.clone()],
        &[value_sub_vector.clone()],
        prover_params.n,
    )
    .unwrap();
    assert_eq!(agg_proof, agg_proof2);
    assert!(agg_proof.same_commit_batch_verify(&verifier_params, &com, &set, &value_sub_vector));
    assert!(agg_proof.same_commit_batch_verify(&verifier_params3, &com, &set, &value_sub_vector));
    assert!(agg_proof.same_commit_batch_verify(&verifier_params256, &com, &set, &value_sub_vector));
    assert!(agg_proof.cross_commit_batch_verify(
        &verifier_params,
        &[com.clone()],
        &[set.clone()],
        &[value_sub_vector.clone()]
    ));
    assert!(agg_proof.cross_commit_batch_verify(
        &verifier_params3,
        &[com.clone()],
        &[set.clone()],
        &[value_sub_vector.clone()]
    ));
    assert!(agg_proof.cross_commit_batch_verify(
        &verifier_params256,
        &[com.clone()],
        &[set],
        &[value_sub_vector]
    ));
    assert!(proofs[0].same_commit_batch_verify(&verifier_params, &com, &[1], &[values[1]]));
    assert!(proofs[0].same_commit_batch_verify(&verifier_params3, &com, &[1], &[values[1]]));
    assert!(proofs[0].same_commit_batch_verify(&verifier_params256, &com, &[1], &[values[1]]));
}

#[test]
fn negative_test_cross_commit_aggregation() {
    let n = 8usize;
    let (prover_params, verifier_params) =
        paramgen_from_seed("This is Leo's Favourite very very very long Seed", 0, n).unwrap();

    let mut values: Vec<Vec<Vec<u8>>> = vec![];
    let mut commits: Vec<Commitment> = vec![];
    let mut proofs: Vec<Vec<Proof>> = vec![];
    let mut value_sub_vector: Vec<Vec<Vec<u8>>> = vec![];
    let mut set = vec![];
    let mut same_commit_proof = vec![];
    for j in 0..4 {
        let mut init_values = Vec::with_capacity(n);
        for i in 0..n {
            let s = format!("this is message number {} for commit {}", i, j);
            init_values.push(s.into_bytes());
        }
        let mut tmp_values: Vec<&[u8]> = Vec::with_capacity(n);
        for e in init_values.iter().take(n) {
            tmp_values.push(&e);
        }
        let com = Commitment::new(&prover_params, &tmp_values).unwrap();

        let tmp_set = vec![1usize, 2, 3];
        let mut tmp_proofs: Vec<Proof> = vec![];
        let mut tmp_value_sub_vector: Vec<Vec<u8>> = vec![];
        for index in &tmp_set {
            let proof = Proof::new(&prover_params, &init_values, *index).unwrap();
            tmp_proofs.push(proof);
            tmp_value_sub_vector.push(init_values[*index].clone());
        }
        same_commit_proof.push(
            Proof::same_commit_aggregate(
                &com,
                &tmp_proofs,
                &tmp_set,
                &tmp_value_sub_vector,
                prover_params.n,
            )
            .unwrap(),
        );

        values.push(init_values);
        commits.push(com);
        set.push(tmp_set);
        proofs.push(tmp_proofs);
        value_sub_vector.push(tmp_value_sub_vector);
    }

    commits[0].ciphersuite = 1;
    assert!(Proof::cross_commit_aggregate_full(
        &commits,
        &proofs,
        &set,
        &value_sub_vector,
        prover_params.n,
    )
    .is_err());
    commits[0].ciphersuite = 0;

    commits[1].ciphersuite = 1;
    assert!(Proof::cross_commit_aggregate_full(
        &commits,
        &proofs,
        &set,
        &value_sub_vector,
        prover_params.n,
    )
    .is_err());
    commits[1].ciphersuite = 0;

    proofs[0][0].ciphersuite = 1;
    assert!(Proof::cross_commit_aggregate_full(
        &commits,
        &proofs,
        &set,
        &value_sub_vector,
        prover_params.n,
    )
    .is_err());
    proofs[0][0].ciphersuite = 0;

    commits.push(commits[0].clone());
    assert!(Proof::cross_commit_aggregate_full(
        &commits,
        &proofs,
        &set,
        &value_sub_vector,
        prover_params.n,
    )
    .is_err());
    commits.pop();

    let agg_proof1 = Proof::cross_commit_aggregate_full(
        &commits,
        &proofs,
        &set,
        &value_sub_vector,
        prover_params.n,
    )
    .unwrap();

    commits[0].ciphersuite = 1;
    assert!(Proof::cross_commit_aggregate_partial(
        &commits,
        &same_commit_proof,
        &set,
        &value_sub_vector,
        prover_params.n,
    )
    .is_err());
    commits[0].ciphersuite = 0;

    commits[1].ciphersuite = 1;
    assert!(Proof::cross_commit_aggregate_partial(
        &commits,
        &same_commit_proof,
        &set,
        &value_sub_vector,
        prover_params.n,
    )
    .is_err());
    commits[1].ciphersuite = 0;

    same_commit_proof[0].ciphersuite = 1;
    assert!(Proof::cross_commit_aggregate_partial(
        &commits,
        &same_commit_proof,
        &set,
        &value_sub_vector,
        prover_params.n,
    )
    .is_err());
    same_commit_proof[0].ciphersuite = 0;

    let agg_proof2 = Proof::cross_commit_aggregate_partial(
        &commits,
        &same_commit_proof,
        &set,
        &value_sub_vector,
        prover_params.n,
    )
    .unwrap();
    assert_eq!(agg_proof1, agg_proof2);

    assert!(agg_proof1.cross_commit_batch_verify(
        &verifier_params,
        &commits,
        &set,
        &value_sub_vector
    ));
}

#[test]
fn test_cross_commit_aggregation_small() {
    let n = 8usize;
    let (prover_params, verifier_params) =
        paramgen_from_seed("This is Leo's Favourite very very very long Seed", 0, n).unwrap();
    let mut verifier_params256 = verifier_params.clone();
    verifier_params256.precomp_256();
    let mut values: Vec<Vec<Vec<u8>>> = vec![];
    let mut commits: Vec<Commitment> = vec![];
    let mut proofs: Vec<Vec<Proof>> = vec![];
    let mut value_sub_vector: Vec<Vec<Vec<u8>>> = vec![];
    let mut set = vec![];
    let mut same_commit_proof = vec![];
    for j in 0..4 {
        let mut init_values = Vec::with_capacity(n);
        for i in 0..n {
            let s = format!("this is message number {} for commit {}", i, j);
            init_values.push(s.into_bytes());
        }
        let mut tmp_values: Vec<&[u8]> = Vec::with_capacity(n);
        for e in init_values.iter().take(n) {
            tmp_values.push(&e);
        }
        let com = Commitment::new(&prover_params, &tmp_values).unwrap();

        let tmp_set = vec![1usize, 2, 3];
        let mut tmp_proofs: Vec<Proof> = vec![];
        let mut tmp_value_sub_vector: Vec<Vec<u8>> = vec![];
        for index in &tmp_set {
            let proof = Proof::new(&prover_params, &init_values, *index).unwrap();
            tmp_proofs.push(proof);
            tmp_value_sub_vector.push(init_values[*index].clone());
        }
        same_commit_proof.push(
            Proof::same_commit_aggregate(
                &com,
                &tmp_proofs,
                &tmp_set,
                &tmp_value_sub_vector,
                prover_params.n,
            )
            .unwrap(),
        );

        values.push(init_values);
        commits.push(com);
        set.push(tmp_set);
        proofs.push(tmp_proofs);
        value_sub_vector.push(tmp_value_sub_vector);
    }

    let agg_proof1 = Proof::cross_commit_aggregate_full(
        &commits,
        &proofs,
        &set,
        &value_sub_vector,
        prover_params.n,
    )
    .unwrap();
    let agg_proof2 = Proof::cross_commit_aggregate_partial(
        &commits,
        &same_commit_proof,
        &set,
        &value_sub_vector,
        prover_params.n,
    )
    .unwrap();
    assert_eq!(agg_proof1, agg_proof2);
    assert!(agg_proof1.cross_commit_batch_verify(
        &verifier_params,
        &commits,
        &set,
        &value_sub_vector
    ));
    assert!(agg_proof1.cross_commit_batch_verify(
        &verifier_params256,
        &commits,
        &set,
        &value_sub_vector
    ));
}

#[test]
#[ignore]
fn test_same_commit_aggregation_large() {
    let test_dim = [256usize, 1024];

    for i in &test_dim {
        let n = *i;

        let (pp, vp) =
            paramgen_from_seed("This is Leo's Favourite very very very long Seed", 0, n).unwrap();

        let mut init_values = Vec::with_capacity(n);
        for i in 0..n {
            let s = format!("this is message number {}", i);
            init_values.push(s.into_bytes());
        }

        let mut values: Vec<&[u8]> = Vec::with_capacity(n);
        for e in init_values.iter().take(n) {
            values.push(&e);
        }

        let com = Commitment::new(&pp, &values).unwrap();

        let set = vec![1usize, 4, 7];
        let mut proofs: Vec<Proof> = vec![];
        let mut value_sub_vector: Vec<&[u8]> = vec![];
        for index in &set {
            let proof = Proof::new(&pp, &values, *index).unwrap();
            proofs.push(proof);
            value_sub_vector.push(values[*index]);
        }

        let agg_proof =
            Proof::same_commit_aggregate(&com, &proofs, &set, &value_sub_vector, pp.n).unwrap();
        assert!(agg_proof.same_commit_batch_verify(&vp, &com, &set, &value_sub_vector));

        let new_set = vec![1usize, 4, 8];
        assert!(!agg_proof.same_commit_batch_verify(&vp, &com, &new_set, &value_sub_vector));
    }
}

#[test]
#[ignore]
fn test_cross_commit_aggregation_large() {
    let test_dim = [256usize, 1024];

    for i in &test_dim {
        let n = *i;
        // read the parameters
        let (pp, vp) =
            paramgen_from_seed("This is Leo's Favourite very very very long Seed", 0, n).unwrap();

        let mut values: Vec<Vec<Vec<u8>>> = vec![];
        let mut commits: Vec<Commitment> = vec![];
        let mut proofs: Vec<Vec<Proof>> = vec![];
        let mut value_sub_vector: Vec<Vec<Vec<u8>>> = vec![];
        let mut set = vec![];
        let mut same_commit_proof = vec![];
        for j in 0..8 {
            let mut init_values = Vec::with_capacity(n);
            for i in 0..n {
                let s = format!("this is message number {} for commit {}", i, j);
                init_values.push(s.into_bytes());
            }
            let mut tmp_values: Vec<&[u8]> = Vec::with_capacity(n);
            for e in init_values.iter().take(n) {
                tmp_values.push(&e);
            }
            let com = Commitment::new(&pp, &tmp_values).unwrap();

            let tmp_set = vec![1usize, 2, 3];
            let mut tmp_proofs: Vec<Proof> = vec![];
            let mut tmp_value_sub_vector: Vec<Vec<u8>> = vec![];
            for index in &tmp_set {
                let proof = Proof::new(&pp, &init_values, *index).unwrap();
                tmp_proofs.push(proof);
                tmp_value_sub_vector.push(init_values[*index].clone());
            }
            same_commit_proof.push(
                Proof::same_commit_aggregate(&com, &tmp_proofs, &tmp_set, &tmp_value_sub_vector, n)
                    .unwrap(),
            );

            values.push(init_values);
            commits.push(com);
            set.push(tmp_set);
            proofs.push(tmp_proofs);
            value_sub_vector.push(tmp_value_sub_vector);
        }

        let agg_proof1 =
            Proof::cross_commit_aggregate_full(&commits, &proofs, &set, &value_sub_vector, n)
                .unwrap();
        let agg_proof2 = Proof::cross_commit_aggregate_partial(
            &commits,
            &same_commit_proof,
            &set,
            &value_sub_vector,
            n,
        )
        .unwrap();
        assert_eq!(agg_proof1, agg_proof2);

        let mut invalid_vp = vp.clone();
        invalid_vp.n = 255;

        let mut invalid_commits = commits.clone();
        invalid_commits[1] = commits[0].clone();

        let mut invalid_set = set.clone();
        invalid_set[0][0] = 0;

        let mut invalid_value_sub_vector = value_sub_vector.clone();
        invalid_value_sub_vector[0][0] = b"this is a must-fail string".to_owned().to_vec();

        assert!(agg_proof1.cross_commit_batch_verify(&vp, &commits, &set, &value_sub_vector));
        assert_eq!(agg_proof1, agg_proof2);
        // must fail: invalid vp
        assert!(!agg_proof1.cross_commit_batch_verify(
            &invalid_vp,
            &commits,
            &set,
            &value_sub_vector
        ));

        // must fail: invalid vp
        assert!(!agg_proof1.cross_commit_batch_verify(
            &vp,
            &invalid_commits,
            &set,
            &value_sub_vector
        ));

        // must fail: invalid set
        assert!(!agg_proof1.cross_commit_batch_verify(
            &vp,
            &commits,
            &invalid_set,
            &value_sub_vector
        ));

        // must fail: invalid vp
        assert!(!agg_proof1.cross_commit_batch_verify(
            &vp,
            &commits,
            &set,
            &invalid_value_sub_vector
        ));
    }
}
